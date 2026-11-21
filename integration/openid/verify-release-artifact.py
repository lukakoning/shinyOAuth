"""Verify a retained GitHub OpenID matrix artifact and replay its client gate."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from zipfile import BadZipFile, ZipFile


WORKFLOW = ".github/workflows/openid-release-matrix.yml"
SUMMARY = "release-summary.json"
MAX_REPORT_BYTES = 64 * 1024**2
SHA256 = re.compile(r"[a-f0-9]{64}")
REPORT_PATH = re.compile(
    r"release-inputs/openid-client-(?P<profile>[a-z0-9-]+)"
    r"-(?P<transport>sync|mirai|future)-evidence-attempt-(?P<attempt>[1-9][0-9]*)/"
    r"(?P<kind>[a-z0-9-]+)-[0-9]{8}-[0-9]{6}-[a-f0-9]{12}/evidence\.json"
)


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON object key")
    return result


def read_object(data):
    result = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


def check_metadata(args, run, artifact):
    repository = run.get("repository", {})
    head_repository = run.get("head_repository", {})
    if not isinstance(repository, dict) or not isinstance(head_repository, dict):
        raise ValueError("Invalid repository metadata for the workflow attempt")
    repository_id = repository.get("id")
    repository_name = repository.get("full_name")
    workflow_path = run.get("path")
    if (
        not isinstance(repository_name, str)
        or repository_name.lower() != args.repository.lower()
        or type(repository_id) is not int
        or repository_id <= 0
        or repository_id != head_repository.get("id")
        or run.get("id") != args.run_id
        or run.get("run_attempt") != args.attempt
        or run.get("head_sha") != args.revision
        or not isinstance(workflow_path, str)
        or workflow_path.partition("@")[0] != WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise ValueError("Expected the selected successful OpenID matrix workflow attempt")

    artifact_run = artifact.get("workflow_run", {})
    artifact_id = artifact.get("id")
    digest = artifact.get("digest")
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or artifact.get("name") != f"openid-declared-matrix-evidence-attempt-{args.attempt}"
        or not isinstance(artifact_run, dict)
        or artifact_run.get("id") != args.run_id
        or artifact_run.get("repository_id") != repository_id
        or artifact_run.get("head_repository_id") != repository_id
        or artifact_run.get("head_sha") != args.revision
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or not SHA256.fullmatch(digest[7:])
    ):
        raise ValueError("Expected the aggregate artifact for the selected matrix attempt")
    return digest[7:]


def read_archive(archive, attempt, directory):
    files = archive.infolist()
    names = [member.filename for member in files]
    if SUMMARY not in names or len(names) != len(set(names)):
        raise ValueError("Expected one release summary and unique archive paths")

    clients = []
    for member in files:
        if member.filename == SUMMARY:
            continue
        match = REPORT_PATH.fullmatch(member.filename)
        if not match or int(match["attempt"]) != attempt:
            raise ValueError("Unexpected path in the release artifact")
        if match["kind"] in {"preflight", "api"}:
            continue
        if match["kind"] != match["profile"]:
            raise ValueError("Release report path differs from its selection")
        data = read_member(archive, member)
        report = read_object(data)
        if report.get("profile") != match["profile"] or report.get("transport") != match["transport"]:
            raise ValueError("Release report identity differs from its selection")
        target = directory / f"client-{len(clients)}.json"
        target.write_bytes(data)
        clients.append(str(target))

    if not clients:
        raise ValueError("No client reports in the release artifact")
    return read_member(archive, archive.getinfo(SUMMARY)), clients


def read_member(archive, member):
    if not 0 < member.file_size <= MAX_REPORT_BYTES:
        raise ValueError("Expected a nonempty evidence file of at most 64 MiB")
    return archive.read(member)


def summary_for_comparison(data):
    summary = read_object(data)
    hashes = summary.get("input_sha256")
    if not isinstance(hashes, list) or not all(
        isinstance(value, str) and SHA256.fullmatch(value) for value in hashes
    ):
        raise ValueError("Invalid client report digests in the release summary")
    # This field enumerates the inputs in invocation order. Entries carry their own digest.
    summary["input_sha256"] = sorted(hashes)
    return json.dumps(summary, sort_keys=True)


def verify(args):
    run = read_object(args.run_metadata.read_bytes())
    artifact = read_object(args.artifact_metadata.read_bytes())
    digest = check_metadata(args, run, artifact)
    with args.archive.open("rb") as file, tempfile.TemporaryDirectory() as tmp:
        if hashlib.file_digest(file, "sha256").hexdigest() != digest:
            raise ValueError("Release artifact ZIP differs from the GitHub SHA-256 digest")
        directory = Path(tmp)
        with ZipFile(file) as archive:
            summary, clients = read_archive(archive, args.attempt, directory)
        replay_path = directory / "replay.json"
        result = subprocess.run(
            [
                "Rscript", "integration/openid/run-release-check.R",
                "--revision", args.revision, "--output", str(replay_path), *clients,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise ValueError(f"Release checker replay failed: {result.stderr.strip()}")
        if summary_for_comparison(summary) != summary_for_comparison(replay_path.read_bytes()):
            raise ValueError("Stored release summary differs from the independent replay")

    return {
        "repository": args.repository,
        "workflow": WORKFLOW,
        "run_id": args.run_id,
        "attempt": args.attempt,
        "revision": args.revision,
        "artifact_id": artifact["id"],
        "artifact_sha256": digest,
        "summary_sha256": hashlib.sha256(summary).hexdigest(),
        "client_report_count": len(clients),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub OWNER/REPO")
    parser.add_argument("--revision", required=True, help="Full expected Git commit SHA")
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("run_metadata", type=Path, help="GitHub workflow run attempt JSON")
    parser.add_argument("artifact_metadata", type=Path, help="GitHub aggregate artifact JSON")
    parser.add_argument("archive", type=Path, help="Original GitHub artifact ZIP bytes")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        parser.error("--revision requires a full lowercase Git commit SHA")
    if args.run_id <= 0 or args.attempt <= 0:
        parser.error("--run-id and --attempt must be positive")
    try:
        print(json.dumps(verify(args), indent=2))
    except (BadZipFile, OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
