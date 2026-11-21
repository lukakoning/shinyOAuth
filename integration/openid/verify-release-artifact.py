"""Verify a retained GitHub OpenID matrix artifact and replay its release evidence."""

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
API_CHECKS = {
    "plan_created", "module_waiting", "exported_issuer_checked",
    "unknown_instance_rejected", "cancellation_verified",
}


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


def read_policy(revision, name):
    result = subprocess.run(
        ["git", "show", f"{revision}:integration/openid/{name}"],
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"Cannot read committed OpenID release policy: {name}")
    return read_object(result.stdout)


def check_companion(report, client, lock, schema):
    sources = report.get("image_sources")
    if (
        report.get("schema_version") != schema
        or report.get("status") != "passed"
        or report.get("application_flow") != "not_attempted"
        or report.get("coverage_complete") is not False
        or report.get("source_verified") is not True
        or report.get("cleanup_verified") is not True
        or report.get("checkout_dirty") is not False
        or report.get("checkout_revision") != client["checkout_revision"]
        or report.get("checkout_source") != client["checkout_source"]
        or report.get("checkout_source_after") != client["checkout_source"]
        or report.get("source_revision") != lock["source_revision"]
        or report.get("images") != lock["images"]
        or not isinstance(sources, dict)
        or sources.keys() != lock["images"].keys()
        or any(source not in ("pulled", "cached") for source in sources.values())
    ):
        raise ValueError("Companion status, checkout or suite identity differs")


def check_preflight(report, client, lock):
    check_companion(report, client, lock, schema=2)
    tls = report.get("browser_tls")
    info = report.get("server_info")
    provenance = report.get("image_provenance")
    tag = lock.get("provenance", {}).get("release_tag")
    if (
        report.get("environment_checks") != "passed"
        or report.get("required_plans_present") is not True
        or report.get("r_tls") != "certificate chain and hostname verified against temporary trust anchor"
        or not isinstance(tls, dict)
        or tls.get("secure_context") is not True
        or tls.get("wrong_pin_rejected") is not True
        or not isinstance(info, dict)
        or info.get("revision") != lock["source_revision"][:7]
        or (tag is not None and info.get("tag") != tag)
        or not isinstance(provenance, dict)
        or provenance.get("revision") != lock["source_revision"]
        or provenance.get("description") != lock["source_description"]
        or provenance.get("dirty") is not False
    ):
        raise ValueError("Preflight is missing pinned suite, plan or TLS evidence")


def check_plan_inventory(inventory, plans):
    if not isinstance(inventory, dict) or inventory.keys() != plans.keys():
        raise ValueError("API inventory differs from the committed plans")
    for name, spec in plans.items():
        observed = inventory[name]
        available = spec["available_modules"]
        combined = spec["plan_variant"] | (spec.get("module_variant") or {})
        if not isinstance(observed, dict):
            raise ValueError(f"Invalid API plan inventory for {name}")
        modules = observed.get("modules")
        if (
            observed.get("plan") != spec["plan"]
            or observed.get("plan_variant") != spec["plan_variant"]
            or "module_variant" not in observed
            or observed["module_variant"] != spec.get("module_variant")
            or not isinstance(modules, list)
            or not all(isinstance(module, str) for module in modules)
            or sorted(modules) != sorted(available)
            or observed.get("probe_module") not in available
            or observed.get("probe_variant") != combined
            or observed.get("probe_cancelled") is not True
        ):
            raise ValueError(f"Invalid API plan inventory for {name}")


def check_api(report, client, lock, plans):
    check_companion(report, client, lock, schema=4)
    checks = report.get("api_checks")
    installation = report.get("installation")
    identity = (
        "method", "revision", "tree", "source_fingerprint",
        "archive_sha256", "package_version",
    )
    if (
        report.get("gate_passed") is not False
        or report.get("upstream_plan_complete") is not False
        or not isinstance(checks, dict)
        or checks.keys() != API_CHECKS
        or any(value is not True for value in checks.values())
        or not isinstance(installation, dict)
        or any(installation.get(name) != client["installation"][name] for name in identity)
        or report.get("regression_installation_after") != installation
        or report.get("installation_after") != installation
    ):
        raise ValueError("API readiness or installed package evidence differs")
    check_plan_inventory(report.get("plan_inventory"), plans)


def read_archive(archive, attempt, directory, lock, plans):
    files = archive.infolist()
    names = [member.filename for member in files]
    if SUMMARY not in names or len(names) != len(set(names)):
        raise ValueError("Expected one release summary and unique archive paths")

    selections = {}
    for member in files:
        if member.filename == SUMMARY:
            continue
        match = REPORT_PATH.fullmatch(member.filename)
        if not match or int(match["attempt"]) != attempt:
            raise ValueError("Unexpected path in the release artifact")
        kind = match["kind"]
        if kind == match["profile"]:
            kind = "client"
        elif kind not in {"api", "preflight"}:
            raise ValueError("Release report path differs from its selection")
        key = (match["profile"], match["transport"])
        members = selections.setdefault(key, {})
        if kind in members:
            raise ValueError(f"Duplicate {kind} report for {'/'.join(key)}")
        members[kind] = member

    if not selections:
        raise ValueError("No client reports in the release artifact")

    clients = []
    companions = {}
    for (profile, transport), members in sorted(selections.items()):
        label = f"{profile}/{transport}"
        if members.keys() != {"api", "client", "preflight"}:
            raise ValueError(f"Expected client, preflight and API reports for {label}")
        data = {name: read_member(archive, member) for name, member in members.items()}
        client = read_object(data["client"])
        if client.get("profile") != profile or client.get("transport") != transport:
            raise ValueError("Release report identity differs from its selection")
        try:
            check_preflight(read_object(data["preflight"]), client, lock)
            check_api(read_object(data["api"]), client, lock, plans)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{label}: {error}") from error
        target = directory / f"client-{len(clients)}.json"
        target.write_bytes(data["client"])
        clients.append(str(target))
        companions[label] = {
            f"{kind}_sha256": hashlib.sha256(data[kind]).hexdigest()
            for kind in ("preflight", "api")
        }
    return read_member(archive, archive.getinfo(SUMMARY)), clients, companions


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
        lock = read_policy(args.revision, "suite-lock.json")
        profiles = read_policy(args.revision, "profiles.json")
        plans = profiles.get("plans")
        if (
            not isinstance(plans, dict)
            or not plans
            or profiles.get("source_revision") != lock.get("source_revision")
        ):
            raise ValueError("Committed OpenID profile manifest does not match the suite lock")
        with ZipFile(file) as archive:
            summary, clients, companions = read_archive(
                archive, args.attempt, directory, lock, plans
            )
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
        "companion_reports": companions,
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
