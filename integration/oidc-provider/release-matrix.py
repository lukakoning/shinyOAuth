"""Declare the provider browser release selections and summarize their verified reports."""

import argparse
import hashlib
import json
from pathlib import Path
import re


PROFILES = {
    "basic": "oidc_provider_interoperability",
    "advanced": "oidc_provider_advanced_interoperability",
    "resources": "oidc_provider_resource_indicators",
    "retention": "oidc_provider_browser_retention",
}
TRANSPORTS = ("sync", "mirai")


def selections():
    return [
        {"profile": profile, "transport": transport}
        for profile in PROFILES
        for transport in TRANSPORTS
    ]


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


def report_path(directory, profile):
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"Expected a report directory in {directory.name}")
    children = list(directory.iterdir())
    if len(children) != 1:
        raise ValueError(f"Expected one original report in {directory.name}")
    run = children[0]
    if (
        not run.is_dir() or run.is_symlink()
        or not re.fullmatch(rf"{profile}-[0-9]{{8}}-[0-9]{{6}}-[a-f0-9]{{12}}", run.name)
    ):
        raise ValueError(f"Expected a {profile} run directory in {directory.name}")
    path = run / "evidence.json"
    if set(run.iterdir()) != {path} or not path.is_file() or path.is_symlink():
        raise ValueError(f"Expected exactly one evidence.json in {directory.name}")
    return path


def check_report(report, revision, profile, transport):
    source = report.get("checkout_source")
    installation = report.get("installation")
    if (
        type(report.get("schema_version")) is not int
        or report["schema_version"] != 2
        or report.get("scope") != PROFILES[profile]
        or report.get("transport") != transport
        or report.get("status") != "passed"
        or report.get("gate_passed") is not True
        or report.get("cleanup_verified") is not True
        or report.get("source_verified") is not True
        or report.get("checkout_dirty") is not False
        or report.get("checkout_revision") != revision
        or not isinstance(source, dict)
        or source.get("dirty") is not False
        or source.get("revision") != revision
        or report.get("checkout_source_after") != source
        or not isinstance(installation, dict)
        or installation.get("method") != "git_archive"
        or installation.get("revision") != revision
        or installation.get("tree") != source.get("tree")
        or report.get("installation_after") != installation
    ):
        raise ValueError(f"Expected a verified {profile}/{transport} report at {revision}")

    tree = source.get("tree")
    archive = installation.get("archive_sha256")
    version = report.get("package_version")
    cases = report.get("results")
    controls = report.get("rejection_controls")
    if (
        not isinstance(tree, str) or not re.fullmatch(r"[a-f0-9]{40}", tree)
        or not isinstance(archive, str) or not re.fullmatch(r"[a-f0-9]{64}", archive)
        or not isinstance(version, str) or not version
        or installation.get("package_version") != version
        or not isinstance(cases, list) or not cases
        or not isinstance(controls, dict) or not controls
        or any(outcome is not True for outcome in controls.values())
    ):
        raise ValueError(f"Invalid source or case evidence for {profile}/{transport}")
    return (tree, archive, version), len(cases), len(controls)


def summarize(reports, revision, run_id, attempt):
    expected = {
        f"oidc-provider-{selection['profile']}-{selection['transport']}-evidence-attempt-{attempt}": selection
        for selection in selections()
    }
    actual = {path.name for path in reports.iterdir()} if reports.is_dir() else set()
    if actual != expected.keys():
        missing = ", ".join(sorted(expected.keys() - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected.keys())) or "none"
        raise ValueError(
            f"Expected all {len(expected)} provider reports from attempt {attempt} "
            f"(missing {missing}, unexpected {unexpected}). Re-run all jobs."
        )

    entries = []
    source_identity = None
    for name, selection in expected.items():
        path = report_path(reports / name, selection["profile"])
        data = path.read_bytes()
        identity, cases, controls = check_report(read_object(data), revision, **selection)
        if source_identity is not None and identity != source_identity:
            raise ValueError(f"Source or installation identity differs in {name}")
        source_identity = identity
        entries.append({
            **selection,
            "path": path.relative_to(reports).as_posix(),
            "report_sha256": hashlib.sha256(data).hexdigest(),
            "case_count": cases,
            "rejection_control_count": controls,
        })

    tree, archive, version = source_identity
    return {
        "schema_version": 1,
        "run_id": run_id,
        "attempt": attempt,
        "revision": revision,
        "checkout_tree": tree,
        "installation_archive_sha256": archive,
        "package_version": version,
        "selections": entries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("selections", help="Print the CI matrix in GitHub include format")
    evidence = commands.add_parser("evidence", help="Write or replay the matrix summary")
    evidence.add_argument("--reports", type=Path, required=True)
    evidence.add_argument("--revision", required=True)
    evidence.add_argument("--run-id", type=int, required=True)
    evidence.add_argument("--attempt", type=int, required=True)
    summary = evidence.add_mutually_exclusive_group(required=True)
    summary.add_argument("--write-summary", type=Path)
    summary.add_argument("--verify-summary", type=Path)
    args = parser.parse_args()
    if args.command == "selections":
        print(json.dumps({"include": selections()}, separators=(",", ":")))
        return
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision) or min(args.run_id, args.attempt) <= 0:
        parser.error("Expected a full lowercase commit SHA and positive run and attempt numbers")

    try:
        result = summarize(args.reports, args.revision, args.run_id, args.attempt)
        encoded = (json.dumps(result, indent=2) + "\n").encode("utf-8")
        if args.write_summary is not None:
            output = args.write_summary.open("xb")
            try:
                with output:
                    output.write(encoded)
            except OSError:
                args.write_summary.unlink(missing_ok=True)
                raise
        elif args.verify_summary.read_bytes() != encoded:
            raise ValueError("Release summary differs from the report set")
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Verified {len(result['selections'])} provider reports for attempt {args.attempt}.")


if __name__ == "__main__":
    main()
