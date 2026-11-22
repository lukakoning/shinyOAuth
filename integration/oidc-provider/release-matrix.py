"""Declare the provider browser release selections and summarize their verified reports."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import zipfile
import zlib


PROFILES = {
    "basic": "oidc_provider_interoperability",
    "advanced": "oidc_provider_advanced_interoperability",
    "resources": "oidc_provider_resource_indicators",
    "retention": "oidc_provider_browser_retention",
}
TRANSPORTS = ("sync", "mirai")
MAX_ARCHIVE_MEMBER_SIZE = 64 * 1024 * 1024


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


def is_run_name(name, profile):
    return re.fullmatch(rf"{profile}-[0-9]{{8}}-[0-9]{{6}}-[a-f0-9]{{12}}", name) is not None


def report_path(directory, profile):
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"Expected a report directory in {directory.name}")
    children = list(directory.iterdir())
    if len(children) != 1:
        raise ValueError(f"Expected one original report in {directory.name}")
    run = children[0]
    if (
        not run.is_dir() or run.is_symlink()
        or not is_run_name(run.name, profile)
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


def expected_artifacts(attempt):
    return {
        f"oidc-provider-{selection['profile']}-{selection['transport']}-evidence-attempt-{attempt}": selection
        for selection in selections()
    }


def check_artifact_set(actual, expected, attempt):
    if actual != expected.keys():
        missing = ", ".join(sorted(expected.keys() - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected.keys())) or "none"
        raise ValueError(
            f"Expected all {len(expected)} provider reports from attempt {attempt} "
            f"(missing {missing}, unexpected {unexpected}). Re-run all jobs."
        )


def summarize_reports(expected, read_report, revision, run_id, attempt):
    entries = []
    source_identity = None
    for name, selection in expected.items():
        path, data = read_report(name)
        identity, cases, controls = check_report(read_object(data), revision, **selection)
        if source_identity is not None and identity != source_identity:
            raise ValueError(f"Source or installation identity differs in {name}")
        source_identity = identity
        entries.append({
            **selection,
            "path": path,
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


def summarize(reports, revision, run_id, attempt):
    expected = expected_artifacts(attempt)
    actual = {path.name for path in reports.iterdir()} if reports.is_dir() else set()
    check_artifact_set(actual, expected, attempt)

    def read_report(name):
        path = report_path(reports / name, expected[name]["profile"])
        return path.relative_to(reports).as_posix(), path.read_bytes()

    return summarize_reports(expected, read_report, revision, run_id, attempt)


def summary_bytes(summary):
    return (json.dumps(summary, indent=2) + "\n").encode("utf-8")


def read_member(archive, member):
    with archive.open(member) as contents:
        data = contents.read(member.file_size + 1)
    if len(data) != member.file_size:
        raise ValueError("Invalid member size in provider aggregate ZIP")
    return data


def replay_archive(path, revision, run_id, attempt):
    expected = expected_artifacts(attempt)
    with zipfile.ZipFile(path) as archive:
        names = set()
        reports = {}
        summary = None
        for member in archive.infolist():
            name = member.filename
            if name in names:
                raise ValueError("Duplicate member in provider aggregate ZIP")
            names.add(name)
            if member.flag_bits & 0x41:
                raise ValueError("Encrypted member in provider aggregate ZIP")
            if (
                name != member.orig_filename
                or member.is_dir()
                or member.external_attr & 0x10
                or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG)
                or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or not 0 < member.file_size <= MAX_ARCHIVE_MEMBER_SIZE
            ):
                raise ValueError("Invalid member in provider aggregate ZIP")
            if name == "release-summary.json":
                summary = member
                continue
            parts = name.split("/")
            if (
                len(parts) != 4
                or parts[0] != "release-inputs"
                or parts[1] not in expected
                or not is_run_name(parts[2], expected[parts[1]]["profile"])
                or parts[3] != "evidence.json"
            ):
                raise ValueError("Unexpected member in provider aggregate ZIP")
            artifact = parts[1]
            if artifact in reports:
                raise ValueError(f"Expected one original report in {artifact}")
            reports[artifact] = member

        check_artifact_set(reports.keys(), expected, attempt)
        if summary is None:
            raise ValueError("Missing release summary in provider aggregate ZIP")

        def read_report(name):
            member = reports[name]
            return member.filename.removeprefix("release-inputs/"), read_member(archive, member)

        verified = summary_bytes(summarize_reports(expected, read_report, revision, run_id, attempt))
        if read_member(archive, summary) != verified:
            raise ValueError("Release summary differs from the report set")
        return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("selections", help="Print the CI matrix in GitHub include format")
    evidence = commands.add_parser("evidence", help="Write or replay the matrix summary")
    evidence.add_argument("--reports", type=Path)
    evidence.add_argument("--revision", required=True)
    evidence.add_argument("--run-id", type=int, required=True)
    evidence.add_argument("--attempt", type=int, required=True)
    operation = evidence.add_mutually_exclusive_group(required=True)
    operation.add_argument("--write-summary", type=Path)
    operation.add_argument("--verify-summary", type=Path)
    operation.add_argument("--archive", type=Path, help="Replay an original provider aggregate ZIP")
    args = parser.parse_args()
    if args.command == "selections":
        print(json.dumps({"include": selections()}, separators=(",", ":")))
        return
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision) or min(args.run_id, args.attempt) <= 0:
        parser.error("Expected a full lowercase commit SHA and positive run and attempt numbers")
    if args.archive is not None and args.reports is not None:
        parser.error("--archive cannot be combined with --reports")
    if args.archive is None and args.reports is None:
        parser.error("--write-summary and --verify-summary require --reports")

    try:
        if args.archive is not None:
            sys.stdout.buffer.write(replay_archive(args.archive, args.revision, args.run_id, args.attempt))
            return
        result = summarize(args.reports, args.revision, args.run_id, args.attempt)
        encoded = summary_bytes(result)
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
    except (OSError, ValueError, zipfile.BadZipFile, zlib.error, NotImplementedError) as error:
        parser.exit(1, f"{error}\n")
    print(f"Verified {len(result['selections'])} provider reports for attempt {args.attempt}.")


if __name__ == "__main__":
    main()
