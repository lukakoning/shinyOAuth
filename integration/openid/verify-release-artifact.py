"""Verify OpenID matrix job reports, replay a GitHub artifact or retain a verified bundle."""

import argparse
import hashlib
from html import escape
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from zipfile import BadZipFile, ZIP_STORED, ZipFile, ZipInfo


WORKFLOW = ".github/workflows/openid-release-matrix.yml"
PROVENANCE = "https://slsa.dev/provenance/v1"
SUMMARY = "release-summary.json"
BUNDLE_ORIGINALS = {
    "run_metadata": "run.json",
    "artifact_metadata": "artifact.json",
    "archive": "artifact.zip",
}
BUNDLE_RECEIPT = "receipt.json"
BUNDLE_REPORT = "release-report.md"
BUNDLE_ATTESTATION = "attestation.jsonl"
PAIRED_MANIFEST = "paired-release-evidence.json"
PAIRED_ORIGINALS = {"paired_link": "link.zip", "provider_archive": "provider.zip"}
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


def check_run_metadata(args, run):
    repository = run.get("repository", {})
    head_repository = run.get("head_repository", {})
    if not isinstance(repository, dict) or not isinstance(head_repository, dict):
        raise ValueError("Invalid repository metadata for the workflow attempt")
    repository_id = repository.get("id")
    repository_name = repository.get("full_name")
    workflow_path = run.get("path")
    conclusion = "failure" if args.failed_attempt else "success"
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
        or run.get("conclusion") != conclusion
    ):
        outcome = "failed" if args.failed_attempt else "successful"
        raise ValueError(f"Expected the selected {outcome} OpenID matrix workflow attempt")
    return repository_id


def aggregate_name(attempt):
    return f"openid-declared-matrix-evidence-attempt-{attempt}"


def check_artifact_metadata(args, repository_id, artifact, name=None):
    artifact_run = artifact.get("workflow_run", {})
    artifact_id = artifact.get("id")
    digest = artifact.get("digest")
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or artifact.get("name") != (name if name is not None else aggregate_name(args.attempt))
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


def read_suite_policy(revision):
    lock = read_policy(revision, "suite-lock.json")
    profiles = read_policy(revision, "profiles.json")
    plans = profiles.get("plans")
    if (
        not isinstance(plans, dict)
        or not plans
        or profiles.get("source_revision") != lock.get("source_revision")
    ):
        raise ValueError("Committed OpenID profile manifest does not match the suite lock")
    return lock, plans


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


def report_path(path, attempt):
    match = REPORT_PATH.fullmatch(path)
    if not match or int(match["attempt"]) != attempt:
        raise ValueError("Unexpected path in the release artifact")
    kind = match["kind"]
    if kind == match["profile"]:
        kind = "client"
    elif kind not in {"api", "preflight"}:
        raise ValueError("Release report path differs from its selection")
    return (match["profile"], match["transport"]), kind


def check_reports(names, read, attempt, lock, plans):
    selections = {}
    for path in names:
        key, kind = report_path(path, attempt)
        members = selections.setdefault(key, {})
        if kind in members:
            raise ValueError(f"Duplicate {kind} report for {'/'.join(key)}")
        members[kind] = path

    if not selections:
        raise ValueError("No client reports in the release artifact")

    for (profile, transport), members in sorted(selections.items()):
        label = f"{profile}/{transport}"
        if members.keys() != {"api", "client", "preflight"}:
            raise ValueError(f"Expected client, preflight and API reports for {label}")
        data = {kind: read(path) for kind, path in members.items()}
        client = read_object(data["client"])
        if client.get("profile") != profile or client.get("transport") != transport:
            raise ValueError("Release report identity differs from its selection")
        try:
            check_preflight(read_object(data["preflight"]), client, lock)
            check_api(read_object(data["api"]), client, lock, plans)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{label}: {error}") from error
        companion_hashes = {
            f"{kind}_sha256": hashlib.sha256(data[kind]).hexdigest()
            for kind in ("preflight", "api")
        }
        yield label, client, data["client"], companion_hashes


def archive_report_paths(archive):
    names = archive.namelist()
    if SUMMARY not in names or len(names) != len(set(names)):
        raise ValueError("Expected one release summary and unique archive paths")
    names.remove(SUMMARY)
    return names


def read_archive(archive, attempt, directory, lock, plans):
    names = archive_report_paths(archive)

    def read(path):
        return read_member(archive, archive.getinfo(path))

    clients = []
    companions = {}
    for label, _, data, hashes in check_reports(names, read, attempt, lock, plans):
        target = directory / f"client-{len(clients)}.json"
        target.write_bytes(data)
        clients.append(str(target))
        companions[label] = hashes
    return read_member(archive, archive.getinfo(SUMMARY)), clients, companions


def read_failed_archive(archive, attempt, directory):
    names = archive_report_paths(archive)
    summary = read_member(archive, archive.getinfo(SUMMARY))
    recorded = read_object(summary)
    diagnostics = recorded.get("selection_diagnostics")
    if (
        recorded.get("status") != "failed"
        or recorded.get("gate_passed") is not False
        or recorded.get("matrix_complete") is not False
        or not isinstance(diagnostics, list)
        or not diagnostics
    ):
        raise ValueError("Expected a failed release summary with selection diagnostics")

    paths_by_digest = {}
    for index, name in enumerate(names):
        _, kind = report_path(name, attempt)
        if kind != "client":
            continue
        data = read_member(archive, archive.getinfo(name))
        target = directory / f"client-{index}.json"
        target.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        paths_by_digest.setdefault(digest, []).append(str(target))

    # A failed replay can depend on which invalid input the checker saw first.
    try:
        clients = [paths_by_digest[digest].pop() for digest in summary_input_hashes(recorded)]
    except (KeyError, IndexError) as error:
        raise ValueError("Stored failure inputs differ from the archive client reports") from error
    if any(paths_by_digest.values()):
        raise ValueError("Stored failure inputs differ from the archive client reports")
    return summary, clients, diagnostics


def check_downloaded_reports(directory, revision, attempt):
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("Expected a regular downloaded report directory")
    lock, plans = read_suite_policy(revision)
    matrix = read_policy(revision, "release-matrix.json")
    try:
        rows = matrix["selections"]
        expected = {f"{row['profile']}/{row['transport']}" for row in rows}
    except (KeyError, TypeError) as error:
        raise ValueError("Invalid committed release matrix") from error
    if not expected or len(expected) != len(rows):
        raise ValueError("Invalid committed release matrix selections")

    files = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("Downloaded report directories require regular files")
        if path.is_file():
            files[f"release-inputs/{path.relative_to(directory).as_posix()}"] = path

    def read(path):
        with files[path].open("rb") as report:
            data = report.read(MAX_REPORT_BYTES + 1)
        if not 0 < len(data) <= MAX_REPORT_BYTES:
            raise ValueError("Expected a nonempty evidence file of at most 64 MiB")
        return data

    observed = set()
    for label, client, _, _ in check_reports(files, read, attempt, lock, plans):
        if (
            client.get("checkout_revision") != revision
            or client.get("checkout_dirty") is not False
            or client.get("status") != "passed"
            or client.get("gate_passed") is not True
        ):
            raise ValueError(
                f"Expected a passing client report at the selected revision for {label}"
            )
        observed.add(label)
    if expected != observed:
        missing = ", ".join(sorted(expected - observed)) or "none"
        unexpected = ", ".join(sorted(observed - expected)) or "none"
        raise ValueError(
            "Downloaded report selections differ from the matrix "
            f"(missing {missing}, unexpected {unexpected})"
        )
    return len(observed)


def read_member(archive, member):
    if not 0 < member.file_size <= MAX_REPORT_BYTES:
        raise ValueError("Expected a nonempty evidence file of at most 64 MiB")
    return archive.read(member)


def summary_input_hashes(summary):
    hashes = summary.get("input_sha256")
    if not isinstance(hashes, list) or not all(
        isinstance(value, str) and SHA256.fullmatch(value) for value in hashes
    ):
        raise ValueError("Invalid client report digests in the release summary")
    return hashes


def summary_for_comparison(data):
    summary = read_object(data)
    # This field enumerates the inputs in invocation order. Entries carry their own digest.
    summary["input_sha256"] = sorted(summary_input_hashes(summary))
    return json.dumps(summary, sort_keys=True)


def release_report(summary, lock, receipt):
    provenance = lock.get("provenance", {})
    changed = provenance.get("upstream_verification_modified")
    changed = json.dumps(changed) if type(changed) is bool else "unrecorded"
    run_url = f"https://github.com/{receipt['repository']}/actions/runs/{receipt['run_id']}"
    lines = [
        "# OpenID client release evidence",
        "",
        f"Verified {summary['selection_count']} declared profile and transport selections.",
        "",
        f"- shinyOAuth `{summary['package_version']}` at `{summary['checkout_revision']}`.",
        f"- OIDF suite `{lock['source_description']}` at `{lock['source_revision']}`.",
        f"- Matrix `{summary['matrix_id']}` and callback policy `{summary['callback_rejection_policy']}`.",
        f"- [GitHub run {receipt['run_id']}]({run_url}), "
        f"attempt `{receipt['attempt']}`, artifact `{receipt['artifact_id']}`.",
        f"- Original artifact SHA-256 `{receipt['artifact_sha256']}`.",
        f"- Certification status `{summary['certification_status']}`.",
        "",
        "## Suite fixture",
        "",
        f"The suite lock records `upstream_verification_modified = {changed}`.",
    ]
    proxy = provenance.get("proxy_configuration")
    if isinstance(proxy, str) and proxy:
        lines.append(escape(proxy))
    lines.extend((
        "",
        "| Image | Locked reference |",
        "| --- | --- |",
    ))
    for name, image in sorted(lock["images"].items()):
        lines.append(f"| {name} | `{image}` |")
    lines.extend((
        "",
        "## Declared selections",
        "",
        "| Profile | Transport | Finished / available | Passed | Warnings | Skipped | Coverage | Recorded limits |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
    ))
    exceptions = []
    for entry in summary["entries"]:
        profile, transport = entry["profile"], entry["transport"]
        assessment = entry["assessment"]
        modules = assessment["module_counts"]
        verdicts = assessment["suite_verdict_counts"]
        limits = sorted({code for codes in assessment["limitations"].values() for code in codes})
        recorded = ", ".join(f"`{code}`" for code in limits) or "None recorded"
        coverage = "Complete" if entry["coverage_complete"] else "Limited"
        lines.append(
            f"| `{profile}` | `{transport}` | {modules['finished']} / {modules['available']} "
            f"| {verdicts['PASSED']} | {verdicts['WARNING']} | {verdicts['SKIPPED']} "
            f"| {coverage} | {recorded} |"
        )
        for result in assessment["accepted_non_passed_results"]:
            exceptions.append(
                f"| `{profile}/{transport}` | `{result['module']}` "
                f"| `{result['suite_result']}` | `{result['policy']}` |"
            )
    if exceptions:
        lines.extend((
            "",
            "## Accepted suite warnings and skips",
            "",
            "| Selection | Module | Suite verdict | Verified policy |",
            "| --- | --- | --- | --- |",
            *exceptions,
        ))
    return "\n".join(lines) + "\n"


def verify_attestation(args, repository_id, name, digest):
    command = [
        "gh", "attestation", "verify", str(args.archive), "--hostname", "github.com",
        "--repo", args.repository, "--signer-workflow", f"{args.repository}/{WORKFLOW}",
        "--source-digest", args.revision, "--signer-digest", args.revision,
        "--deny-self-hosted-runners", "--predicate-type", PROVENANCE, "--format", "json",
    ]
    if args.attestation_bundle is not None:
        command.extend(("--bundle", str(args.attestation_bundle)))
    if args.attestation_root is not None:
        command.extend(("--custom-trusted-root", str(args.attestation_root)))
    result = subprocess.run(command, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"GitHub attestation verification failed: {detail}")

    attestations = json.loads(result.stdout, object_pairs_hook=unique_object)
    if not isinstance(attestations, list):
        raise ValueError("Expected verified GitHub attestations")

    invocation = f"https://github.com/{args.repository}/actions/runs/{args.run_id}/attempts/{args.attempt}"
    subject = {"name": name, "digest": {"sha256": digest}}
    for attestation in attestations:
        try:
            verified = attestation["verificationResult"]
            certificate = verified["signature"]["certificate"]
            statement = verified["statement"]
            run_uri = certificate["runInvocationURI"]
            if (
                isinstance(run_uri, str)
                and run_uri.lower() == invocation.lower()
                and certificate["sourceRepositoryIdentifier"] == str(repository_id)
                and certificate["buildTrigger"] == "workflow_dispatch"
                and statement["predicateType"] == PROVENANCE
                and subject in statement["subject"]
            ):
                return
        except (KeyError, TypeError):
            continue
    raise ValueError("No verified attestation identifies the expected run attempt and aggregate ZIP")


def verify(args, report_path=None):
    run = read_object(args.run_metadata.read_bytes())
    artifact = read_object(args.artifact_metadata.read_bytes())
    repository_id = check_run_metadata(args, run)
    digest = check_artifact_metadata(args, repository_id, artifact)
    with args.archive.open("rb") as file, tempfile.TemporaryDirectory() as tmp:
        if hashlib.file_digest(file, "sha256").hexdigest() != digest:
            raise ValueError("Release artifact ZIP differs from the GitHub SHA-256 digest")
        if args.require_attestation:
            verify_attestation(args, repository_id, f"{artifact['name']}.zip", digest)
        directory = Path(tmp)
        with ZipFile(file) as archive:
            if args.failed_attempt:
                summary, clients, diagnostics = read_failed_archive(archive, args.attempt, directory)
            else:
                lock, plans = read_suite_policy(args.revision)
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
        expected_exit = 1 if args.failed_attempt else 0
        if result.returncode != expected_exit or not replay_path.is_file():
            raise ValueError(f"Release checker replay failed: {result.stderr.strip()}")
        replay = replay_path.read_bytes()
        if summary_for_comparison(summary) != summary_for_comparison(replay):
            raise ValueError("Stored release summary differs from the independent replay")

    receipt = {
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
    if args.failed_attempt:
        receipt.update(gate_passed=False, matrix_complete=False, selection_diagnostics=diagnostics)
    else:
        receipt["companion_reports"] = companions
        if report_path is not None:
            markdown = release_report(read_object(replay), lock, receipt)
            report_file = report_path.open("x", encoding="utf-8", newline="\n")
            try:
                with report_file:
                    report_file.write(markdown)
            except OSError:
                report_path.unlink(missing_ok=True)
                raise
    return receipt


def bundle_inputs(args, directory):
    inputs = {field: directory / name for field, name in BUNDLE_ORIGINALS.items()}
    return argparse.Namespace(**(vars(args) | inputs))


def paired_inputs(args, directory):
    inputs = {field: directory / name for field, name in PAIRED_ORIGINALS.items()}
    return argparse.Namespace(**(vars(bundle_inputs(args, directory)) | inputs))


def paired_link_name(attempt):
    return f"openid-provider-release-link-attempt-{attempt}"


def paired_artifacts(args, manifest):
    identity = {
        "schema_version": 1, "revision": args.revision, "run_id": args.run_id, "attempt": args.attempt,
    }
    repository = manifest.get("repository")
    if (
        set(manifest) != {*identity, "repository", "artifacts"}
        or not isinstance(repository, str) or repository.lower() != args.repository.lower()
        or any(
            type(manifest[key]) is not type(value) or manifest[key] != value
            for key, value in identity.items()
        )
    ):
        raise ValueError("Paired evidence does not identify the selected repository, revision and run attempt")

    names = {
        "oidf": aggregate_name(args.attempt),
        "provider": f"oidc-provider-release-evidence-attempt-{args.attempt}",
    }
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or artifacts.keys() != names.keys():
        raise ValueError("Expected the OIDF and provider aggregates in the paired evidence")
    for matrix, name in names.items():
        artifact = artifacts[matrix]
        if (
            not isinstance(artifact, dict) or set(artifact) != {"id", "name", "sha256"}
            or type(artifact["id"]) is not int or artifact["id"] <= 0
            or artifact["name"] != name
            or not isinstance(artifact["sha256"], str) or not SHA256.fullmatch(artifact["sha256"])
        ):
            raise ValueError(f"Invalid {matrix} aggregate reference in the paired evidence")
    if artifacts["oidf"]["id"] == artifacts["provider"]["id"]:
        raise ValueError("Expected distinct aggregate artifacts in the paired evidence")
    return artifacts


def verify_paired_link(args, repository_id):
    link_name = f"{paired_link_name(args.attempt)}.zip"
    link_args = argparse.Namespace(**(vars(args) | {"archive": args.paired_link}))
    with args.paired_link.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
        verify_attestation(link_args, repository_id, link_name, digest)
        with ZipFile(file) as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].orig_filename != PAIRED_MANIFEST or members[0].flag_bits & 0x41:
                raise ValueError("Expected one unencrypted paired-release-evidence.json in the link ZIP")
            artifacts = paired_artifacts(args, read_object(read_member(archive, members[0])))
    return digest, artifacts


def replay_paired_aggregates(args, repository_id, link_digest, artifacts, report_path=None):
    artifact = read_object(args.artifact_metadata.read_bytes())
    oidf_digest = check_artifact_metadata(args, repository_id, artifact)
    if artifacts["oidf"]["id"] != artifact["id"] or artifacts["oidf"]["sha256"] != oidf_digest:
        raise ValueError("OIDF artifact metadata differs from the signed link")

    with args.provider_archive.open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != artifacts["provider"]["sha256"]:
            raise ValueError("Provider aggregate ZIP differs from the signed SHA-256 digest")
    result = subprocess.run([
        sys.executable, str(Path(__file__).resolve().parent.parent / "oidc-provider/release-matrix.py"),
        "evidence", "--revision", args.revision, "--run-id", str(args.run_id), "--attempt", str(args.attempt),
        "--archive", str(args.provider_archive),
    ], capture_output=True)
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"Provider aggregate replay failed: {detail}")
    provider_reports = read_object(result.stdout).get("selections")
    if not isinstance(provider_reports, list) or not provider_reports:
        raise ValueError("Expected a verified provider report summary")

    receipt = verify(args, report_path=report_path)
    receipt["paired_evidence"] = {
        "link_sha256": link_digest,
        "artifacts": artifacts,
        "provider_report_count": len(provider_reports),
    }
    return receipt


def verify_paired_evidence(args):
    with tempfile.TemporaryDirectory() as tmp:
        replay = paired_inputs(args, Path(tmp))
        for field in (*BUNDLE_ORIGINALS, *PAIRED_ORIGINALS):
            shutil.copyfile(getattr(args, field), getattr(replay, field))
        repository_id = check_run_metadata(replay, read_object(replay.run_metadata.read_bytes()))
        link_digest, artifacts = verify_paired_link(replay, repository_id)
        return replay_paired_aggregates(replay, repository_id, link_digest, artifacts)


def write_release_bundle(args):
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        replay = bundle_inputs(args, directory)
        for field in BUNDLE_ORIGINALS:
            shutil.copyfile(getattr(args, field), getattr(replay, field))
        names = [*BUNDLE_ORIGINALS.values(), BUNDLE_REPORT, BUNDLE_RECEIPT]
        if args.attestation_bundle is not None:
            with args.attestation_bundle.open("rb") as sidecar:
                proof = sidecar.read(MAX_REPORT_BYTES + 1)
            if not 0 < len(proof) <= MAX_REPORT_BYTES:
                raise ValueError("Expected a nonempty attestation file of at most 64 MiB")
            replay.attestation_bundle = directory / BUNDLE_ATTESTATION
            replay.attestation_bundle.write_bytes(proof)
            names.append(BUNDLE_ATTESTATION)
        report = directory / BUNDLE_REPORT
        receipt = verify(replay, report_path=report)
        receipt_bytes = (json.dumps(receipt, indent=2) + "\n").encode("utf-8")
        (directory / BUNDLE_RECEIPT).write_bytes(receipt_bytes)

        output = args.bundle_output.open("xb")
        try:
            with output, ZipFile(output, "w") as bundle:
                for name in names:
                    path = directory / name
                    entry = ZipInfo(name)
                    entry.create_system = 3
                    entry.file_size = path.stat().st_size
                    with path.open("rb") as source, bundle.open(entry, "w") as member:
                        shutil.copyfileobj(source, member)
        except (OSError, RuntimeError):
            args.bundle_output.unlink(missing_ok=True)
            raise
    return receipt


def verify_release_bundle(args):
    expected = {*BUNDLE_ORIGINALS.values(), BUNDLE_RECEIPT, BUNDLE_REPORT}
    with ZipFile(args.bundle_input) as bundle, tempfile.TemporaryDirectory() as tmp:
        members = bundle.infolist()
        names = {member.filename for member in members}
        embedded_attestation = BUNDLE_ATTESTATION in names
        if embedded_attestation:
            expected.add(BUNDLE_ATTESTATION)
        if (
            len(members) != len(expected)
            or names != expected
            or any(member.compress_type != ZIP_STORED or member.flag_bits & 1 for member in members)
        ):
            raise ValueError("Expected the five original and derived files and at most one stored attestation")

        directory = Path(tmp)
        replay = bundle_inputs(args, directory)
        if embedded_attestation:
            if not args.require_attestation or args.attestation_root is None or args.attestation_bundle is not None:
                raise ValueError("Embedded attestation replay requires --require-attestation and --attestation-root only")
            replay.attestation_bundle = directory / BUNDLE_ATTESTATION
            replay.attestation_bundle.write_bytes(read_member(bundle, bundle.getinfo(BUNDLE_ATTESTATION)))
        elif args.attestation_root is not None and args.attestation_bundle is None:
            raise ValueError("Release bundle has no embedded attestation. Supply --attestation-bundle for a separate proof.")
        for field, name in BUNDLE_ORIGINALS.items():
            target = getattr(replay, field)
            if field == "archive":
                with bundle.open(name) as source, target.open("wb") as copied:
                    shutil.copyfileobj(source, copied)
            else:
                target.write_bytes(read_member(bundle, bundle.getinfo(name)))
        receipt = read_object(read_member(bundle, bundle.getinfo(BUNDLE_RECEIPT)))
        report = read_member(bundle, bundle.getinfo(BUNDLE_REPORT))
        regenerated = directory / BUNDLE_REPORT
        replayed = verify(replay, report_path=regenerated)
        if receipt != replayed or report != regenerated.read_bytes():
            raise ValueError("Release bundle receipt or Markdown differs from the independent replay")
        return replayed


def github_api(endpoint, stdout=subprocess.PIPE):
    try:
        return subprocess.run(
            ["gh", "api", "--hostname", "github.com", endpoint],
            stdout=stdout,
            check=True,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise ValueError(f"GitHub API request failed: {endpoint}") from error


def find_run_artifact(run_api, name):
    listing = read_object(github_api(f"{run_api}/artifacts?name={name}&per_page=2"))
    artifacts = listing.get("artifacts")
    if (
        listing.get("total_count") != 1
        or not isinstance(artifacts, list)
        or len(artifacts) != 1
        or not isinstance(artifacts[0], dict)
        or artifacts[0].get("name") != name
        or type(artifacts[0].get("id")) is not int
        or artifacts[0]["id"] <= 0
        or artifacts[0].get("expired") is not False
    ):
        raise ValueError(f"Expected one available {name} artifact for the selected attempt")
    return artifacts[0]["id"]


def publish_bundle(stage, destination, receipt):
    (stage / BUNDLE_RECEIPT).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    # A concurrent successful collector leaves a nonempty destination.
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Bundle destination already exists: {destination}")
    stage.rename(destination)


def retain(args):
    destination = args.retain
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Bundle destination already exists: {destination}")

    actions_api = f"repos/{args.repository}/actions"
    run_api = f"{actions_api}/runs/{args.run_id}"
    run_data = github_api(f"{run_api}/attempts/{args.attempt}")
    repository_id = check_run_metadata(args, read_object(run_data))
    artifact_id = find_run_artifact(run_api, aggregate_name(args.attempt))
    artifact_api = f"{actions_api}/artifacts/{artifact_id}"
    artifact_data = github_api(artifact_api)
    artifact = read_object(artifact_data)
    check_artifact_metadata(args, repository_id, artifact)
    if artifact["id"] != artifact_id or artifact.get("expired") is not False:
        raise ValueError("Aggregate artifact identity or availability changed")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".openid-matrix-", dir=destination.parent) as tmp:
        stage = Path(tmp) / "bundle"
        stage.mkdir()
        replay = bundle_inputs(args, stage)
        replay.run_metadata.write_bytes(run_data)
        replay.artifact_metadata.write_bytes(artifact_data)
        with replay.archive.open("wb") as archive:
            github_api(f"{artifact_api}/zip", stdout=archive)
        receipt = verify(replay, report_path=stage / BUNDLE_REPORT)
        publish_bundle(stage, destination, receipt)
    return receipt


def collect_paired_artifact(args, repository_id, actions_api, reference, archive, metadata):
    endpoint = f"{actions_api}/artifacts/{reference['id']}"
    data = github_api(endpoint)
    artifact = read_object(data)
    digest = check_artifact_metadata(args, repository_id, artifact, name=reference["name"])
    if (
        artifact["id"] != reference["id"] or artifact.get("expired") is not False
        or digest != reference.get("sha256", digest)
    ):
        raise ValueError(f"Artifact identity, digest or availability differs for {reference['name']}")
    metadata.write_bytes(data)
    with archive.open("wb") as output:
        github_api(f"{endpoint}/zip", stdout=output)
    return digest


def download_paired_attestation(args, directory, digest):
    result = subprocess.run([
        "gh", "attestation", "download", str(args.paired_link.resolve()), "--hostname", "github.com",
        "--repo", args.repository, "--predicate-type", PROVENANCE,
    ], cwd=directory, capture_output=True)
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"GitHub link attestation download failed: {detail}")
    separator = "-" if os.name == "nt" else ":"
    proof = directory / f"sha256{separator}{digest}.jsonl"
    if not proof.is_file() or proof.is_symlink() or not 0 < proof.stat().st_size <= MAX_REPORT_BYTES:
        raise ValueError("Expected a downloaded Sigstore bundle for the link ZIP digest")
    return proof


def retain_paired(args):
    destination = args.retain_paired
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Bundle destination already exists: {destination}")

    actions_api = f"repos/{args.repository}/actions"
    run_api = f"{actions_api}/runs/{args.run_id}"
    run_data = github_api(f"{run_api}/attempts/{args.attempt}")
    repository_id = check_run_metadata(args, read_object(run_data))
    name = paired_link_name(args.attempt)
    link_reference = {"id": find_run_artifact(run_api, name), "name": name}

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".openid-matrix-", dir=destination.parent) as tmp:
        directory = Path(tmp)
        stage = directory / "bundle"
        stage.mkdir()
        replay = paired_inputs(args, stage)
        replay.run_metadata.write_bytes(run_data)
        expected_digest = collect_paired_artifact(
            replay, repository_id, actions_api, link_reference, replay.paired_link, stage / "link-artifact.json",
        )
        with replay.paired_link.open("rb") as file:
            if hashlib.file_digest(file, "sha256").hexdigest() != expected_digest:
                raise ValueError("Paired link ZIP differs from the GitHub SHA-256 digest")
        proof = download_paired_attestation(replay, directory, expected_digest)
        replay.attestation_bundle = proof.rename(stage / BUNDLE_ATTESTATION)
        link_digest, artifacts = verify_paired_link(replay, repository_id)

        collect_paired_artifact(
            replay, repository_id, actions_api, artifacts["oidf"], replay.archive, replay.artifact_metadata,
        )
        collect_paired_artifact(
            replay, repository_id, actions_api, artifacts["provider"], replay.provider_archive,
            stage / "provider-artifact.json",
        )
        receipt = replay_paired_aggregates(
            replay, repository_id, link_digest, artifacts, report_path=stage / BUNDLE_REPORT,
        )
        publish_bundle(stage, destination, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", help="GitHub OWNER/REPO for ZIP replay or retention")
    parser.add_argument("--revision", required=True, help="Full expected Git commit SHA")
    parser.add_argument("--run-id", type=int, help="GitHub run ID for ZIP replay or retention")
    parser.add_argument("--attempt", required=True, type=int)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument(
        "--downloaded-reports", type=Path, help="Check the downloaded job artifact directories in CI"
    )
    inputs.add_argument(
        "--retain", type=Path, help="Fetch and verify a GitHub attempt into a new directory"
    )
    inputs.add_argument(
        "--retain-paired", type=Path, help="Fetch and verify signed paired evidence into a new directory"
    )
    inputs.add_argument(
        "--bundle-input", type=Path, help="Replay a saved release bundle offline"
    )
    inputs.add_argument(
        "--paired-link", type=Path, help="Verify the original signed link ZIP and replay both aggregates"
    )
    parser.add_argument("--provider-archive", type=Path, help="Original provider aggregate ZIP for paired replay")
    parser.add_argument(
        "--failed-attempt", action="store_true", help="Replay a failed client aggregate and its diagnostics"
    )
    parser.add_argument(
        "--require-attestation", action="store_true", help="Require signed provenance for the original GitHub ZIP"
    )
    parser.add_argument(
        "--attestation-bundle", type=Path, help="Saved GitHub Sigstore bundle to verify and embed with --bundle-output"
    )
    parser.add_argument("--attestation-root", type=Path, help="Trusted Sigstore roots for offline verification")
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument(
        "--report-output", type=Path, help="Write verified Markdown to a new file during offline replay"
    )
    outputs.add_argument(
        "--bundle-output", type=Path, help="Pack a verified offline replay into a new release ZIP"
    )
    parser.add_argument(
        "run_metadata", type=Path, nargs="?", help="GitHub workflow run attempt JSON"
    )
    parser.add_argument(
        "artifact_metadata", type=Path, nargs="?", help="GitHub aggregate artifact JSON"
    )
    parser.add_argument(
        "archive", type=Path, nargs="?", help="Original GitHub artifact ZIP bytes"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.revision):
        parser.error("--revision requires a full lowercase Git commit SHA")
    if args.attempt <= 0 or (args.run_id is not None and args.run_id <= 0):
        parser.error("--run-id and --attempt must be positive")
    paired = args.paired_link is not None
    if paired != (args.provider_archive is not None):
        parser.error("Paired replay requires both --paired-link and --provider-archive")
    if paired and (args.failed_attempt or args.require_attestation or args.report_output or args.bundle_output):
        parser.error("Paired replay uses the link attestation and emits a JSON receipt for a passing attempt")
    if args.retain_paired is not None and (
        args.failed_attempt or args.require_attestation or args.attestation_bundle or args.attestation_root
        or args.report_output or args.bundle_output
    ):
        parser.error("--retain-paired fetches its own signed evidence and writes all outputs to its destination")
    if args.require_attestation and (args.failed_attempt or args.downloaded_reports is not None):
        parser.error("--require-attestation needs the ZIP of a passing attempt")
    if args.attestation_bundle is not None and args.attestation_root is None:
        parser.error("--attestation-bundle requires --attestation-root")
    if args.attestation_root is not None and (
        not (args.require_attestation or paired) or (args.attestation_bundle is None and args.bundle_input is None)
    ):
        parser.error("--attestation-root requires attestation verification and a saved or embedded attestation")
    if (args.report_output is not None or args.bundle_output is not None) and (
        args.failed_attempt or args.retain is not None or args.downloaded_reports is not None
        or args.bundle_input is not None
    ):
        parser.error("Report and bundle output require the three original files of a passing attempt")
    files = (args.run_metadata, args.artifact_metadata, args.archive)
    if args.downloaded_reports is not None:
        if args.failed_attempt or any(
            value is not None for value in (args.repository, args.run_id, args.retain, *files)
        ):
            parser.error("--downloaded-reports must be used independently of ZIP replay or retention")
    elif args.retain is not None or args.retain_paired is not None:
        option = "--retain-paired" if args.retain_paired is not None else "--retain"
        if args.run_id is None or not re.fullmatch(
            r"[a-zA-Z0-9-]+/(?!\.{1,2}$)[a-zA-Z0-9_.-]+", args.repository or ""
        ):
            parser.error(f"{option} requires --repository OWNER/REPO and --run-id")
        if any(value is not None for value in files):
            parser.error(f"{option} downloads its own input files")
    elif args.bundle_input is not None:
        if args.repository is None or args.run_id is None:
            parser.error("--bundle-input requires --repository and --run-id")
        if args.failed_attempt or any(value is not None for value in files):
            parser.error("--bundle-input replays a passing attempt from the files in the bundle")
    elif any(value is None for value in (args.repository, args.run_id, *files)):
        parser.error("ZIP replay requires --repository, --run-id and all three input files")
    try:
        if args.downloaded_reports is not None:
            count = check_downloaded_reports(
                args.downloaded_reports, args.revision, args.attempt
            )
            print(f"Verified preflight and API reports for {count} declared OpenID selections.")
        elif args.retain is not None:
            receipt = retain(args)
            if args.failed_attempt:
                print(f"Retained and replayed failed OpenID matrix diagnostics in {args.retain}.")
            else:
                print(f"Retained {receipt['client_report_count']} verified OpenID selections in {args.retain}.")
        elif args.retain_paired is not None:
            receipt = retain_paired(args)
            print(
                f"Retained {receipt['client_report_count']} OpenID and "
                f"{receipt['paired_evidence']['provider_report_count']} provider selections in {args.retain_paired}."
            )
        elif args.bundle_input is not None:
            print(json.dumps(verify_release_bundle(args), indent=2))
        elif paired:
            print(json.dumps(verify_paired_evidence(args), indent=2))
        elif args.bundle_output is not None:
            print(json.dumps(write_release_bundle(args), indent=2))
        else:
            print(json.dumps(verify(args, report_path=args.report_output), indent=2))
        if args.require_attestation:
            print("Verified the GitHub attestation for the original aggregate ZIP.", file=sys.stderr)
    except (BadZipFile, OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
