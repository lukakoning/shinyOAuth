import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile


spec = importlib.util.spec_from_file_location(
    "release_artifact", Path(__file__).with_name("verify-release-artifact.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ReleaseArtifactTest(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.args = SimpleNamespace(
            repository="owner/repository",
            revision="a" * 40,
            run_id=10,
            attempt=2,
            failed_attempt=False,
            run_metadata=directory / "run.json",
            artifact_metadata=directory / "artifact.json",
            archive=directory / "artifact.zip",
        )
        self.run = {
            "repository": {"id": 11, "full_name": self.args.repository},
            "head_repository": {"id": 11},
            "id": self.args.run_id,
            "run_attempt": self.args.attempt,
            "head_sha": self.args.revision,
            "path": verifier.WORKFLOW,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
        }
        self.artifact = {
            "id": 12,
            "name": "openid-declared-matrix-evidence-attempt-2",
            "workflow_run": {
                "id": self.args.run_id,
                "repository_id": 11,
                "head_repository_id": 11,
                "head_sha": self.args.revision,
            },
        }
        self.summary = {
            "input_sha256": ["b" * 64, "a" * 64], "matrix_complete": True,
            "entries": [{"profile": "smoke"}, {"profile": "basic"}],
        }
        self.lock = {
            "source_revision": "b" * 40,
            "source_description": "release-v5.3.4",
            "provenance": {"release_tag": "release-v5.3.4"},
            "images": {"server": "pinned-server"},
        }
        spec = {
            "plan": "basic", "plan_variant": {"client": "oidc"},
            "module_variant": {"response_mode": "query"},
            "available_modules": ["oidcc-client-test", "oidcc-client-test-second"],
        }
        self.plans = {"basic": spec}
        self.matrix = {"selections": [{"profile": "smoke", "transport": "sync"}]}
        self.enterContext(patch.object(
            verifier, "read_policy", side_effect=lambda revision, name: {
                "suite-lock.json": self.lock,
                "profiles.json": {
                    "plans": self.plans,
                    "source_revision": self.lock["source_revision"],
                },
                "release-matrix.json": self.matrix,
            }[name],
        ))
        source = {"revision": self.args.revision, "tree": "f" * 40}
        installation = {
            "revision": self.args.revision, "tree": source["tree"],
            "method": "git_archive", "source_fingerprint": "a" * 64,
            "archive_sha256": "e" * 64, "package_version": "1.2.3",
        }
        self.report = {
            "profile": "smoke", "transport": "sync", "checkout_revision": self.args.revision,
            "checkout_source": source, "installation": installation,
            "checkout_dirty": False, "status": "passed", "gate_passed": True,
        }
        common = {
            "status": "passed", "application_flow": "not_attempted",
            "coverage_complete": False, "source_verified": True, "cleanup_verified": True,
            "checkout_dirty": False, "checkout_revision": self.args.revision,
            "checkout_source": source, "checkout_source_after": source,
            "source_revision": self.lock["source_revision"], "images": self.lock["images"],
            "image_sources": {"server": "cached"},
        }
        self.preflight = {
            **common, "schema_version": 2, "environment_checks": "passed",
            "required_plans_present": True,
            "r_tls": "certificate chain and hostname verified against temporary trust anchor",
            "browser_tls": {"secure_context": True, "wrong_pin_rejected": True},
            "server_info": {
                "revision": self.lock["source_revision"][:7],
                "tag": self.lock["provenance"]["release_tag"],
            },
            "image_provenance": {
                "revision": self.lock["source_revision"],
                "description": self.lock["source_description"], "dirty": False,
            },
        }
        self.api = {
            **common, "schema_version": 4, "gate_passed": False, "upstream_plan_complete": False,
            "api_checks": {name: True for name in verifier.API_CHECKS},
            "installation": installation, "installation_after": installation,
            "regression_installation_after": installation,
            "plan_inventory": {"basic": {
                "plan": spec["plan"], "plan_variant": spec["plan_variant"],
                "module_variant": spec["module_variant"],
                "modules": list(reversed(spec["available_modules"])),
                "probe_module": spec["available_modules"][0], "probe_cancelled": True,
                "probe_variant": spec["plan_variant"] | spec["module_variant"],
            }},
        }
        self.member = (
            "release-inputs/openid-client-smoke-sync-evidence-attempt-2/"
            "smoke-20261121-130000-123456abcdef/evidence.json"
        )

    def write_fixture(self, extra=None, omit=None):
        with ZipFile(self.args.archive, "w") as archive:
            archive.writestr(verifier.SUMMARY, json.dumps(self.summary))
            archive.writestr(self.member, json.dumps(self.report))
            for kind, report in (("api", self.api), ("preflight", self.preflight)):
                if kind == omit:
                    continue
                archive.writestr(
                    self.member.replace("/smoke-20261121", f"/{kind}-20261121"),
                    json.dumps(report),
                )
            if extra:
                archive.writestr(extra, "{}")
        self.write_metadata()

    def write_metadata(self):
        digest = hashlib.sha256(self.args.archive.read_bytes()).hexdigest()
        self.artifact["digest"] = f"sha256:{digest}"
        self.args.run_metadata.write_text(json.dumps(self.run), encoding="utf-8")
        self.args.artifact_metadata.write_text(json.dumps(self.artifact), encoding="utf-8")

    def mock_replay(self, replay, inputs=None, returncode=0):
        if inputs is None:
            inputs = [json.dumps(self.report).encode()]

        def run(command, **options):
            self.assertEqual(command[:4], [
                "Rscript", "integration/openid/run-release-check.R",
                "--revision", self.args.revision,
            ])
            self.assertEqual(command[4], "--output")
            self.assertEqual([Path(path).read_bytes() for path in command[6:]], inputs)
            Path(command[5]).write_text(json.dumps(replay), encoding="utf-8")
            return SimpleNamespace(returncode=returncode, stderr="")

        return patch.object(verifier.subprocess, "run", side_effect=run)

    def downloaded_fixture(self, omit=None):
        self.write_fixture(omit=omit)
        root = self.args.archive.parent / "release-inputs"
        with ZipFile(self.args.archive) as archive:
            for name in archive.namelist():
                if name == verifier.SUMMARY:
                    continue
                target = root / name.removeprefix("release-inputs/")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(name))
        return root

    def test_receipt_replays_original_bytes_and_accepts_reordered_input_hashes(self):
        self.write_fixture()
        replay = {**self.summary, "input_sha256": list(reversed(self.summary["input_sha256"]))}
        with self.mock_replay(replay):
            receipt = verifier.verify(self.args)
        self.assertEqual(receipt["artifact_sha256"], self.artifact["digest"][7:])
        self.assertEqual(receipt["client_report_count"], 1)
        self.assertEqual(receipt["companion_reports"]["smoke/sync"], {
            f"{kind}_sha256": hashlib.sha256(json.dumps(report).encode()).hexdigest()
            for kind, report in (("api", self.api), ("preflight", self.preflight))
        })

    def test_rejects_changed_summary(self):
        self.write_fixture()
        replay = {**self.summary, "entries": list(reversed(self.summary["entries"]))}
        with self.mock_replay(replay), self.assertRaisesRegex(ValueError, "summary differs"):
            verifier.verify(self.args)

    def test_rejects_changed_archive_bytes_before_replay(self):
        self.write_fixture()
        with self.args.archive.open("ab") as archive:
            archive.write(b"extra bytes")
        with self.assertRaisesRegex(ValueError, "SHA-256 digest"):
            verifier.verify(self.args)

    def test_rejects_failed_run_and_wrong_artifact_name(self):
        self.run["conclusion"] = "failure"
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "successful OpenID matrix workflow attempt"):
            verifier.verify(self.args)
        self.run["conclusion"] = "success"
        self.artifact["name"] = "openid-declared-matrix-evidence-attempt-1"
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "aggregate artifact"):
            verifier.verify(self.args)

    def failed_attempt_fixture(self, inputs, status):
        self.args.failed_attempt = True
        self.run["conclusion"] = "failure"
        hashes = [hashlib.sha256(data).hexdigest() for data in inputs]
        self.summary = {
            "status": "failed", "gate_passed": False, "matrix_complete": False,
            "input_sha256": hashes,
            "selection_diagnostics": [{
                "profile": "smoke", "transport": "sync", "status": status,
                "report_sha256": hashes,
            }],
        }
        with ZipFile(self.args.archive, "w") as archive:
            archive.writestr(verifier.SUMMARY, json.dumps(self.summary))
            for i, data in enumerate(reversed(inputs)):
                archive.writestr(self.member.replace("130000", f"13000{i}"), data)
        self.write_metadata()

    def test_failed_attempt_replays_every_report_in_the_original_order(self):
        inputs = [json.dumps({**self.report, "run": i}).encode() for i in range(2)]
        self.failed_attempt_fixture(inputs, "duplicate")
        with self.mock_replay(self.summary, inputs=inputs, returncode=1):
            receipt = verifier.verify(self.args)
        self.assertIs(receipt["gate_passed"], False)
        self.assertIs(receipt["matrix_complete"], False)
        self.assertEqual(receipt["client_report_count"], 2)
        self.assertEqual(receipt["selection_diagnostics"], self.summary["selection_diagnostics"])
        self.assertNotIn("companion_reports", receipt)

    def test_failed_attempt_replays_missing_all_reports(self):
        self.failed_attempt_fixture([], "missing")
        with self.mock_replay(self.summary, inputs=[], returncode=1):
            receipt = verifier.verify(self.args)
        self.assertEqual(receipt["client_report_count"], 0)
        self.assertEqual(receipt["selection_diagnostics"][0]["status"], "missing")

    def test_failed_attempt_rejects_changed_diagnostics(self):
        self.failed_attempt_fixture([], "missing")
        replay = {**self.summary, "selection_diagnostics": [{"status": "reported_failure"}]}
        with self.mock_replay(replay, inputs=[], returncode=1):
            with self.assertRaisesRegex(ValueError, "summary differs"):
                verifier.verify(self.args)

    def test_rejects_extra_files_and_reports_in_the_wrong_directory(self):
        self.write_fixture(extra="release-inputs/browser.log")
        with self.assertRaisesRegex(ValueError, "Unexpected path"):
            verifier.verify(self.args)
        self.report["transport"] = "mirai"
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "report identity differs"):
            verifier.verify(self.args)

    def test_requires_exactly_one_of_each_companion_for_the_selection(self):
        self.write_fixture(omit="preflight")
        with self.assertRaisesRegex(ValueError, "Expected client, preflight and API reports"):
            verifier.verify(self.args)

        duplicate = self.member.replace("/smoke-20261121-130000", "/api-20261121-140000")
        self.write_fixture(extra=duplicate)
        with self.assertRaisesRegex(ValueError, "Duplicate api report"):
            verifier.verify(self.args)

    def test_rejects_changed_source_tls_and_api_inventory(self):
        for report, key, value, explanation in (
            (self.preflight, "checkout_revision", "e" * 40, "checkout or suite"),
            (self.preflight["server_info"], "tag", "release-v0.0.0", "pinned suite"),
            (self.preflight["browser_tls"], "wrong_pin_rejected", False, "TLS evidence"),
            (self.api, "installation_after", {}, "installed package evidence"),
            (self.api, "plan_inventory", {}, "inventory differs"),
            (self.api["plan_inventory"]["basic"], "probe_cancelled", False, "plan inventory"),
            (self.api["plan_inventory"]["basic"], "probe_variant", {}, "plan inventory"),
            (
                self.api["plan_inventory"]["basic"], "modules",
                ["oidcc-client-test", "oidcc-client-test"], "plan inventory",
            ),
        ):
            with self.subTest(key=key):
                previous = report[key]
                report[key] = value
                try:
                    self.write_fixture()
                    with self.assertRaisesRegex(ValueError, explanation):
                        verifier.verify(self.args)
                finally:
                    report[key] = previous

    def test_downloaded_reports_cover_every_declared_selection_and_attempt(self):
        directory = self.downloaded_fixture()
        self.assertEqual(verifier.check_downloaded_reports(
            directory, self.args.revision, self.args.attempt
        ), 1)
        self.matrix["selections"] = [{"profile": "basic", "transport": "mirai"}]
        with self.assertRaisesRegex(ValueError, "missing basic/mirai, unexpected smoke/sync"):
            verifier.check_downloaded_reports(directory, self.args.revision, self.args.attempt)
        with self.assertRaisesRegex(ValueError, "Unexpected path"):
            verifier.check_downloaded_reports(
                directory, self.args.revision, self.args.attempt + 1
            )

    def test_downloaded_reports_require_both_companions_and_a_passing_client(self):
        directory = self.downloaded_fixture(omit="preflight")
        with self.assertRaisesRegex(ValueError, "Expected client, preflight and API reports"):
            verifier.check_downloaded_reports(directory, self.args.revision, self.args.attempt)

        self.report["gate_passed"] = False
        directory = self.downloaded_fixture()
        with self.assertRaisesRegex(ValueError, "Expected a passing client report"):
            verifier.check_downloaded_reports(directory, self.args.revision, self.args.attempt)

    def test_downloaded_reports_cli_exits_nonzero_for_altered_api_inventory(self):
        repository = self.args.archive.parent / "policy-repository"
        policy_dir = repository / "integration" / "openid"
        policy_dir.mkdir(parents=True)
        for name in ("suite-lock.json", "profiles.json", "release-matrix.json"):
            (policy_dir / name).write_text(
                json.dumps(verifier.read_policy(self.args.revision, name)), encoding="utf-8"
            )

        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repository, text=True).strip()

        git("init", "--quiet")
        git("add", "integration/openid")
        git("-c", "user.name=Report Test", "-c", "user.email=test@example.com",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "record test policy")
        revision = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        for report in (self.report, self.preflight, self.api):
            report["checkout_revision"] = revision
            report["checkout_source"].update(revision=revision, tree=tree)
        self.report["installation"].update(revision=revision, tree=tree)

        directory = self.downloaded_fixture()
        command = [
            sys.executable, "-B", str(Path(verifier.__file__).resolve()), "--revision", revision,
            "--attempt", str(self.args.attempt), "--downloaded-reports", str(directory),
        ]
        valid = subprocess.run(command, cwd=repository, capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn("for 1 declared OpenID selections", valid.stdout)

        self.api["plan_inventory"]["basic"]["probe_cancelled"] = False
        self.downloaded_fixture()
        invalid = subprocess.run(command, cwd=repository, capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("smoke/sync: Invalid API plan inventory for basic", invalid.stderr)

    def retention_fixture(self):
        self.args.retain = self.args.archive.parent / "retained"
        self.artifact["expired"] = False
        self.write_fixture()
        actions = f"repos/{self.args.repository}/actions"
        run = f"{actions}/runs/{self.args.run_id}"
        artifact = f"{actions}/artifacts/{self.artifact['id']}"
        return {
            f"{run}/attempts/{self.args.attempt}": self.args.run_metadata.read_bytes(),
            f"{run}/artifacts?name={self.artifact['name']}&per_page=2": json.dumps({
                "total_count": 1, "artifacts": [self.artifact],
            }).encode(),
            artifact: self.args.artifact_metadata.read_bytes(),
            f"{artifact}/zip": self.args.archive.read_bytes(),
        }

    def mock_github_api(self, responses):
        def api(endpoint, stdout=None):
            data = responses[endpoint]
            if stdout is not None:
                stdout.write(data)
                return None
            return data

        return patch.object(verifier, "github_api", side_effect=api)

    def test_retains_original_bytes_and_receipt_in_a_new_bundle(self):
        responses = self.retention_fixture()
        with self.mock_github_api(responses), self.mock_replay(self.summary):
            receipt = verifier.retain(self.args)

        for original in (self.args.run_metadata, self.args.artifact_metadata, self.args.archive):
            self.assertEqual(
                (self.args.retain / original.name).read_bytes(), original.read_bytes()
            )
        receipt_path = self.args.retain / "receipt.json"
        self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)
        with patch.object(verifier, "github_api") as api:
            with self.assertRaisesRegex(ValueError, "destination already exists"):
                verifier.retain(self.args)
            api.assert_not_called()
        self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)

    def test_retention_rejects_in_progress_run_before_artifact_lookup(self):
        self.run.update(status="in_progress", conclusion=None)
        responses = self.retention_fixture()
        run_endpoint = next(iter(responses))
        with self.mock_github_api({run_endpoint: responses[run_endpoint]}) as api:
            with self.assertRaisesRegex(ValueError, "successful OpenID matrix workflow attempt"):
                verifier.retain(self.args)
            api.assert_called_once_with(run_endpoint)
        self.assertFalse(self.args.retain.exists())

    def test_retention_cleans_up_after_archive_verification_fails(self):
        responses = self.retention_fixture()
        zip_endpoint = next(endpoint for endpoint in responses if endpoint.endswith("/zip"))
        responses[zip_endpoint] += b"unexpected bytes"
        with self.mock_github_api(responses):
            with self.assertRaisesRegex(ValueError, "SHA-256 digest"):
                verifier.retain(self.args)
        self.assertFalse(self.args.retain.exists())
        self.assertEqual(list(self.args.retain.parent.glob(".openid-matrix-*")), [])


if __name__ == "__main__":
    unittest.main()
