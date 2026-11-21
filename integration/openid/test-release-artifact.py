import hashlib
import importlib.util
import json
from pathlib import Path
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
        self.enterContext(patch.object(
            verifier, "read_policy", side_effect=lambda revision, name: {
                "suite-lock.json": self.lock,
                "profiles.json": {
                    "plans": self.plans,
                    "source_revision": self.lock["source_revision"],
                },
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
        digest = hashlib.sha256(self.args.archive.read_bytes()).hexdigest()
        self.artifact["digest"] = f"sha256:{digest}"
        self.args.run_metadata.write_text(json.dumps(self.run), encoding="utf-8")
        self.args.artifact_metadata.write_text(json.dumps(self.artifact), encoding="utf-8")

    def mock_replay(self, replay):
        def run(command, **options):
            self.assertEqual(command[:4], [
                "Rscript", "integration/openid/run-release-check.R",
                "--revision", self.args.revision,
            ])
            self.assertEqual(command[4], "--output")
            self.assertEqual(len(command), 7)
            self.assertEqual(Path(command[6]).read_bytes(), json.dumps(self.report).encode())
            Path(command[5]).write_text(json.dumps(replay), encoding="utf-8")
            return SimpleNamespace(returncode=0)

        return patch.object(verifier.subprocess, "run", side_effect=run)

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


if __name__ == "__main__":
    unittest.main()
