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
        self.report = {"profile": "smoke", "transport": "sync"}
        self.member = (
            "release-inputs/openid-client-smoke-sync-evidence-attempt-2/"
            "smoke-20261121-130000-123456abcdef/evidence.json"
        )

    def write_fixture(self, extra=None):
        with ZipFile(self.args.archive, "w") as archive:
            archive.writestr(verifier.SUMMARY, json.dumps(self.summary))
            archive.writestr(self.member, json.dumps(self.report))
            for kind in ("api", "preflight"):
                archive.writestr(
                    self.member.replace("/smoke-20261121", f"/{kind}-20261121"),
                    "{}",
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


if __name__ == "__main__":
    unittest.main()
