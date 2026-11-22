import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SCRIPT = Path(__file__).with_name("release-matrix.py")
spec = spec_from_file_location("provider_release_matrix", SCRIPT)
matrix = module_from_spec(spec)
spec.loader.exec_module(matrix)


class ProviderReleaseMatrixTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.revision = "a" * 40
        self.run_id = 402
        self.attempt = 2
        self.paths = {}
        source = {"revision": self.revision, "tree": "b" * 40, "dirty": False}
        installation = {
            "revision": self.revision, "tree": source["tree"], "method": "git_archive",
            "archive_sha256": "c" * 64, "package_version": "0.8.0",
        }
        for selection in matrix.selections():
            profile, transport = selection["profile"], selection["transport"]
            artifact = f"oidc-provider-{profile}-{transport}-evidence-attempt-{self.attempt}"
            path = self.reports / artifact / f"{profile}-20261122-141658-13e974208bea" / "evidence.json"
            path.parent.mkdir(parents=True)
            report = {
                "schema_version": 2, "scope": matrix.PROFILES[profile], "transport": transport,
                "status": "passed", "gate_passed": True, "cleanup_verified": True,
                "source_verified": True, "checkout_dirty": False, "checkout_revision": self.revision,
                "checkout_source": source, "checkout_source_after": source,
                "installation": installation, "installation_after": installation,
                "package_version": installation["package_version"],
                "results": [{"id": "fixture-case"}], "rejection_controls": {"fixture-control": True},
            }
            path.write_text(json.dumps(report), encoding="utf-8")
            self.paths[(profile, transport)] = path
        self.basic = self.paths[("basic", "sync")]

    def summarize(self):
        return matrix.summarize(self.reports, self.revision, self.run_id, self.attempt)

    def test_matrix_declares_and_summarizes_each_report(self):
        summary = self.summarize()
        self.assertEqual(summary["revision"], self.revision)
        self.assertEqual(summary["run_id"], self.run_id)
        self.assertEqual(summary["attempt"], self.attempt)
        self.assertEqual(summary["installation_archive_sha256"], "c" * 64)
        entries = summary["selections"]
        self.assertEqual(len(entries), 8)
        self.assertEqual({(entry["profile"], entry["transport"]) for entry in entries}, set(self.paths))
        for entry in entries:
            original = self.paths[(entry["profile"], entry["transport"])]
            self.assertEqual(entry["path"], original.relative_to(self.reports).as_posix())
            self.assertEqual(entry["report_sha256"], hashlib.sha256(original.read_bytes()).hexdigest())

    def test_rejects_missing_or_reused_attempt_artifact(self):
        artifact = self.basic.parent.parent
        outside = artifact.rename(self.root / artifact.name)
        with self.assertRaisesRegex(ValueError, "Expected all 8 provider reports from attempt 2"):
            self.summarize()
        outside.rename(self.reports / artifact.name.replace("attempt-2", "attempt-1"))
        with self.assertRaisesRegex(ValueError, "unexpected .*attempt-1"):
            self.summarize()

    def test_rejects_empty_or_flattened_download(self):
        self.reports = self.root / "download"
        with self.assertRaisesRegex(ValueError, "Re-run all jobs"):
            self.summarize()
        flattened = self.reports / self.basic.parent.name
        flattened.mkdir(parents=True)
        (flattened / "evidence.json").write_bytes(self.basic.read_bytes())
        with self.assertRaisesRegex(ValueError, "Re-run all jobs"):
            self.summarize()

    def test_rejects_an_extra_payload_or_artifact(self):
        extra = self.basic.parent / ".diagnostic.json"
        extra.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exactly one evidence.json"):
            self.summarize()
        extra.unlink()
        (self.reports / "unexpected-artifact").mkdir()
        with self.assertRaisesRegex(ValueError, "unexpected-artifact"):
            self.summarize()

    def test_rejects_failed_or_cross_assigned_evidence(self):
        original = json.loads(self.basic.read_bytes())
        for key, value in (
            ("checkout_revision", "d" * 40),
            ("scope", matrix.PROFILES["advanced"]),
            ("transport", "mirai"),
            ("status", "failed"),
            ("gate_passed", False),
            ("source_verified", False),
        ):
            with self.subTest(key=key):
                self.basic.write_text(json.dumps(original | {key: value}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Expected a verified basic/sync report"):
                    self.summarize()

    def test_rejects_different_installation_identity(self):
        report = json.loads(self.basic.read_bytes())
        report["installation"]["archive_sha256"] = "d" * 64
        report["installation_after"] = report["installation"]
        self.basic.write_text(json.dumps(report), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "installation identity differs"):
            self.summarize()

    def test_rejects_duplicate_json_keys(self):
        original = self.basic.read_bytes()
        self.basic.write_bytes(original.replace(b"{", b'{"status":"passed",', 1))
        with self.assertRaisesRegex(ValueError, "Duplicate JSON object key"):
            self.summarize()

    def test_cli_writes_and_replays_exact_report_set(self):
        summary = self.root / "release-summary.json"
        command = [
            sys.executable, str(SCRIPT), "evidence", "--reports", str(self.reports),
            "--revision", self.revision, "--run-id", str(self.run_id), "--attempt", str(self.attempt),
        ]
        written = subprocess.run(command + ["--write-summary", str(summary)], capture_output=True)
        self.assertEqual(written.returncode, 0, written.stderr)
        original = summary.read_bytes()
        reused = subprocess.run(command + ["--write-summary", str(summary)], capture_output=True)
        self.assertNotEqual(reused.returncode, 0)
        self.assertEqual(summary.read_bytes(), original)
        replay = command + ["--verify-summary", str(summary)]
        verified = subprocess.run(replay, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        # Whitespace changes preserve parsed values but must change the original report digest.
        self.basic.write_bytes(self.basic.read_bytes() + b"\n")
        rejected = subprocess.run(replay, capture_output=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(b"Release summary differs", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
