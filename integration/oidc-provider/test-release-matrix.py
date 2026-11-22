import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import warnings
import zipfile


SCRIPT = Path(__file__).with_name("release-matrix.py")
spec = spec_from_file_location("provider_release_matrix", SCRIPT)
matrix = module_from_spec(spec)
spec.loader.exec_module(matrix)


class ProviderReleaseMatrixTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self.archive = self.root / "artifact.zip"
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

    def archive_members(self):
        return [
            (f"release-inputs/{path.relative_to(self.reports).as_posix()}", path.read_bytes())
            for path in self.paths.values()
        ] + [("release-summary.json", matrix.summary_bytes(self.summarize()))]

    def write_archive(self, members):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in members:
                archive.writestr(name, data)

    def replay_archive(self):
        return matrix.replay_archive(self.archive, self.revision, self.run_id, self.attempt)

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

    def test_archive_cli_replays_original_summary(self):
        members = self.archive_members()
        self.write_archive(reversed(members))
        command = [
            sys.executable, str(SCRIPT), "evidence", "--archive", str(self.archive),
            "--revision", self.revision, "--run-id", str(self.run_id), "--attempt", str(self.attempt),
        ]
        verified = subprocess.run(command, capture_output=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(verified.stdout, members[-1][1])
        for option, path in (("--reports", self.reports), ("--verify-summary", self.archive)):
            with self.subTest(option=option):
                ambiguous = subprocess.run(command + [option, str(path)], capture_output=True)
                self.assertEqual(ambiguous.returncode, 2, ambiguous.stderr)

    def test_archive_rejects_changed_report_bytes_or_summary(self):
        members = self.archive_members()
        for index in (0, -1):
            with self.subTest(index=index):
                changed = list(members)
                name, data = changed[index]
                changed[index] = (name, data + b"\n")
                self.write_archive(changed)
                with self.assertRaisesRegex(ValueError, "Release summary differs"):
                    self.replay_archive()

    def test_archive_requires_each_member_and_rejects_old_attempts(self):
        members = self.archive_members()
        self.write_archive(members[1:])
        with self.assertRaisesRegex(ValueError, "Expected all 8 provider reports"):
            self.replay_archive()
        self.write_archive(members[:-1])
        with self.assertRaisesRegex(ValueError, "Missing release summary"):
            self.replay_archive()
        name, data = members[0]
        self.write_archive([(name.replace("attempt-2", "attempt-1"), data)] + members[1:])
        with self.assertRaisesRegex(ValueError, "Unexpected member"):
            self.replay_archive()

    def test_archive_rejects_duplicate_members_and_reports(self):
        members = self.archive_members()
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Duplicate name:", category=UserWarning)
            self.write_archive(members + [members[0]])
        with self.assertRaisesRegex(ValueError, "Duplicate member"):
            self.replay_archive()
        name, data = members[0]
        self.write_archive(members + [(name.replace("13e974208bea", "a" * 12), data)])
        with self.assertRaisesRegex(ValueError, "Expected one original report"):
            self.replay_archive()

    def test_archive_rejects_unexpected_payload_and_special_members(self):
        members = self.archive_members()
        for name in ("extra.json", "release-inputs/../extra.json", "release-inputs/"):
            with self.subTest(name=name):
                self.write_archive(members + [(name, b"{}")])
                with self.assertRaisesRegex(ValueError, "(?:Unexpected|Invalid) member"):
                    self.replay_archive()
        name, data = members[0]
        noncanonical = zipfile.ZipInfo(name)
        noncanonical.filename = name.replace("/", "\\")
        self.write_archive([(noncanonical, data)] + members[1:])
        with self.assertRaisesRegex(ValueError, "(?:Unexpected|Invalid) member"):
            self.replay_archive()
        shortcut = zipfile.ZipInfo("release-summary.json")
        shortcut.create_system = 3
        shortcut.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_archive(members[:-1] + [(shortcut, b"target.json")])
        with self.assertRaisesRegex(ValueError, "Invalid member"):
            self.replay_archive()

    def test_archive_rejects_encrypted_members_before_reading(self):
        self.write_archive(self.archive_members())
        data = bytearray(self.archive.read_bytes())
        last_directory_header = data.rindex(b"PK\x01\x02")
        # General-purpose ZIP flags start eight bytes into a central directory record.
        data[last_directory_header + 8] |= 1
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "Encrypted member"):
            self.replay_archive()


if __name__ == "__main__":
    unittest.main()
