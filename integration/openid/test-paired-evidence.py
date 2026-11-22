from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).with_name("record-paired-evidence.py")
spec = spec_from_file_location("record_paired_evidence", SCRIPT)
recorder = module_from_spec(spec)
spec.loader.exec_module(recorder)


class PairedEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "GITHUB_REPOSITORY": "owner/repository",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "700",
            "GITHUB_RUN_ATTEMPT": "2",
            "OIDF_ID": "123",
            "OIDF_DIGEST": "b" * 64,
            "OIDF_ATTEMPT": "2",
            "PROVIDER_ID": "456",
            "PROVIDER_DIGEST": "c" * 64,
            "PROVIDER_ATTEMPT": "2",
        }

    def test_cli_records_both_original_aggregate_identities(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], env=os.environ | self.environment, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "schema_version": 1,
            "repository": "owner/repository",
            "revision": "a" * 40,
            "run_id": 700,
            "attempt": 2,
            "artifacts": {
                "oidf": {
                    "id": 123, "name": "openid-declared-matrix-evidence-attempt-2", "sha256": "b" * 64,
                },
                "provider": {
                    "id": 456, "name": "oidc-provider-release-evidence-attempt-2", "sha256": "c" * 64,
                },
            },
        })

    def test_requires_current_attempt_for_both_aggregates(self):
        for matrix in ("OIDF", "PROVIDER"):
            with self.subTest(matrix=matrix), self.assertRaisesRegex(ValueError, "Re-run all jobs"):
                recorder.evidence_link(self.environment | {f"{matrix}_ATTEMPT": "1"})

    def test_rejects_missing_or_invalid_artifact_output(self):
        for field, value in (
            ("OIDF_ID", ""),
            ("PROVIDER_ID", "0"),
            ("OIDF_DIGEST", "short"),
            ("PROVIDER_DIGEST", "sha256:" + "c" * 64),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                recorder.evidence_link(self.environment | {field: value})

    def test_rejects_reusing_one_artifact_for_both_aggregates(self):
        with self.assertRaisesRegex(ValueError, "distinct"):
            recorder.evidence_link(self.environment | {"PROVIDER_ID": self.environment["OIDF_ID"]})

    def test_rejects_invalid_workflow_identity(self):
        for field, value in (
            ("GITHUB_REPOSITORY", "repository"),
            ("GITHUB_SHA", "a" * 12),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ATTEMPT", "0"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                recorder.evidence_link(self.environment | {field: value})

    def test_cli_emits_no_link_when_one_aggregate_is_unavailable(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=os.environ | self.environment | {"PROVIDER_ATTEMPT": ""},
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Re-run all jobs", result.stderr)


if __name__ == "__main__":
    unittest.main()
