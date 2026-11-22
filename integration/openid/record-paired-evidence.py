"""Record the two verified matrix aggregates in the current workflow attempt."""

import json
import os
import re
import sys


ARTIFACTS = {
    "oidf": "openid-declared-matrix-evidence",
    "provider": "oidc-provider-release-evidence",
}


def positive_integer(environment, key):
    value = environment.get(key, "")
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError(f"Expected a positive {key}")
    return int(value)


def evidence_link(environment):
    repository = environment.get("GITHUB_REPOSITORY", "")
    revision = environment.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[a-zA-Z0-9-]+/(?!\.{1,2}$)[a-zA-Z0-9_.-]+", repository):
        raise ValueError("Expected the workflow repository")
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("Expected the selected full Git revision")
    run_id = positive_integer(environment, "GITHUB_RUN_ID")
    attempt = positive_integer(environment, "GITHUB_RUN_ATTEMPT")

    artifacts = {}
    for matrix, name in ARTIFACTS.items():
        prefix = matrix.upper()
        if environment.get(f"{prefix}_ATTEMPT") != str(attempt):
            raise ValueError(f"Expected the {matrix} aggregate from attempt {attempt}. Re-run all jobs.")
        artifact_id = positive_integer(environment, f"{prefix}_ID")
        digest = environment.get(f"{prefix}_DIGEST", "")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError(f"Expected a SHA-256 digest for the {matrix} aggregate ZIP")
        artifacts[matrix] = {
            "id": artifact_id,
            "name": f"{name}-attempt-{attempt}",
            "sha256": digest,
        }
    if artifacts["oidf"]["id"] == artifacts["provider"]["id"]:
        raise ValueError("Expected distinct OIDF and provider aggregate artifacts")
    return {
        "schema_version": 1,
        "repository": repository,
        "revision": revision,
        "run_id": run_id,
        "attempt": attempt,
        "artifacts": artifacts,
    }


if __name__ == "__main__":
    try:
        evidence = evidence_link(os.environ)
    except ValueError as error:
        sys.exit(str(error))
    print(json.dumps(evidence, indent=2))
