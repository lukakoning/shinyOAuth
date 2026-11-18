**OIDF suite release review: 2026-11-18**

The previous server and proxy digests returned `not found` from the official
GitLab registry. Verified cached images supported the earlier local runs, while
fresh runners could not acquire them. This update selects available official
`release-v5.3.4` images explicitly by digest.

| Input | New identity |
| --- | --- |
| Suite source | `23353b36957d6466010de767c812d2c91ed37638` |
| Server index | `sha256:dcc4bd1fb7e9c00f048a67373fe2bec5ecf9feb45a6b5d55e237e5c30e5312c6` |
| Proxy index | `sha256:9a7850826fcc8690cd43373528f50e9551ba33bf8e4a40b67b13267b0aca3675` |
| Database | Existing MongoDB 6.0.13 digest in [suite-lock.json](suite-lock.json) |

Anonymous registry requests resolved the release tag to these indices; hashing
the returned manifest bytes reproduced each content digest. Both images were
then pulled explicitly by digest. Docker `RepoDigests` matched the requested
identities. The server jar's `git.properties` reports the exact source commit,
`git.dirty=false` and description `release-v5.3.4`. MongoDB's existing digest
remained available. These checks do not depend on the old cached images.

This is a move from the previously pinned development build
`410812ef6bc72a84723c1685725edce3558e31e3` to an earlier published release.
The upstream [source comparison](https://gitlab.com/openid/conformance-suite/-/compare/23353b36957d6466010de767c812d2c91ed37638...410812ef6bc72a84723c1685725edce3558e31e3)
contains 47 commits and 96 changed files, with no truncated or collapsed diffs
in the API response reviewed for this update. Relevant differences include:

- The release uses Spring Boot 4.0.7; the development build uses 4.0.9.
- The development build changes handling of unexpected HTTP/mTLS paths in the
  OIDC and FAPI simulated authorization servers. Selected normal endpoints and
  the client-validation conditions retain their identities. Browser runs must
  still demonstrate the expected application outcomes.
- The development build adds a non-alias token-endpoint holder-of-key test to
  server-testing plans. Those plans test authorization servers; this harness
  selects client-testing plans. No selected client module is removed here.
- Suite UI cache behavior, hosted-login setup and logout handling differ.
  The local stack uses the upstream dev profile with disposable data and no
  hosted account. JWKS cache policy and resource-certificate limitations retain
  their explicit checks and scope descriptions.

A disposable stack using the release server matched the complete module lists
and variants for all 17 declared client selections against the existing
manifest. This first comparison used the previously cached proxy. The subsequent
public preflight and API runs use both new locked images. The API runner now
checks all 15 declared plan configurations, including the public-client probe,
so future lock updates must resolve every module and variant difference.
One module per configuration verifies the live combined variant and issuer,
then is cancelled without attempting a client flow.
The selections, expected verdicts, application rejection checks and exception
allowlists are unchanged.

The [official prebuilt Compose file](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/docker-compose-prebuilt.yml)
uses the same registry and release-tag convention. Our Compose transport keeps
temporary certificates, loopback ports and local nginx configuration; upstream
test assertions remain unmodified. The [proxy Dockerfile](https://gitlab.com/openid/conformance-suite/-/blob/23353b36957d6466010de767c812d2c91ed37638/nginx/Dockerfile)
includes OpenSSL, as required by preflight.

Validation is in progress. Record local preflight/API/browser results and fresh
GitHub runner acquisition evidence before marking SA01 complete. Larger-job
timings and the remaining source-identity/release-matrix work retain their own
status. Earlier reports remain evidence for their recorded revisions.
