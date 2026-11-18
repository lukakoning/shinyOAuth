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

Local API and client commands ran from clean harness source
`65fbdc8e49d70e85f99cbccc527428c91a785992`. Both client-flow reports record that
revision and clean flag. Preflight ran earlier during development with the new
image pins. Environment/API reports currently omit checkout-identity fields;
their execution context is documented here, without adding retrospective fields
to those reports. Source-identity enforcement remains SA02 work. Windows used
R 4.5.1; Linux used R 4.5.0 inside Docker Desktop.

| Check | Result | Local sanitized evidence directory |
| --- | --- | --- |
| Windows preflight | 26 environment assertions, source/revision checks, R/Chrome TLS, wrong-pin rejection and cleanup passed | `preflight-20261118-220843-c3f33ce78045` |
| Windows API | All 15 plan inventories and combined-variant probes passed, plus unknown-instance rejection and cancellation | `api-20261118-221249-7546c0e37383` |
| Windows/sync Configuration | All six cases passed; 61.21-second module loop | `config-20261118-221249-4d54304ba7df` |
| Linux/mirai Message Signing | All 29 modules passed; 265.24-second module loop | `fapi-message-signing-20261118-212334-16d39ccd0fc9` |

The evidence regression passed 6,808 assertions on both platforms, with zero
test warnings or skips. Windows R retained its existing startup locale warnings.
The complete API, Configuration and Message Signing commands took approximately
144, 236 and 413 seconds respectively. Loop timings exclude installation,
regression checks, startup and harness controls; local host resources were shared.
Serialized preflight, API-inventory and client-flow reports were independently
checked against the new lock, with altered metadata rejected. Configuration
retains `coverage_complete=false` because the suite's JWKS response forbids
storage. Message Signing reports completion for its exact selected plan/variant;
the requirement mapping and certification boundary remain separate.

The first Linux/mirai Message Signing attempt,
`fapi-message-signing-20261118-211749-1872924f5082`, passed four modules before
Chrome failed to open its debugging port within the existing 30-second limit.
That report remains failed and receives no coverage credit. Twenty standalone
Chrome startup/evaluation/cleanup cycles did not reproduce the failure. A fresh
full run then passed without changing checks or timeouts. Its failed-run
diagnostics remain private alongside the original report. An earlier scratch
metadata comparison also timed out before API readiness; the successful repeat
used the standard Windows OpenSSL backend setting. Neither diagnostic run
establishes client coverage.

Local acquisition checks retrieved both new images from the registry by digest;
the subsequent local preflight reused them through verified `RepoDigests`.
Fresh GitHub validation passed at
[smoke run 44399653873](https://github.com/lukakoning/shinyOAuth/actions/runs/44399653873),
for the same harness source above. Its preflight records all three images as
`pulled`; the API and browser commands then record verified cache reuse. All
15 API inventories, TLS controls, three browser cases and cleanup passed. The
browser report records a clean checkout and `coverage_complete=false` for smoke.
The downloaded ZIP matched GitHub artifact digest
`sha256:e233d62a72f57bc61566731b2ccf6e12636611a2d15c0518f868fdef28b3ae4b`.
The reports were independently revalidated against the lock and expected source.

| Hosted smoke phase | Seconds |
| --- | ---: |
| Queue before runner assignment | 550 |
| Complete job, excluding queue | 729 |
| Dependency setup | 422 |
| Preflight | 46 |
| API and evidence checks | 89 |
| Browser command, including regression checks and setup | 122 |
| Three-case browser loop inside that command | 19.85 |

The first-run dependency setup dominates this measurement. Hosted Basic/sync
[44403591230](https://github.com/lukakoning/shinyOAuth/actions/runs/44403591230)
and Message Signing/mirai
[44403727783](https://github.com/lukakoning/shinyOAuth/actions/runs/44403727783)
also passed at the same clean source on separate fresh runners. Their preflights
each record all three images as `pulled`; subsequent commands record verified
cache reuse. Both API reports cover all 15 plan configurations. Basic completed
fourteen cases: thirteen suite `PASSED` verdicts and the documented `SKIPPED`
unsigned-token outcome after the client rejected `alg=none`. All 29 Message
Signing modules returned suite `PASSED`. Both selections record cleanup and
completion for their exact plan/variant. Their downloaded artifacts matched
GitHub's published hashes and the serialized reports passed independent checks.

| Larger hosted selection | Job seconds | Dependencies | Preflight | API | Browser command | Module loop |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Basic / sync | 412 | 50 | 45 | 85 | 180 | 81.44 |
| Message Signing / mirai | 581 | 49 | 44 | 90 | 345 | 245.08 |

Each larger job queued for four seconds before assignment. Table values are
seconds; job time excludes queueing, and module loops sit inside the browser
command. These are individual observations on GitHub-hosted `ubuntu-latest`
runners with R 4.5.1. Reports and job timing
metadata are retained locally under `integration/openid/.artifacts/hosted-RUN_ID/`.

| Larger-job artifact | Verified SHA-256 |
| --- | --- |
| Basic | `764c997c33ca274d65839d47c5e358125a61b943a3afedb719631e61b8b6581b` |
| Message Signing | `a2c4701ade844bbf33b6e6557a2e1b44959b5ce7ade0de4d975d47f2d6f25782` |

SA01 is complete for image reproducibility, fresh preflight/API/browser smoke
and the selected larger-job timings. Keep the existing PR smoke and manual
larger selections while the final tiering is reviewed in C16. SA02's source
identity and SA08's complete release matrix and durable evidence retention
remain pending. Earlier reports remain evidence for their recorded revisions.
Only sanitized evidence JSON is eligible for workflow upload; private
keys, registrations, libraries and raw diagnostics remain ignored locally.
