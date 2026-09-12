# Additional SMART application scenarios

Run these commands from the repository root after installing the checkout. Each
gate fails on missing dependencies, failed assertions or skipped scenarios and
writes sanitized evidence under `.artifacts/`. Synthetic resources are used
throughout. These gates supplement the independently maintained Inferno client
verifier; they do not establish vendor certification.

## 1. Cross-site HTTPS callbacks

`Rscript integration/smart/run-profiles.R --cross-site`

Eight public-client scenarios cover standalone/EHR launch, query/form-post
callbacks and synchronous/mirai token transport. Both sides use HTTPS: the app
is at `127.0.0.1`, and providers are at `localhost`. These are distinct browser
sites, without changing the machine's DNS or hosts file. The browser checks the
provider origin, Secure cookies and the HttpOnly/Lax owner cookie, then completes
the existing two-grant retention, narrowing, refresh, disconnect and logout flow.
Only the isolated browser/readiness probe ignores the fixture certificate's
trust errors; R provider requests validate the existing test CA. The provider
is our synthetic SMART implementation, which supports incoming form-post
callbacks; the pinned Inferno simulator supports query callbacks only.

This gate currently runs Chrome. Firefox/WebKit coverage remains future work.
Validation on 2026-09-13: eight scenarios, 240 passing assertions, no skips.
