# HTTPS cross-site Form Post selection

Run the declared `form-post-cross-site` selection from the repository root:

```sh
Rscript integration/openid/run-tests.R --profile form-post-cross-site --transport sync
Rscript integration/openid/run-tests.R --profile form-post-cross-site --transport mirai
```

This selects two modules from the pinned suite's 30-module Comprehensive
variant: `oidcc-client-test` and `oidcc-client-test-form-post-error`. The
variant uses static registration, `client_secret_basic`, code flow and
`response_mode = form_post`. Both require suite `PASSED`; the selection does
not complete the Comprehensive plan or establish certification.

The provider uses HTTPS `localhost`; the app uses HTTPS `127.0.0.1` on a
separate loopback port. The certificate covers both names. Each case checks
the app's CA-verified readiness and rejects a wrong Chrome SPKI pin. The
fixture requires an existing Secure, SameSite=Strict browser binding
cookie, an actual cross-site POST with the provider Origin and
`Sec-Fetch-Site: cross-site`, and absence of that Strict cookie on the POST.
The returned continuation restores the same browser binding before callback
processing. These are observed browser facts, not a claim based on different
port numbers alone.

The success case requires validated identity, exactly one token request and
one UserInfo request. Mirai must perform that protocol work in a verified
worker. The `login_required` case is a valid provider denial: its matching
state is consumed exactly once, no token or UserInfo request occurs, no
identity is installed and the user sees a safe denial. Its existing
`audit_error_state_consumed` event occurs in the main process. Mirai must
initialize verified probes but dispatch no protocol worker for the denial.

This denial is distinct from malformed HTTP callback rejection: it passes
callback validation and consumes its own state. The
[opaque rejection continuation](assessment.md#rejected-callback-cleanup)
preserves pending state when rejecting an invalid callback before a session.
Neither outcome substitutes for the other.

The Basic Form Post plan does not contain `oidcc-client-test-form-post-error`.
The new Comprehensive variant makes that module applicable; its request uses
`prompt = none` and `max_age = 0`. The existing authentication-method variants
use the default response mode, so their capability probes cannot establish
this error path.

The selection retains `https_cross_site_loopback_form_post_only`. It tests a
pinned Chrome/SPKI deployment with loopback hosts, not a public certificate
chain or every browser, proxy, cookie policy and production domain. The
existing same-site Form Post Basic and cross-site attack fixtures retain
their separate coverage. Sanitized reports contain comparisons and counters;
raw forms, cookies, state and private diagnostics remain ignored.
