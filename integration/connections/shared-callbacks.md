# Several targets using one callback URL (P6)

P6 is an optional convenience for the connection manager. Two API resources or
app registrations can use the same authorization server and the same callback
URL. Each resulting connection still belongs to its original target and owner.
This works for generic OAuth/OIDC; it is not a new SMART protocol object.

| `callback_policy` | Client configuration | Routing |
| --- | --- | --- |
| `"distinct_routes"` (default) | With multiple targets, `multi_redirect_uri` and all registered redirect URIs | A distinct registered route per target. |
| `"issuer"` | Explicit `multi_issuer` for every client | Shared routes require distinct trusted issuers. |
| `"shared_routes"` | Explicit `multi_issuer` for every client | Issuer first; when several targets remain, the manager's pending-state index selects the original target. |

For the two opt-in policies, direct responses require an explicitly configured
issuer, advertised RFC 9207 response support and issuer enforcement. Signed JARM
can instead supply issuer identification. Knowing the issuer through OIDC alone
does not prove RFC 9207 support. Configure these settings on the clients before
creating their targets; the manager does not rewrite client policies.

```r
# a and b are approved oauth_target() configurations whose clients explicitly
# use multi_issuer and the same registered callback URL.
manager <- oauth_connections(
  targets = list(a = a, b = b),
  app_origin = "https://app.example",
  callback_policy = "shared_routes"
)
```

Add the usual retention, owner and store arguments to retain connections across
navigation. Existing UI/server calls stay the same. See the
[plain-language guide](../../playground/smart-fhir-explained.md) for the complete
manager design.

## What happens during login

1. The manager records the target, configuration fingerprint, transaction and
   expiry in an encrypted index. Its key is a SHA-256 digest of the exact outgoing
   OAuth state, obtained from structured preparation before provider work,
   including generic PAR/JAR. It never reads state back out of an authorization URL.
2. The callback handler bounds parsing and checks the registered route, response
   transport and issuer. If needed, it reads the index to select one approved
   client. This lookup cannot consume the pending login or logical OAuth state.
3. The existing bridge verifies the selected client's state and issuer/JARM.
   The module checks the owner, browser binding and transaction, then atomically
   consumes logical state before exchanging a code. Changing the selected site
   in another tab cannot change the target or resource for an earlier login.
4. Completion, validated provider errors, preparation failures, disconnect-all
   and logout remove routing entries. Expired entries fail lookup and are pruned
   when another login starts. The index shares the manager's 1,000-pending-login
   bound and one-process lifetime; it is not a distributed store.

The issuer checks retain the OAuth Security BCP's mix-up defense and RFC 9207's
exact comparison, including error responses.
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.4.2),
[RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html#section-2.4).

For signed JARM, the unverified state claim is only a bounded routing hint. The
selected client's signature, issuer, audience, expiry and state checks still
apply. Same-issuer encrypted JARM on the same route is rejected at setup: use
distinct routes. The router does not guess keys or try decrypting against several
registrations. [JARM processing rules](https://openid.net/specs/oauth-v2-jarm-final.html#name-processing-rules).

## Verification

Install the current checkout, then run from the repository root:

```sh
Rscript integration/connections/run-shared-router.R
```

The real-browser gate runs query/form POST with synchronous and actual mirai
transport. One loopback provider serves two registrations, one callback URL and
two resource paths on the same origin. Two tabs start pending logins before
either completes. Tests check target preservation, independent reads and refresh,
cross-resource rejection, owner isolation, logout across tabs and POST callbacks
without the owner cookie. CI runs it alongside the original retention gate.

Package tests additionally cover signed JARM success/errors, registration and
signature rejection, read-only failure handling, encrypted-response rejection,
expiry and configuration binding. Sanitized browser evidence is written to
`.artifacts/shared-<run>/evidence.json`; failures or skips fail the gate.

Verified on 2026-09-11 with R 4.5.1, Chrome 152.0.7977.83, Shiny 1.13.0 and
mirai 2.7.1: 218 targeted package assertions and 68 browser assertions passed
with no skips. The original retention browser gate also passed 104 assertions.
The manager/callback regression suite passed, and `R CMD check` with tests and
manual generation disabled reported zero errors, warnings or notes; tests were
run separately. Dependency build-version warnings in the unit run and Chromote
websocket EOF messages during browser shutdown are environment diagnostics.

This synthetic fixture does not establish independent SMART interoperability.
SMART optional transport composition remains gated separately in P4c2. Continue
the [sandbox](../smart/sandbox.md) and [Inferno](../smart/inferno.md) roadmap runs;
P6 does not close those external gates.
