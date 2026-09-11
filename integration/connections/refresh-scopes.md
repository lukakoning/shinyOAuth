# Requesting fewer permissions on refresh (P7a)

A managed connection can request a replacement access token with fewer
permissions. This is ordinary OAuth functionality; SMART connections apply
their existing semantic scope rules to the same operation.

```r
# Inside the Shiny session, using the result of oauth_connections_server():
connection <- connections$connection(connection_id)
connection$refresh(scopes = "read")
```

Use scope names from your approved client. For example, `read` can replace
`c("read", "write")` for a generic OAuth client. A SMART client might reduce
`patient/Observation.rs` to `patient/Observation.r` if the client's required
permissions allow it. The server must support the requested scopes. With async
transport, the method returns a promise and narrowing takes effect after its
successful commit.

## Scope and lifecycle rules

- Supply a non-empty character vector. The manager bounds its size, validates
  its syntax and requires coverage by both the current grant and client
  configuration. Generic scopes use literal comparison; SMART clients use the
  existing semantic evaluator. An indeterminate comparison is rejected.
- Keep the client's required scopes. Widening or dropping required permissions
  fails before taking the store's refresh claim or sending credentials.
- After success, the encrypted connection record remembers that narrowing was
  selected. Later `$refresh()` calls, automatic refreshes and restored sessions
  explicitly request the current accepted scopes. If the server grants an even
  smaller acceptable set, that becomes the next limit. Other connections and
  the client's shared configuration retain their settings.
- Connections that have never selected narrowing still omit request `scope`.
  The existing standalone `refresh_token()` interface keeps its behavior.
  `extra_token_params$scope` remains reserved; use the managed method.
- A provider response that exceeds the requested limit or drops required scopes
  is rejected before UserInfo or credential installation. SMART still requires
  explicit returned scope. For ordinary OAuth, an omitted response scope means
  the requested scopes; the token retains its unverified-scope evidence flag.
- Provider rejection is returned to the caller; there is no retry without scope.
  Existing rotation and uncertain-outcome rules apply. If the refresh credential
  may have been consumed, reconnect instead of reusing it. Late results still
  cannot restore disconnected or invalid-owner connections.

This is a **local limit on this connection**, not remote revocation. OAuth keeps
the refresh token's original grant even when a particular refresh requests a
narrower access token. Without sending the limit again, a future refresh could
restore the original permissions. The manager therefore remembers to send it;
regaining broader permissions through the manager requires a new authorization.
[RFC 6749 refresh request and rotation rules](https://www.rfc-editor.org/rfc/rfc6749.html#section-6).

The response fallback follows [RFC 6749 section 5.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1).
SMART comparison and explicit grant evidence follow
[SMART STU 2.2 scopes](https://hl7.org/fhir/smart-app-launch/STU2.2/scopes-and-launch-context.html).
The method does not add patient-chart synchronization or change launch context
rules; existing context continuity checks still run during refresh.

## Verification

Install the current checkout and the [browser prerequisites](README.md), then:

```sh
Rscript integration/connections/run-scope-narrowing.R
```

The real-browser gate uses two loopback OAuth fixtures and runs query/form POST
callbacks with synchronous and actual mirai transport. Its provider deliberately
keeps the refresh credential's original read/write grant, so omitting scope
after narrowing would restore write access and fail the test. The test checks
read/write resource behavior, rotation, retained connection IDs, session changes,
required-scope and widening rejection, isolation from the second connection and
logout. The shared connection-retention CI job runs this gate.

Package tests in `test-refresh-scope-narrowing.R` also cover omitted responses,
SMART semantic comparison, introspection scope checks, provider errors, rotated
credential rejection, disconnect racing with a narrowed response and async
request coalescing. Only requests with matching scope policies can share a
refresh operation.

Verified on 2026-09-11 with R 4.5.1, Chrome 152.0.7977.83, Shiny 1.13.0 and
mirai 2.7.1: 85 focused package assertions and 64 browser assertions passed with
no skips. The broader scope/refresh/connection regression run passed 1,785
assertions (overlapping the focused tests). The original retention and P6 browser
gates passed 104 and 68 assertions. `R CMD check --no-tests --no-manual
--ignore-vignettes` reported zero errors, warnings or notes; tests ran separately.
Unit runs reported only dependency build-version warnings. Browser teardown
reported benign Chromote websocket EOF diagnostics.

Sanitized browser versions and assertion counts go to
`.artifacts/scopes-<run>/evidence.json`. Missing prerequisites, failures or skips
fail the runner. These fixtures exercise library behavior; independent provider
and SMART compatibility remain separate [sandbox](../smart/sandbox.md) and
[Inferno](../smart/inferno.md) gates. P7b-P7e remain separate roadmap items.
