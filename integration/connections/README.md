# Retained-connection browser gates (P3d, P6 and P7a)

From the repository root, install the current checkout and run:

```sh
R CMD INSTALL .
Rscript integration/connections/run-tests.R
Rscript integration/connections/run-shared-router.R
Rscript integration/connections/run-scope-narrowing.R
```

Requires Chrome/Chromium, the package's dependencies, and `testthat`, `webfakes`,
`chromote`, `callr`, `withr`, `promises`, `future` and `mirai`. An isolated R library
can be selected using `R_LIBS`. The app and mirai workers must load the same
installed checkout. Missing prerequisites, failures and skips fail this gate.

The original runner creates two loopback OAuth providers, a Shiny process and isolated
Chrome browser contexts, then cleans up the processes it owns. It uses invented
credentials only. No Docker service or external account is required.

The [P6 shared-callback gate](shared-callbacks.md) uses one authorization server,
two registrations and two resource paths on the same origin. It checks pending
logins in separate tabs through the same callback URL, resource isolation and
the same query/form POST and sync/mirai matrix.

The [P7a refresh-scope gate](refresh-scopes.md) narrows one connection from read
and write to read, then verifies the limit survives a new Shiny session and
later refresh. Another connection retains its original permissions. It runs
the same four transport combinations and checks actual resource access.

The matrix covers `query` and `form_post`, each with synchronous transport and
actual mirai workers. It verifies:

- Connect A, leave for B's approval page, and return to a new Shiny session with
  both grants. The provider pages use `localhost`; the app uses `127.0.0.1`, so
  navigation crosses sites as well as origins.
- Read each provider's API using the correct grant; rotate each refresh token;
  keep each connection ID and use the replacement access token for subsequent reads.
- Reject access to a connection ID from a separate browser context.
- Keep the owner cookie HttpOnly. Cross-site `form_post` callbacks arrive without
  it; the clean GET continuation restores the existing owner.
- Disconnect B while A stays usable, and send both of B's credentials for
  revocation. Logout returns to a new empty owner and old IDs stop resolving.

`fixture-app.R` uses public manager APIs and exposes only summaries, synthetic
resource revisions, session counters and cookie-presence booleans. The provider
checks registered redirects, PKCE and single-use codes/refresh credentials. It is
a test fixture, not an independently implemented conformance suite.

Only sanitized versions, transport choices, status and assertion counts are
written to `.artifacts/<run>/evidence.json`. There are no raw callback, credential,
cookie or patient records in that artifact. CI uploads this file only.

This gate uses the explicit HTTP loopback development exception. Secure cookie
attributes are checked by package tests; this run does not prove TLS deployment,
untrusted reverse-proxy handling, embedding, account-provider authentication or
shared-worker storage. The store and owner registries remain in one R process;
mirai workers perform transport and return results for guarded commits there.

Managed callback pages retain their registered paths. `oauth_connections_ui()`
places an HTML base before dependencies so scripts resolve at the application
root. For a Shiny app mounted under a public directory, configure `app_base_path`
and place every registered callback inside that directory. Do not add a separate
HTML base element. This follows the [HTML base element's ordering requirement](https://html.spec.whatwg.org/multipage/semantics.html#the-base-element).

P4/P5 must repeat the applicable workflow against the [SMART Sandbox](../smart/sandbox.md)
and [Inferno client suite](../smart/inferno.md), adding discovery, registration,
FHIR scope/context and standalone/EHR launch assertions. A P3d pass does not
establish SMART interoperability. See the [retention checkpoints](../smart/retention.md).

Implementation references: [webfakes handler and server lifecycle](https://webfakes.r-lib.org/reference/new_app.html),
[Shiny session request](https://shiny.posit.co/r/reference/shiny/latest/session.html),
[OAuth refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14).
