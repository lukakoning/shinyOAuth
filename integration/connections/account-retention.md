# Account retention browser gate

Install the current checkout, then run `Rscript integration/connections/run-account.R`
from the repository root. Requires the browser-test dependencies used by the
other connection gates, `processx`, and Python 3 (`py` on Windows, `python3` on
Linux/macOS). The Shiny parent and mirai workers must load the same installation.

The fixture supplies an independent local password-login boundary for two
invented accounts. Its own server-side login registry issues Secure, HttpOnly,
SameSite=Lax cookies and invalidates an old session on logout or replacement.
The account-owner resolver validates that registry on every call. OAuth tokens
and provider responses cannot select a local account. This fixture is test
infrastructure, not a production account-login implementation.

Each query/form POST and sync/mirai combination checks:

- Invalid local credentials cannot start an authenticated application session.
- A committed grant survives OAuth navigation and a fresh login to its account.
- Switching accounts exposes only the newly authenticated account's grants.
- An old Shiny tab loses access after local logout, including after the same
  account logs in again with a new session generation.
- A pending authorization cannot be committed after either account switching or
  same-account relogin. Provider exchange counters confirm rejection happens
  before code exchange.
- Refresh uses the restored account's grant. Manager logout disconnects that
  account's grants without removing another account's authorization.

The app is reached through a loopback-only TLS proxy using existing test PEM
fixtures. Only this isolated test browser and local readiness probe ignore the
test certificate's trust errors. The public origin remains HTTPS and the account
policy is unchanged; no package authentication check is mocked or relaxed.
The local login page uses `Referrer-Policy: same-origin`; logout uses an explicit
same-origin fetch policy so both POSTs carry the Origin required by the local
login checks. Application documents and OAuth callbacks retain the package's
`no-referrer` policy and clean continuation.
The proxy forwards to a fixed loopback port; the OAuth UI wrapper accepts only its
configured Host authority. This proves the fixture's login/session integration and HTTPS
cookie behavior, not general deployment certificate or reverse-proxy security.

Every scenario must pass without skips. CI runs the gate and uploads only
`.artifacts/account-<run>/evidence.json`: versions, transport descriptions,
scenario choices and counts, without cookies, tokens, passwords or account IDs.
