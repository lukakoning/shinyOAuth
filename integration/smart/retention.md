# Retained connection implementation checkpoints

P3 is delivered in independently reviewable steps. The optional manager and the
generic browser-retention gate are implemented for a single R process.
`oauth_connection()` continues to follow a single module's session-scoped token.

| Step | Deliverable | Status |
| --- | --- | --- |
| P3a | Versioned encrypted credential schema and atomic memory connection store | Implemented; focused credential and lifecycle tests. |
| P3b | Owner sessions, generation/expiry checks, browser cookie and account resolver contracts | Implemented; focused browser/account lifecycle tests. |
| P3c | Manager UI/server, guarded callback commit, restoration, coordinated refresh and disconnect | Implemented in P3c1 (module hooks) and P3c2 (manager API), with HTTP/Shiny lifecycle regression tests. |
| P3d | Two-site real-browser retention, owner isolation and lifecycle integration evidence | Implemented: 104 Chrome assertions across query/form_post and sync/mirai, no skips. HTTP loopback development deployment; SMART repeats follow in P4/P5. |

The memory store is constructed outside `server()` with
`oauth_connection_store_memory()`. Its low-level methods accept only sealed
credential envelopes; callers must already have verified the owner. The factory
does not establish a browser session or enable retention on existing modules.
`oauth_connections()` connects these operations to verified local ownership.

The credential codec uses the package's AES-GCM envelope with a separate
HMAC-derived purpose key from a deployment-controlled 32-byte root. The root is
not held in the store. The authenticated payload binds the opaque owner ID,
connection ID, target configuration fingerprint and schema version. The owner ID
is stable across session rotation; current session/generation checks remain a
separate prerequisite for reading or changing its records.
It stores an explicit token-property allowlist and the original authentication
time. It preserves original/latest ID tokens, scope evidence and initial/latest
extension snapshots. Restoring a prior `id_token_validated` value records prior
validation; it cannot create a fresh login or reset authentication age.

Data uses a bounded tagged JSON schema, preserving missing values, empty vectors,
nulls and numeric precision without R deserialization. It excludes clients,
functions, environments, caches and private keys. Sender-constraint keys and
certificates remain deployment configuration; restoration recomputes the target
fingerprint, including its material policy and key/certificate references.

The store enforces owner-scoped access and compare-and-swap revisions. Refresh
claims expire into `uncertain`, with old credentials removed. Only an explicit
`not_consumed` failure releases a claim for retry. Disconnect installs a
tombstone before returning the previous encrypted record for bounded revocation
work. Transaction reservations prevent duplicate acceptance; a monotonic revision
sequence prevents stale operations from affecting a reused identifier. Record
expiry and reservations bound memory use; capacity errors never evict a live grant.

The adapter's atomicity applies only within one R process. A copied worker store
is rejected. It survives Shiny sessions, not R restarts. External backends remain
future work and must demonstrate equivalent atomicity, monotonic revisions and
owner semantics. Encryption alone cannot protect against a backend replaying old
valid ciphertext.

`oauth_browser_owner()` and `oauth_account_owner()` now describe local ownership
policy. They do not authenticate a user or enable retention by themselves. The
internal browser registry issues random 43-character cookies, stores only a
keyed digest for lookup, and checks a live server record on every resolution.
Rotation preserves the owner ID and original absolute expiry while replacing
the cookie and session generation immediately. Old cookies and generation
snapshots stop resolving; logout removes the live session. Idle expiry is
server-enforced, and a full registry refuses new sessions without evicting live
ones. Registry copies in other R processes are rejected.

The cookie helpers construct `Secure; HttpOnly; SameSite=Lax` host-only cookies
with `Path=/` and a `__Host-` name on HTTPS. `Strict` is an explicit alternative.
Only an explicitly enabled HTTP loopback development exception omits Secure and
the host prefix. The cookie name and lookup key include the configured origin
and manager namespace. Cookies themselves are host scoped, not port scoped;
different ports or application paths must not be treated as isolation from
untrusted applications on the same host.

Account ownership calls the application's trusted local-login resolver again on
resolution and validation. The account ID is a deployment-keyed digest of the
local subject, origin and namespace; the session generation additionally binds
the local session ID, generation and original authentication time. An external
OAuth/FHIR identity does not establish that local login. Local expiry may shorten
an enrolled owner's lifetime but cannot extend it. Logout, idle expiry and
absolute expiry retire the generation. Retirement metadata is kept until the
local authentication freshness limit, so repeatedly returning the same login
cannot re-enroll it. A fresh authenticated session can use the same account ID.
Account expiry and capacity are explicit; these registries also remain local to
one R process and do not survive a restart.

`oauth_connections_ui()` establishes the browser cookie on an ordinary HTTP page
request before Shiny starts. Both HTTP and Shiny setup check the configured
application origin. Raw callbacks never create replacement owners. A cross-site
POST without the owner cookie first uses the existing clean callback continuation;
that continuation requires the still-valid owner. Invalid cookies on ordinary
pages are cleared by an HTTP response and a same-origin redirect.

The first P3c commit adds internal module hooks for transaction preparation,
owner validation, credential acceptance, cancellation and cleanup. Managed code
and error callbacks verify the existing browser proof and the authenticated
transaction context before consuming logical state. Async dispatch carries only
the original context JSON, and accepted results recheck the owner before commit.
Accepted managed tokens never enter the legacy module's token slot. The module's
public arguments and ordinary lifecycle remain unchanged. The hook regression
run passes 809 assertions, including 57 managed-hook assertions, with no skips;
two warnings reflect locally installed Shiny/future packages built under newer
R patch versions. This does not establish real-browser retention.

The P3c2 API comprises `oauth_connections()`, `oauth_connections_ui()` and
`oauth_connections_server()`. Create one manager outside `server()` and share its
namespace and origin across the wrappers. Multiple targets require distinct
registered callbacks and clients configured with `multi_redirect_uri` plus the
complete callback list. Browser/account retention requires explicit owner policy,
memory store and deployment-held credential/owner keys. The default `shiny` mode
discards old grants when the Shiny session ends; pending authorization still uses
the existing browser/state proofs to complete in a new session.

Each successful authorization creates a new connection ID, including repeated
authorizations at one target. The server returns `connect()`, `connections()`,
`connection()`, `disconnect()`, `disconnect_all()`, `logout()` and `errors()`.
References remain bound to their Shiny session and resolve current owner-scoped
credentials for every request. Summaries exclude token and patient/context data.
The manager owns refresh, including shared automatic retry cooldowns, exclusive
claims, original authentication/retention times and uncertain-outcome handling.
Polling and automatic refresh do not extend local-owner idle limits.

Local disconnect installs all applicable tombstones before remote cleanup. Logout
invalidates the owner generation first. Remote revocation has a ten-second batch
HTTP budget, with two seconds and one attempt per credential; failure never
restores local usability. Account logout also requires a fresh trusted local
login before reenrollment. A failed late refresh is discarded and cannot replace
a disconnected grant.

The manager's focused tests cover HTTP cookie setup/clearing, Origin rejection,
restoration across mock Shiny sessions, browser/account isolation, login generation
changes, owner idle expiry, repeated grants, refresh rotation/failure outcomes,
late completion versus disconnect/expiry, and the public reference API. These
tests exercise synthetic credentials; they are not external conformance evidence.

P3c2 validation on 2026-09-10: the affected callback, connection and lifecycle
regression run passed 1,320 assertions with no failures. One worker-version skip
was resolved by installing this checkout into an isolated library; rerunning the
async module file passed all 42 assertions without skips. The only test warnings
were the local Shiny/future R patch-version build notices. R CMD check (without
tests, manual or vignette rebuilding; focused tests run separately) reported zero
errors, warnings and notes. Roxygen help rendered and Jarl checks passed.

Protocol references reviewed for P3:

- [OAuth refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14): rotating credentials require coordinated lifecycle handling.
- [Token revocation](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2): local disconnect and remote revocation are separate outcomes.
- [Cookie attributes and host prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): the manager connects the owner cookie contract to HTTP responses.
- [Cookie port isolation limits](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.5): an origin-specific cookie name does not isolate applications on different ports of the same host.
- [Shiny session request](https://shiny.posit.co/r/reference/shiny/latest/session.html): the manager validates cookies and origin from the server request, never client-supplied Shiny inputs.

The [P3d browser suite](../connections/README.md) exercises actual navigation:
connect A, navigate away to authorize B, return in a new Shiny session with both
connections, refresh each independently, then disconnect B while A remains usable.
It also checks browser isolation, HttpOnly ownership, cross-site POST callbacks
without the owner cookie, and logout through a new empty owner. Four scenarios
cover query/form_post and synchronous/mirai transport. The run on 2026-09-10 passed
104 assertions with no skips (Chrome 152.0.7977.83, R 4.5.1, Shiny 1.13.0, mirai
2.7.1). Sanitized run evidence is saved by the runner and uploaded by its CI job.

This gate found and fixed two integration defects: nested manager modules now use
their full namespace when resolving HTTP continuations, and callback documents
declare the public application base before Shiny dependencies. Callback URLs
remain on their registered routes. `app_base_path` configures a mounted directory;
the browser fixture exercises the default root deployment. Rewritten documents
discard stale length/cache validators while retaining unrelated response headers.

The affected callback/connection/lifecycle regression run passed 1,339 assertions
without skips. R CMD check reported zero errors, warnings and notes. The final
HTML-header adjustment was additionally covered by the focused manager suite
(136 assertions, no failures or skips).
The fixtures use explicit HTTP loopback and invented credentials. They do not
establish TLS deployment, embedding or independent protocol conformance. See the
[sandbox](sandbox.md) and [Inferno](inferno.md) plans for SMART-specific repeats in
P4/P5, including real FHIR scope/context and standalone/EHR launch behavior.
