# Retained connection implementation checkpoints

P3 is being delivered in independently reviewable steps. The retained manager
is not yet available; `oauth_connection()` remains Shiny-session scoped.

| Step | Deliverable | Status |
| --- | --- | --- |
| P3a | Versioned encrypted credential schema and atomic memory connection store | Implemented; focused credential and lifecycle tests. |
| P3b | Owner sessions, generation/expiry checks, browser cookie and account resolver contracts | Implemented; focused browser/account lifecycle tests. HTTP and callback integration follows in P3c. |
| P3c | Manager UI/server, guarded callback commit, restoration, coordinated refresh and disconnect | Planned. |
| P3d | Two-site real-browser retention, owner isolation and lifecycle integration evidence | Required before marking P3 complete. |

The memory store is constructed outside `server()` with
`oauth_connection_store_memory()`. Its low-level methods accept only sealed
credential envelopes; callers must already have verified the owner. The factory
does not establish a browser session or enable retention on existing modules.
Only the future manager will connect those operations to browser authentication.

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

P3c must wire these helpers to the HTTP and Shiny boundaries. In particular, it
must establish the browser cookie before Shiny starts, validate the request
origin, and bind pending authorization to the owner generation. Recheck that
generation before code exchange and before committing credentials. A cross-site
POST without the owner cookie must first use the existing clean callback
continuation. The helper tests do not yet demonstrate those HTTP, callback or
late-completion properties.

Protocol references reviewed for P3:

- [OAuth refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14): rotating credentials require coordinated lifecycle handling.
- [Token revocation](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2): local disconnect and remote revocation are separate outcomes.
- [Cookie attributes and host prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): P3b's header and parsing helpers implement the cookie contract; P3c will connect them to HTTP responses.
- [Cookie port isolation limits](https://www.rfc-editor.org/rfc/rfc6265.html#section-8.5): an origin-specific cookie name does not isolate applications on different ports of the same host.
- [Shiny session request](https://shiny.posit.co/r/reference/shiny/latest/session.html): P3c will validate cookies and origin from the server request, never client-supplied Shiny inputs.

The acceptance test remains actual browser navigation: connect A, navigate away
to authorize B, return in a new Shiny session with both connections, refresh each
independently, then disconnect B while A remains usable. Storage unit tests do not
satisfy that gate. See the [sandbox](sandbox.md) and [Inferno](inferno.md) plans for
the later SMART-specific repeats in P4/P5.
