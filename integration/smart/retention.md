# Retained connection implementation checkpoints

P3 is being delivered in independently reviewable steps. The retained manager
is not yet available; `oauth_connection()` remains Shiny-session scoped.

| Step | Deliverable | Status |
| --- | --- | --- |
| P3a | Versioned encrypted credential schema and atomic memory connection store | Implemented; focused credential and lifecycle tests. |
| P3b | Owner sessions, generation/expiry checks, browser cookie and account resolver contracts | Planned. |
| P3c | Manager UI/server, guarded callback commit, restoration, coordinated refresh and disconnect | Planned. |
| P3d | Two-site real-browser retention, owner isolation and lifecycle integration evidence | Required before marking P3 complete. |

The memory store is constructed outside `server()` with
`oauth_connection_store_memory()`. Its low-level methods accept only sealed
credential envelopes; callers must already have verified the owner. The factory
does not establish a browser session or enable retention on existing modules.
Only the future manager will connect those operations to browser authentication.

The credential codec uses the package's AES-GCM envelope with a separate
HMAC-derived purpose key from a deployment-controlled 32-byte root. The root is
not held in the store. The authenticated payload binds the owner generation's
opaque ID, connection ID, target configuration fingerprint and schema version.
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

Protocol references reviewed for P3:

- [OAuth refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14): rotating credentials require coordinated lifecycle handling.
- [Token revocation](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2): local disconnect and remote revocation are separate outcomes.
- [Cookie attributes and host prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): P3b will establish the owner cookie at the HTTP boundary.

The acceptance test remains actual browser navigation: connect A, navigate away
to authorize B, return in a new Shiny session with both connections, refresh each
independently, then disconnect B while A remains usable. Storage unit tests do not
satisfy that gate. See the [sandbox](sandbox.md) and [Inferno](inferno.md) plans for
the later SMART-specific repeats in P4/P5.
