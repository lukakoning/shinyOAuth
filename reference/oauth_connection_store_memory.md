# Create a process-local store for retained OAuth connections

Stores encrypted credential envelopes and coordinates their lifecycle
across Shiny sessions in one R process. Create one store outside
`server()`. This adapter does not survive process restarts and rejects
use from a copied worker process. It is a connection-manager building
block, not an authentication API.

## Usage

``` r
oauth_connection_store_memory(
  max_age = 28800,
  refresh_timeout = 60,
  max_entries = 1000L
)

# S3 method for class 'OAuthConnectionStore'
print(x, ...)
```

## Arguments

- max_age:

  Maximum record and transaction-deduplication lifetime in seconds. Each
  record must also supply an earlier or equal absolute expiry.

- refresh_timeout:

  Maximum time in seconds for a claimed refresh. An abandoned operation
  becomes uncertain; its old credentials cannot be retried.

- max_entries:

  Maximum live record and transaction-reservation count, including
  tombstones and recently expired transactions. A full store rejects
  creation instead of evicting another connection.

- x:

  An `OAuthConnectionStore` adapter to print.

- ...:

  Unused print arguments.

## Value

An `OAuthConnectionStore` adapter with the methods described below.

## Details

Methods are trusted server-side operations. The manager must validate
the current owner session and generation before calling them. The opaque
owner identifier scopes records and can survive session rotation;
knowledge of an owner or connection ID does not authenticate a user.
Records contain ciphertext only. Encryption keys stay with the manager,
outside this adapter. Never expose these methods or credential imports
as HTTP routes.

- `[["create"]](owner, id, transaction, client, fingerprint, sealed, expires_at)`
  returns a record with a new revision, or `NULL` for a duplicate
  connection/transaction.

- `[["read"]](owner, id)` returns the owner's record, or `NULL` when
  absent, expired, or owned by someone else. It includes the sealed
  envelope for internal use.

- `[["list"]](owner)` returns metadata lists without ciphertext or
  operation IDs.

- `[["begin_refresh"]](owner, id, revision)` claims an active record and
  returns its new revision and operation ID. A conflicting claim returns
  `NULL`.

- `[["commit_refresh"]](owner, id, operation, revision, sealed)`
  installs credentials only for the current claim, returning the updated
  record or `NULL`.

- `[["fail_refresh"]](owner, id, operation, revision, outcome)` releases
  a claim only for `"not_consumed"`; `"possibly_consumed"` and
  `"consumed"` remove the old envelope and mark the record
  `"uncertain"`. Returns the record or `NULL`.

- `[["disconnect"]](owner, id, revision)` first installs a
  credential-free tombstone, then returns `list(record, previous)` for
  bounded remote cleanup. Conflicts return `NULL`; the caller must
  reload before retrying.

- `[["disconnect_owner"]](owner)` tombstones all of that owner's records
  and returns the previous records for bounded cleanup. Other owners are
  unaffected.

Reads expire abandoned refresh claims before returning data. Tombstones
and transaction IDs remain at least until the original absolute expiry
so late completions cannot restore a disconnected grant. Operations are
synchronous and do not yield or perform network calls. Atomicity applies
to this R process only. A separate shared backend needs its own verified
concurrency contract.

## See also

[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md),
[`oauth_connection()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connection.md)

## Examples

``` r
# Create once, outside server(), then supply to oauth_connections().
store <- oauth_connection_store_memory(max_age = 8 * 3600, max_entries = 100)
```
