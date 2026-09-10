#' Create a process-local store for retained OAuth connections
#'
#' Stores encrypted credential envelopes and coordinates their lifecycle across
#' Shiny sessions in one R process. Create one store outside `server()`. This
#' adapter does not survive process restarts and rejects use from a copied worker
#' process. It is a connection-manager building block, not an authentication API.
#'
#' @param max_age Maximum record and transaction-deduplication lifetime in seconds.
#'   Each record must also supply an earlier or equal absolute expiry.
#' @param refresh_timeout Maximum time in seconds for a claimed refresh. An
#'   abandoned operation becomes uncertain; its old credentials cannot be retried.
#' @param max_entries Maximum live record and transaction-reservation count,
#'   including tombstones and recently expired transactions.
#'   A full store rejects creation instead of evicting another connection.
#' @return An `OAuthConnectionStore` adapter with the methods described below.
#' @details
#' Methods are trusted server-side operations. The manager must validate the
#' current owner session and generation before calling them. The opaque owner
#' identifier scopes records and can survive session rotation; knowledge of an
#' owner or connection ID does not authenticate a user.
#' Records contain ciphertext only. Encryption keys stay with the manager, outside
#' this adapter. Never expose these methods or credential imports as HTTP routes.
#'
#' * `$create(owner, id, transaction, target, fingerprint, sealed, expires_at)`
#'   returns a record with a new revision, or `NULL` for a duplicate connection/transaction.
#' * `$read(owner, id)` returns the owner's record, or `NULL` when absent, expired,
#'   or owned by someone else. It includes the sealed envelope for internal use.
#' * `$list(owner)` returns metadata lists without ciphertext or operation IDs.
#' * `$begin_refresh(owner, id, revision)` claims an active record and returns its
#'   new revision and operation ID. A conflicting claim returns `NULL`.
#' * `$commit_refresh(owner, id, operation, revision, sealed)` installs credentials
#'   only for the current claim, returning the updated record or `NULL`.
#' * `$fail_refresh(owner, id, operation, revision, outcome)` releases a claim only
#'   for `"not_consumed"`; `"possibly_consumed"` and `"consumed"` remove the old
#'   envelope and mark the record `"uncertain"`. Returns the record or `NULL`.
#' * `$disconnect(owner, id, revision)` first installs a credential-free tombstone,
#'   then returns `list(record, previous)` for bounded remote cleanup. Conflicts
#'   return `NULL`; the caller must reload before retrying.
#' * `$disconnect_owner(owner)` tombstones all of that owner's records and returns
#'   the previous records for bounded cleanup. Other owners are unaffected.
#'
#' Reads expire abandoned refresh claims before returning data. Tombstones and
#' transaction IDs remain at least until the original absolute expiry so late completions
#' cannot restore a disconnected grant. Operations are synchronous and do not yield
#' or perform network calls. Atomicity applies to this R process only. A separate
#' shared backend needs its own verified concurrency contract.
#'
#' @seealso [oauth_target()], [oauth_connection()]
#' @export
oauth_connection_store_memory <- function(
  max_age = 28800,
  refresh_timeout = 60,
  max_entries = 1000L
) {
  connection_store_memory_impl(max_age, refresh_timeout, max_entries)
}

connection_store_memory_impl <- function(
  max_age,
  refresh_timeout,
  max_entries,
  clock = function() as.numeric(Sys.time())
) {
  for (value in list(max_age, refresh_timeout, max_entries)) {
    if (
      !is.numeric(value) ||
        length(value) != 1L ||
        !is.finite(value) ||
        value <= 0
    ) {
      err_config("Connection store limits must be positive finite numbers")
    }
  }
  if (max_entries != floor(max_entries)) {
    err_config("max_entries must be a whole number")
  }
  records <- new.env(parent = emptyenv())
  transactions <- new.env(parent = emptyenv())
  process <- Sys.getpid()
  sequence <- 0
  next_revision <- function() {
    if (sequence >= 2^53 - 2) {
      err_token("Connection store revision limit reached")
    }
    sequence <<- sequence + 1
    sequence
  }
  guard <- function() {
    if (!identical(Sys.getpid(), process)) {
      err_config(
        "The memory connection store cannot be used in another R process"
      )
    }
    clock()
  }
  id_check <- function(value) {
    if (!is_valid_string(value) || !grepl("^[A-Za-z0-9_-]{16,128}$", value)) {
      err_input("Invalid opaque connection-store identifier")
    }
  }
  revision_check <- function(value) {
    if (
      !is.numeric(value) ||
        length(value) != 1L ||
        !is.finite(value) ||
        value < 1 ||
        value != floor(value) ||
        value >= 2^53 - 1
    ) {
      err_input("Invalid connection revision")
    }
  }
  sealed_check <- function(value) {
    if (
      !is_valid_string(value) ||
        nchar(value, type = "bytes") > 3 * 1024^2 ||
        !grepl("^[A-Za-z0-9_-]+$", value)
    ) {
      err_input("Invalid sealed connection envelope")
    }
  }
  save <- function(record) {
    records[[record$id]] <- record
    record
  }
  remove_expired <- function(now) {
    for (id in ls(records, all.names = TRUE)) {
      if (records[[id]]$expires_at <= now) {
        rm(list = id, envir = records)
      }
    }
    for (id in ls(transactions, all.names = TRUE)) {
      if (transactions[[id]] <= now) {
        rm(list = id, envir = transactions)
      }
    }
  }
  read <- function(owner, id) {
    now <- guard()
    id_check(owner)
    id_check(id)
    record <- records[[id]]
    if (is.null(record) || !identical(record$owner, owner)) {
      return(NULL)
    }
    if (record$expires_at <= now) {
      rm(list = id, envir = records)
      return(NULL)
    }
    if (
      identical(record$status, "refreshing") &&
        record$operation_expires_at <= now
    ) {
      record$status <- "uncertain"
      record$sealed <- NULL
      record$operation <- NULL
      record$operation_expires_at <- NULL
      record$revision <- next_revision()
      save(record)
    }
    record
  }
  matches <- function(record, revision, status = NULL, operation = NULL) {
    !is.null(record) &&
      identical(record$revision, as.numeric(revision)) &&
      (is.null(status) || identical(record$status, status)) &&
      (is.null(operation) || identical(record$operation, operation))
  }
  finish <- function(record, status, sealed) {
    record$status <- status
    record$sealed <- sealed
    record$operation <- NULL
    record$operation_expires_at <- NULL
    record$revision <- next_revision()
    save(record)
  }
  create <- function(
    owner,
    id,
    transaction,
    target,
    fingerprint,
    sealed,
    expires_at
  ) {
    now <- guard()
    lapply(list(owner, id, transaction), id_check)
    sealed_check(sealed)
    if (
      !is_valid_string(target) ||
        !grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", target) ||
        !is_valid_string(fingerprint) ||
        nchar(fingerprint, type = "bytes") > 256L
    ) {
      err_input("Invalid connection target configuration")
    }
    if (
      !is.numeric(expires_at) ||
        length(expires_at) != 1L ||
        !is.finite(expires_at) ||
        expires_at <= now ||
        expires_at > now + max_age
    ) {
      err_input("Connection expiry must be within the store lifetime")
    }
    remove_expired(now)
    transaction_key <- paste(owner, transaction, sep = ":")
    if (!is.null(records[[id]]) || !is.null(transactions[[transaction_key]])) {
      return(NULL)
    }
    if (length(records) >= max_entries || length(transactions) >= max_entries) {
      err_token("Connection store capacity reached")
    }
    record <- list(
      version = 1L,
      owner = owner,
      id = id,
      target = target,
      fingerprint = fingerprint,
      sealed = sealed,
      created_at = now,
      expires_at = expires_at,
      revision = next_revision(),
      status = "active"
    )
    # Deduplication lasts the full store window, even for a short-lived record.
    transactions[[transaction_key]] <- now + max_age
    save(record)
  }
  begin_refresh <- function(owner, id, revision) {
    revision_check(revision)
    record <- read(owner, id)
    if (!matches(record, revision, "active")) {
      return(NULL)
    }
    record$status <- "refreshing"
    record$operation <- random_urlsafe(32L)
    record$operation_expires_at <- min(
      guard() + refresh_timeout,
      record$expires_at
    )
    record$revision <- next_revision()
    save(record)
  }
  commit_refresh <- function(owner, id, operation, revision, sealed) {
    revision_check(revision)
    id_check(operation)
    sealed_check(sealed)
    record <- read(owner, id)
    if (!matches(record, revision, "refreshing", operation)) {
      return(NULL)
    }
    finish(record, "active", sealed)
  }
  fail_refresh <- function(owner, id, operation, revision, outcome) {
    revision_check(revision)
    id_check(operation)
    if (
      !is_valid_string(outcome) ||
        !outcome %in% c("not_consumed", "possibly_consumed", "consumed")
    ) {
      err_input("Invalid refresh credential outcome")
    }
    record <- read(owner, id)
    if (!matches(record, revision, "refreshing", operation)) {
      return(NULL)
    }
    retryable <- identical(outcome, "not_consumed")
    finish(
      record,
      if (retryable) "active" else "uncertain",
      if (retryable) record$sealed else NULL
    )
  }
  disconnect <- function(owner, id, revision) {
    revision_check(revision)
    record <- read(owner, id)
    if (!matches(record, revision)) {
      return(NULL)
    }
    if (identical(record$status, "disconnected")) {
      return(list(record = record, previous = NULL))
    }
    list(record = finish(record, "disconnected", NULL), previous = record)
  }
  list_records <- function(owner) {
    guard()
    id_check(owner)
    result <- lapply(ls(records, all.names = TRUE), function(id) {
      record <- read(owner, id)
      if (is.null(record)) {
        return(NULL)
      }
      record[c(
        "id",
        "target",
        "fingerprint",
        "created_at",
        "expires_at",
        "revision",
        "status"
      )]
    })
    Filter(Negate(is.null), result)
  }
  disconnect_owner <- function(owner) {
    rows <- list_records(owner)
    lapply(rows, function(record) {
      disconnect(owner, record$id, record$revision)$previous
    })
  }
  structure(
    list(
      scope = "process",
      version = 1L,
      max_age = max_age,
      create = create,
      read = read,
      list = list_records,
      begin_refresh = begin_refresh,
      commit_refresh = commit_refresh,
      fail_refresh = fail_refresh,
      disconnect = disconnect,
      disconnect_owner = disconnect_owner
    ),
    class = "OAuthConnectionStore"
  )
}

#' @rdname oauth_connection_store_memory
#' @param x An `OAuthConnectionStore` adapter to print.
#' @param ... Unused print arguments.
#' @export
print.OAuthConnectionStore <- function(x, ...) {
  cat("<OAuthConnectionStore: single process; credential envelopes redacted>\n")
  invisible(x)
}
