# A connection ID is not a credential identity. Keep only keyed digests and
# record locators here; token bytes remain in the authenticated store envelopes.
# This index shares the manager's process and retention boundary, across owners
# and controllers. A reused credential never implies interchangeable identities,
# scopes or context, so rotation invalidates aliases instead of copying a token
# response from one authorization to another.
connection_credential_keys <- function(manager, client, token) {
  key <- function(value, type) {
    if (!is_valid_string(value)) return(NULL)
    raw_to_hex_lower(openssl::sha256(serialize(list(
      type, client@provider@issuer, client@provider@token_url,
      if (identical(type, "refresh")) client@client_id else NULL, value
    ), NULL, version = 2), key = manager$keys$credentials))
  }
  list(refresh = key(token@refresh_token, "refresh"),
    access = key(token@access_token, "access"))
}

connection_credential_prune <- function(manager) {
  entries <- manager$state$credential_records
  now <- as.numeric(Sys.time())
  for (id in ls(entries, all.names = TRUE)) {
    if (entries[[id]]$expires_at <= now) rm(list = id, envir = entries)
  }
  flights <- manager$state$credential_flights
  for (key in ls(flights, all.names = TRUE)) {
    flight <- flights[[key]]
    if (flight$expires_at <= now) {
      connection_credential_retire(manager, list(refresh = key))
      rm(list = key, envir = flights)
    }
  }
  invisible(NULL)
}

connection_credential_unusable <- function(manager, keys) {
  length(connection_credential_retired(manager, keys)) > 0L
}

connection_credential_retired <- function(manager, keys) {
  entries <- manager$state$credential_records
  keys[vapply(names(keys), function(type) {
    any(vapply(as.list(entries), function(entry) {
      connection_credential_matches(entry$retired, keys[type])
    }, logical(1)))
  }, logical(1))]
}

connection_credential_matches <- function(a, b) {
  any(vapply(intersect(names(a), names(b)), function(type) {
    !is.null(a[[type]]) && identical(a[[type]], b[[type]])
  }, logical(1)))
}

connection_credential_track <- function(manager, record, token) {
  entries <- manager$state$credential_records
  entries[[record$id]] <- list(
    owner = record$owner, id = record$id, expires_at = record$expires_at,
    keys = connection_credential_keys(manager, manager$clients[[record$client]], token),
    retired = list())
  invisible(NULL)
}

connection_credential_retire <- function(manager, keys, except = NULL) {
  entries <- manager$state$credential_records
  for (id in ls(entries, all.names = TRUE)) {
    entry <- entries[[id]]
    if (identical(id, except) || !connection_credential_matches(entry$keys, keys)) next
    # Publish invalidation before touching the store. Even a backend failure
    # cannot leave a known superseded copy usable through a later read.
    for (type in names(keys)) {
      if (connection_credential_matches(entry$keys[type], keys[type])) {
        entry$retired[type] <- keys[type]
      }
    }
    entries[[id]] <- entry
    try({
      record <- manager$store$read(entry$owner, id)
      if (!is.null(record) && identical(record$status, "active")) {
        record <- manager$store$begin_refresh(entry$owner, id, record$revision)
      }
      if (!is.null(record) && identical(record$status, "refreshing")) {
        manager$store$fail_refresh(entry$owner, id, record$operation,
          record$revision, "possibly_consumed")
      }
    }, silent = TRUE)
    connection_manager_signal(manager, entry$owner)
  }
  invisible(NULL)
}
