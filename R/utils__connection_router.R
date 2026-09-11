# A private process-local index, populated from structured authorization
# preparation. It selects an approved client only; the callback bridge and
# module retain all issuer/JARM, state, browser, owner and consumption checks.
connection_router_key <- function(manager) {
  as.raw(openssl::sha256(charToRaw(paste0(
    "shinyOAuth/connection-router/v1/", manager$app_origin, "/", manager$state$id
  )), key = manager$keys$credentials))
}

connection_router_digest <- function(state) {
  if (!is_valid_string(state) || nchar(state, type = "bytes") > oauth_callback_limits()$state) {
    err_invalid_state("Invalid callback routing state")
  }
  unclass(as.character(openssl::sha256(charToRaw(state))))
}

connection_router_register <- function(manager, client_name, context, prepared) {
  connection_manager_check(manager)
  client <- manager$clients[[client_name]]
  pending <- manager$state$pending[[context$transaction]]
  context_digest <- authorization_context_digest(authorization_context_json(context))
  if (is.null(pending) || !is.null(pending$route_digest) ||
      !identical(context_digest,
        authorization_context_digest(authorization_context_json(pending$context))) ||
      !identical(context$client, client_name) || context$expires_at <= as.numeric(Sys.time())) {
    err_invalid_state("Authorization routing transaction is unavailable")
  }
  state <- prepared$build_args$payload
  digest <- connection_router_digest(state)
  payload <- state_payload_decrypt_validate(client, state, audit_success = FALSE)
  record <- state_store_get(client, payload$state)
  state_record_verify_authorization_context(record, payload$transaction_context_digest)
  if (!identical(payload$transaction_context_digest, context_digest) ||
      !identical(prepared$state_key, state_cache_key(payload$state)) ||
      !is.null(manager$state$routes[[digest]]) || length(manager$state$routes) >= 1000L) {
    err_invalid_state("Authorization routing state is unavailable")
  }
  route <- list(
    purpose = "connection-router-v1",
    manager = manager$state$id,
    digest = digest,
    transaction = context$transaction,
    client = client_name,
    fingerprint = connection_client_fingerprint(client),
    context_digest = context_digest,
    expires_at = min(context$expires_at, payload$issued_at + client@state_payload_max_age)
  )
  sealed <- state_encrypt_gcm(route, connection_router_key(manager))
  pending$route_digest <- digest
  manager_state <- manager$state
  manager_state$routes[[digest]] <- sealed
  manager_state$pending[[context$transaction]] <- pending
  invisible(NULL)
}

# Called only after bounded HTTP parsing, registered-route, transport and exact
# issuer filtering. A signed JWT's unverified state is a hint, never a proof.
# Five-part encrypted responses are deliberately not decrypted here.
connection_router_select <- function(manager, candidates, payload) {
  connection_manager_check(manager)
  state <- if (identical(payload$type, "response")) {
    parse_jwt_payload(payload$response)[["state"]]
  } else payload$state
  digest <- connection_router_digest(state)
  sealed <- manager$state$routes[[digest]]
  if (is.null(sealed)) err_invalid_state("Callback routing transaction is unavailable")
  route <- state_decrypt_gcm(sealed, connection_router_key(manager))
  pending <- manager$state$pending[[route$transaction]]
  client <- manager$clients[[route$client]]
  if (!identical(route$purpose, "connection-router-v1") ||
      !identical(route$manager, manager$state$id) || !identical(route$digest, digest) ||
      !is.numeric(route$expires_at) || length(route$expires_at) != 1L ||
      !is.finite(route$expires_at) || route$expires_at <= as.numeric(Sys.time()) ||
      is.null(pending) || is.null(client) ||
      !identical(pending$route_digest, digest) ||
      !identical(pending$context$client, route$client) ||
      !identical(route$context_digest,
        authorization_context_digest(authorization_context_json(pending$context))) ||
      !identical(route$fingerprint, connection_client_fingerprint(client))) {
    err_invalid_state("Callback routing transaction is unavailable")
  }
  id <- shiny::NS(manager$state$id)(route$client)
  if (!id %in% names(candidates)) err_invalid_state("Callback client does not match its route")
  # Read-only: neither this lookup nor an invalid response can consume a login.
  candidates[id]
}

connection_router_cancel <- function(manager, transaction) {
  pending <- manager$state$pending[[transaction]]
  if (!is.null(pending$route_digest) &&
      exists(pending$route_digest, manager$state$routes, inherits = FALSE)) {
    rm(list = pending$route_digest, envir = manager$state$routes)
  }
  if (!is.null(pending)) rm(list = transaction, envir = manager$state$pending)
  invisible(NULL)
}
