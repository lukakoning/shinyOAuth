# Only the connection manager supplies these server-side hooks. They are never
# taken from HTTP requests, Shiny inputs or the authorization server's response.
oauth_module_validate_managed_hooks <- function(hooks) {
  if (is.null(hooks)) {
    return(invisible(NULL))
  }
  required <- c("prepare", "validate", "accept", "cancel", "discard")
  if (
    !is.list(hooks) ||
      !all(vapply(
        required,
        function(name) {
          is.function(hooks[[name]])
        },
        logical(1)
      ))
  ) {
    err_config("Invalid internal connection-manager hooks")
  }
  for (name in c("parameters", "prepared")) {
    if (!is.null(hooks[[name]]) && !is.function(hooks[[name]])) {
      err_config("Invalid internal connection-manager hooks")
    }
  }
  invisible(NULL)
}

# Run before consuming logical state or dispatching a token exchange, including
# provider-error callbacks. Keep the original authenticated JSON for the core's
# exact state-record comparison; only bounded data goes to async workers.
oauth_module_managed_context <- function(
  hooks,
  client,
  state,
  browser_token,
  payload = NULL,
  record = NULL
) {
  if (is.null(hooks)) {
    return(NULL)
  }
  payload <- if (is.null(payload)) {
    state_payload_decrypt_validate(client, state, audit_success = FALSE)
  } else {
    state_payload_revalidate(client, payload, audit_success = FALSE)
  }
  record <- record %||% state_store_get(client, payload$state)
  validate_browser_token(browser_token)
  if (!constant_time_compare(record$browser_token, browser_token)) {
    err_invalid_state("Browser token mismatch")
  }
  state_record_verify_authorization_context(
    record,
    payload$transaction_context_digest
  )
  json <- record$transaction_context
  if (!is_valid_string(json)) {
    err_invalid_state("Managed callback requires its authorization context")
  }
  context <- jsonlite::fromJSON(json, simplifyVector = FALSE)
  authorization_context_json(context)
  if (!isTRUE(hooks$validate(context))) {
    err_invalid_state("Managed authorization owner is unavailable")
  }
  list(json = json, data = context)
}
