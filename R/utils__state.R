# State helpers: decrypt/validate payload and fetch/remove store --------------

#' Decrypt and validate OAuth state payload
#'
#' Internal utility that decrypts the encrypted `state` payload using the
#' client's `state_key`, then validates freshness and client binding.
#'
#' @param client [OAuthClient] instance
#' @param encrypted_payload Encrypted state payload string received via the
#'   `state` query parameter.
#'
#' @return A named list payload (state, client_id, redirect_uri, scopes,
#'   provider, issued_at) on success; otherwise throws an error via
#'   `err_invalid_state()`.
#' @keywords internal
state_payload_decrypt_validate <- function(client, encrypted_payload) {
  S7::check_is_S7(client, class = OAuthClient)

  # Centralized auditing for decrypt + validation to align sync/async flows
  tryCatch(
    {
      # Validate input early but within tryCatch so failures are audited
      if (!is_valid_string(encrypted_payload)) {
        err_invalid_state("Invalid or missing state payload")
      }
      pld <- state_decrypt_gcm(encrypted_payload, key = client@state_key)
      # Verify freshness and client/provider binding
      payload_verify_issued_at(client, pld)
      payload_verify_client_binding(client, pld)

      # Success audit (redacted identifiers only)
      try(
        audit_event(
          "callback_validation_success",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = string_digest(pld$state)
          )
        ),
        silent = TRUE
      )
      pld
    },
    error = function(e) {
      # Failure audit; include encrypted payload digest (state may be unknown)
      try(
        audit_event(
          "callback_validation_failed",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = string_digest(encrypted_payload),
            error_class = paste(class(e), collapse = ", "),
            phase = "payload_validation"
          )
        ),
        silent = TRUE
      )
      rlang::abort(
        message = c(
          "State payload decryption or validation failed",
          "i" = paste0("", conditionMessage(e))
        ),
        class = c("shinyOAuth_state_error", "shinyOAuth_error"),
        parent = e
      )
    }
  )
}

#' Fetch and remove the single-use state entry
#'
#' Retrieves the state-bound values from the client's `state_store` and removes
#' the entry to enforce single-use semantics.
#'
#' @param client [OAuthClient] instance
#' @param state Plain (decrypted) state string used as the logical key
#'
#' @return A list with `browser_token`, `pkce_code_verifier`, and `nonce`.
#'   Throws an error via `err_invalid_state()` if retrieval or removal fails,
#'   or if the retrieved value is missing/malformed.
#' @keywords internal
state_store_get_remove <- function(client, state) {
  S7::check_is_S7(client, class = OAuthClient)
  # Validate state early and emit audited error instead of raw assertion
  if (!is_valid_string(state)) {
    try(
      audit_event(
        "state_store_lookup_failed",
        context = list(
          provider = client@provider@name %||% NA_character_,
          issuer = client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(client@client_id),
          state_digest = string_digest(state %||% NA_character_),
          error_class = "shinyOAuth_state_error",
          phase = "state_store_lookup"
        )
      ),
      silent = TRUE
    )
    err_invalid_state("Invalid or missing state")
  }

  key <- state_cache_key(state)

  # Initialize state store value as NULL
  ssv <- NULL

  # Track progress
  get_succeeded <- FALSE
  remove_succeeded <- FALSE
  get_error_class <- NULL
  remove_error_class <- NULL

  tryCatch(
    {
      # Get from state store
      ssv <- client@state_store$get(key, missing = NULL)
      # Treat missing/non-list as lookup failure. Don't raise the final error
      # here to avoid double-emitting error events; audit and finalize below.
      if (is.null(ssv) || !is.list(ssv)) {
        rlang::abort(
          c(
            "State store entry is missing or malformed"
          ),
          class = c("shinyOAuth_state_error", "shinyOAuth_error")
        )
      }
      get_succeeded <- TRUE
    },
    error = function(e) {
      # Failure audit centralized here for consistent sync/async behavior
      get_error_class <<- paste(class(e), collapse = ", ")
      try(
        audit_event(
          "state_store_lookup_failed",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = string_digest(state),
            error_class = get_error_class,
            phase = "state_store_lookup"
          )
        ),
        silent = TRUE
      )
    }
  )

  tryCatch(
    {
      # Remove from state store; strict: failure to remove is an error to
      # enforce single-use semantics and prevent replay.
      rm_ret <- client@state_store$remove(key)
      # Many cachem backends return TRUE/FALSE; some may return invisible(NULL)
      # or even echo the key name on no-op removals. Treat only a logical TRUE
      # as an affirmative success. For NULL/unknown return types, fall back to
      # a post-check: the key must be absent right after removal. Any other
      # concrete, non-TRUE return (e.g., character key) is considered failure
      # to avoid accepting racy replays where the second remover "succeeds".
      if (isTRUE(rm_ret)) {
        remove_succeeded <- TRUE
      } else if (is.null(rm_ret)) {
        # Unknown return contract: verify absence with an immediate round-trip
        post <- client@state_store$get(key, missing = NA)
        remove_succeeded <- isTRUE(is.na(post))
      } else if (is.logical(rm_ret) && identical(rm_ret, FALSE)) {
        remove_succeeded <- FALSE
      } else {
        # Non-boolean/non-NULL return (e.g., key name) → treat as failure
        remove_succeeded <- FALSE
      }
    },
    error = function(e) {
      # Removal failure audit (best-effort)
      remove_error_class <<- paste(class(e), collapse = ", ")
      try(
        audit_event(
          "state_store_removal_failed",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = string_digest(state),
            error_class = remove_error_class,
            phase = "state_store_removal"
          )
        ),
        silent = TRUE
      )
    }
  )

  if (!(get_succeeded && remove_succeeded)) {
    # Compose structured context for the final state error
    ctx <- list(
      provider = client@provider@name %||% NA_character_,
      issuer = client@provider@issuer %||% NA_character_,
      client_id_digest = string_digest(client@client_id),
      state_digest = string_digest(state),
      get_succeeded = get_succeeded,
      remove_succeeded = remove_succeeded,
      get_error_class = get_error_class %||% NA_character_,
      remove_error_class = remove_error_class %||% NA_character_,
      phase = "state_store_access"
    )
    err_invalid_state("State access failed", context = ctx)
  }

  return(ssv)
}
