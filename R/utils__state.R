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
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#' @keywords internal
state_payload_decrypt_validate <- function(
  client,
  encrypted_payload,
  shiny_session = NULL
) {
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
          ),
          shiny_session = shiny_session
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
          ),
          shiny_session = shiny_session
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
#' When the store exposes an atomic `$take(key, missing)` method (see
#' [custom_cache()]), it is used preferentially to guarantee single-use even
#' under concurrent access in shared/distributed backends.
#' When `$take()` is not available, the function falls back to
#' `$get()` + `$remove()` with a post-removal absence check.
#' This fallback is safe for per-process caches (e.g., [cachem::cache_mem()])
#' but cannot guarantee single-use under concurrent access in shared stores.
#'
#' @param client [OAuthClient] instance
#' @param state Plain (decrypted) state string used as the logical key
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#'
#' @return A list with `browser_token`, `pkce_code_verifier`, and `nonce`.
#'   Throws an error via `err_invalid_state()` if retrieval or removal fails,
#'   or if the retrieved value is missing/malformed.
#' @keywords internal
state_store_get_remove <- function(client, state, shiny_session = NULL) {
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
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
    err_invalid_state("Invalid or missing state")
  }

  key <- state_cache_key(state)
  store <- client@state_store

  # Prefer atomic $take() when available; fall back to $get() + $remove().
  has_take <- !is.null(store$take) && is.function(store$take)

  if (has_take) {
    ssv <- state_store_consume_atomic(store, key, client, state, shiny_session)
  } else {
    # For non-cachem stores (likely shared/distributed), warn once that the
    # non-atomic fallback cannot guarantee single-use under concurrency.
    if (!inherits(store, "cachem")) {
      warn_no_atomic_take()
    }
    ssv <- state_store_consume_fallback(
      store,
      key,
      client,
      state,
      shiny_session
    )
  }

  return(ssv)
}


# -- Atomic consume path (store has $take) -----------------------------------

#' @noRd
state_store_consume_atomic <- function(
  store,
  key,
  client,
  state,
  shiny_session
) {
  ssv <- NULL
  consume_error_class <- NULL
  consume_error_message <- NULL

  tryCatch(
    {
      ssv <- store$take(key, missing = NULL)
      # Validate the returned value in the same tryCatch so failures are
      # audited consistently
      validate_state_store_value(ssv)
    },
    error = function(e) {
      consume_error_class <<- paste(class(e), collapse = ", ")
      consume_error_message <<- conditionMessage(e)
      try(
        audit_event(
          "state_store_lookup_failed",
          context = list(
            provider = client@provider@name %||% NA_character_,
            issuer = client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(client@client_id),
            state_digest = string_digest(state),
            error_class = consume_error_class,
            phase = "state_store_atomic_take"
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
    }
  )

  if (!is.null(consume_error_message) || is.null(ssv)) {
    ctx <- list(
      provider = client@provider@name %||% NA_character_,
      issuer = client@provider@issuer %||% NA_character_,
      client_id_digest = string_digest(client@client_id),
      state_digest = string_digest(state),
      consume_error_class = consume_error_class %||% NA_character_,
      phase = "state_store_atomic_take"
    )
    err_invalid_state(
      consume_error_message %||% "State store entry is missing or malformed",
      context = ctx
    )
  }

  ssv
}


# -- Non-atomic fallback path (get + remove + post-check) --------------------

#' @noRd
state_store_consume_fallback <- function(
  store,
  key,
  client,
  state,
  shiny_session
) {
  ssv <- NULL
  get_succeeded <- FALSE
  remove_succeeded <- FALSE
  get_error_class <- NULL
  get_error_message <- NULL
  remove_error_class <- NULL

  # -- Step 1: Get the value --------------------------------------------------
  tryCatch(
    {
      ssv <- store$get(key, missing = NULL)
      validate_state_store_value(ssv)
      get_succeeded <- TRUE
    },
    error = function(e) {
      get_error_class <<- paste(class(e), collapse = ", ")
      get_error_message <<- conditionMessage(e)
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
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
    }
  )

  # -- Step 2: Remove + post-check -------------------------------------------
  # Do NOT trust the return value of $remove() (e.g., cachem::cache_mem()
  # returns TRUE even for already-absent keys).  Instead, always verify
  # absence via a post-removal $get().
  tryCatch(
    {
      store$remove(key)
      # Post-check: the key MUST be absent now.  If the store is shared and
      # another consumer already removed the entry, the key is absent and
      # remove was a no-op — that is the expected single-use path. However,
      # if the key is *still present* after our remove, something went wrong.
      post <- store$get(key, missing = NA)
      remove_succeeded <- isTRUE(is.na(post))
    },
    error = function(e) {
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
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
    }
  )

  if (!(get_succeeded && remove_succeeded)) {
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
    final_msg <- if (!is.null(get_error_message)) {
      get_error_message
    } else {
      "State access failed"
    }
    err_invalid_state(final_msg, context = ctx)
  }

  return(ssv)
}


# -- Shared validation for state store values --------------------------------

#' @noRd
validate_state_store_value <- function(ssv) {
  if (is.null(ssv) || !is.list(ssv)) {
    rlang::abort(
      "State store entry is missing or malformed",
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }
  expected_keys <- c("browser_token", "pkce_code_verifier", "nonce")
  missing_keys <- setdiff(expected_keys, names(ssv))
  if (length(missing_keys) > 0) {
    rlang::abort(
      c(
        "State store entry is malformed: missing required fields",
        "i" = paste0("Missing: ", paste(missing_keys, collapse = ", "))
      ),
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }
  if (!is_valid_string(ssv$browser_token)) {
    rlang::abort(
      "State store entry is malformed: browser_token must be a non-empty string",
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }
  invisible(ssv)
}


# -- Warning for stores without atomic $take() ------------------------------

#' @noRd
warn_no_atomic_take <- function() {
  rlang::warn(
    c(
      "State store lacks atomic `$take(key, missing)` method",
      "i" = paste0(
        "Single-use state enforcement uses a non-atomic get+remove fallback. ",
        "This is safe for per-process caches but may allow replay attacks ",
        "in multi-worker deployments with shared stores."
      ),
      "i" = paste0(
        "Provide an atomic `$take()` via `custom_cache(take = ...)` ",
        "for replay-safe state stores."
      )
    ),
    class = "shinyOAuth_no_atomic_take_warning",
    .frequency = "once",
    .frequency_id = "shinyOAuth_no_atomic_take"
  )
}
