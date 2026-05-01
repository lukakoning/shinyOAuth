# This file contains helpers for the sealed login state and the state store.
# Use them during callback handling to decrypt the saved state, confirm it still
# matches the login that started earlier, and consume the single-use state entry.

# 1 State payload helpers -------------------------------------------------

## 1.1 Decrypt and validate payload --------------------------------------

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
      with_trace_id(
        pld$trace_id %||% NULL,
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
      rethrow_with_context(
        e,
        class = c("shinyOAuth_state_error", "shinyOAuth_error"),
        message = c(
          "State payload decryption or validation failed",
          "i" = paste0("", conditionMessage(e))
        )
      )
    }
  )
}

## 1.2 Payload binding and freshness -------------------------------------

# Check that the sealed login state is still fresh enough to use.
# Used by state_payload_decrypt_validate() and otel_callback_parent_hint().
# Input: client and decrypted payload list. Output: invisible TRUE or a state error.
payload_verify_issued_at <- function(client, payload) {
  # Freshness backstop for the encrypted state payload (independent of store TTL)
  max_age <- client_state_payload_max_age(client)

  # Validate issued_at (integer seconds OK)
  ia <- payload$issued_at
  if (length(ia) != 1L || !is.numeric(ia) || !is.finite(ia)) {
    err_invalid_state("Invalid payload: missing or invalid issued_at")
  }

  # Use the same leeway as ID token checks for clock drift tolerance
  leeway <- client@provider@leeway %||% getOption("shinyOAuth.leeway", 30)
  lwe <- as.numeric(leeway %||% 0)
  if (!is.finite(lwe) || is.na(lwe) || length(lwe) != 1) {
    lwe <- 0
  }

  # Compute age in seconds using double math (robust even after 2038)
  now <- as.numeric(Sys.time())
  ia_val <- as.numeric(ia)

  # Reject if issued_at is in the future beyond leeway (clock drift tolerance)
  if (ia_val > (now + lwe)) {
    err_invalid_state("Invalid payload: issued_at is in the future")
  }

  # Compute age for max_age check
  age <- now - ia_val
  if (age > max_age) {
    err_invalid_state("Invalid payload: issued_at is too old")
  }

  invisible(TRUE)
}

# Check that the callback payload still matches the client that started login.
# Used by state_payload_decrypt_validate() before any token exchange happens.
# Input: client and decrypted payload list. Output: invisible TRUE or a state error.
payload_verify_client_binding <- function(client, payload) {
  # Helpers --------------------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  # Client ID ------------------------------------------------------------------

  expected_client_id <- client@client_id
  payload_client_id <- payload$client_id

  if (!is_valid_string(payload_client_id)) {
    err_invalid_state("Invalid payload: missing or invalid client_id")
  }
  if (!identical(payload_client_id, expected_client_id)) {
    err_invalid_state(sprintf(
      "Invalid payload: client_id mismatch (got %s)",
      payload_client_id
    ))
  }

  # Redirect_uri ---------------------------------------------------------------

  expected_redirect <- client@redirect_uri
  payload_redirect <- payload$redirect_uri

  if (!is_valid_string(payload_redirect)) {
    err_invalid_state("Invalid payload: missing or invalid redirect_uri")
  }

  if (!identical(payload_redirect, expected_redirect)) {
    err_invalid_state(sprintf(
      "Invalid payload: redirect_uri mismatch (got %s)",
      payload_redirect
    ))
  }

  # Scopes (order-insensitive set comparison) ----------------------------------

  expected_scopes <- as_scope_tokens(effective_client_scopes(client))
  payload_scopes <- as_scope_tokens(payload$scopes %||% NULL)

  # Normalize by unique + sort so we can produce clear differences
  exp_norm <- sort(unique(expected_scopes))
  got_norm <- sort(unique(payload_scopes))

  if (!setequal(exp_norm, got_norm)) {
    missing <- setdiff(exp_norm, got_norm)
    extra <- setdiff(got_norm, exp_norm)
    bullets <- c("x" = "Invalid payload: scopes do not match")
    if (length(missing)) {
      bullets <- c(
        bullets,
        "!" = paste0(
          "Missing: ",
          paste(missing, collapse = ", ")
        )
      )
    }
    if (length(extra)) {
      bullets <- c(
        bullets,
        "!" = paste0(
          "Unexpected: ",
          paste(extra, collapse = ", ")
        )
      )
    }
    err_invalid_state(bullets)
  }

  # Provider fingerprint -------------------------------------------------------

  expected_fp <- provider_fingerprint(client@provider)
  payload_fp <- payload$provider

  if (!is_valid_string(payload_fp)) {
    err_invalid_state(
      "Invalid payload: missing or invalid provider fingerprint"
    )
  }
  if (!identical(payload_fp, expected_fp)) {
    err_invalid_state(sprintf(
      "Invalid payload: provider fingerprint mismatch (got %s)",
      payload_fp
    ))
  }

  invisible(TRUE)
}

# 2 State store helpers ---------------------------------------------------

## 2.1 Fetch and remove state entry --------------------------------------

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
#' but **errors** for any other store (e.g., [cachem::cache_disk()] or custom
#' backends) because non-atomic get+remove cannot guarantee single-use under
#' concurrent access. Shared stores **must** implement `$take()` to be used
#' as a state store.
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
    # Fail closed: the non-atomic get()+remove() fallback is only safe for
    # per-process caches.  cachem::cache_mem() is the only built-in backend
    # that is inherently per-process; cachem::cache_disk() and any other
    # shared or custom stores MUST provide an atomic $take() method to
    # guarantee single-use state consumption under concurrent access.
    #
    # Users can opt in to the non-atomic fallback for shared stores by setting
    # options(shinyOAuth.allow_non_atomic_state_store = TRUE). This is
    # discouraged because it re-opens the TOCTOU replay window, but may be
    # acceptable when the deployment has sticky sessions or other external
    # safeguards.
    if (!inherits(store, "cache_mem")) {
      if (isTRUE(getOption("shinyOAuth.allow_non_atomic_state_store"))) {
        rlang::warn(
          c(
            "Using non-atomic get()+remove() state store fallback",
            "i" = paste0(
              "Single-use state enforcement uses a non-atomic get+remove fallback. ",
              "This cannot guarantee single-use under concurrent access and may ",
              "allow replay attacks in multi-worker deployments with shared stores."
            ),
            "i" = paste0(
              "Opted in via `options(shinyOAuth.allow_non_atomic_state_store = TRUE)`. ",
              "Provide an atomic `$take()` via `custom_cache(take = ...)` for ",
              "replay-safe state stores."
            )
          ),
          class = "shinyOAuth_non_atomic_state_store_warning",
          .frequency = "once",
          .frequency_id = "shinyOAuth_non_atomic_state_store"
        )
      } else {
        err_config(
          c(
            "Shared state store requires atomic `$take(key, missing)` method",
            "i" = paste0(
              "Non-atomic get()+remove() cannot guarantee single-use state ",
              "consumption under concurrent access, which may allow replay attacks ",
              "in multi-worker deployments with shared stores."
            ),
            "i" = paste0(
              "Provide an atomic `$take()` via `custom_cache(take = ...)` ",
              "(e.g., Redis GETDEL, SQL DELETE ... RETURNING) or use ",
              "`cachem::cache_mem()` for single-process deployments."
            ),
            "i" = paste0(
              "If you accept the replay risk (e.g., sticky sessions), set ",
              "`options(shinyOAuth.allow_non_atomic_state_store = TRUE)` to ",
              "allow the non-atomic fallback."
            )
          )
        )
      }
    }
    ssv <- state_store_consume_fallback(
      store,
      key,
      client,
      state,
      shiny_session
    )
  }

  ssv
}


## 2.2 Atomic consume path ------------------------------------------------

# Consume one state-store entry with an atomic read-and-remove operation.
# Used by state_store_get_remove() when the backend exposes `$take()`.
# Input: store, computed key, client/state context, and Shiny context. Output: validated state-store value list or a state error.

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


## 2.3 Non-atomic fallback path -------------------------------------------

# Consume one state-store entry with get + remove + a post-check.
# Used by state_store_get_remove() only for per-process caches that do not offer `$take()`.
# Input: store, computed key, client/state context, and Shiny context. Output: validated state-store value list or a state error.

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

  ssv
}


## 2.4 Shared state-store validation --------------------------------------

# Check that a retrieved state-store value has the fields callback handling expects.
# Used by both state-store consume paths before browser-token and PKCE checks continue.
# Input: one retrieved state-store value. Output: invisible value or a state error.
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
