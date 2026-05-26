# This file contains helpers for the sealed login state and the state store
# The state value is the temporary login data that is created before redirect
# and checked again on callback
# Used for decrypting saved state, matching it to the original login, and
# consuming the single-use state entry

# 1 State payload helpers ------------------------------------------------------

## 1.1 Decrypt and validate payload --------------------------------------------

#' Decrypt and validate OAuth state payload
#'
#' Internal utility that decrypts the encrypted `state` payload using the
#' client's `state_key`, then validates freshness and client binding. Used by
#' callback handling before the code exchange continues.
#'
#' @param client [OAuthClient] instance
#' @param encrypted_payload Encrypted state payload string received via the
#'   `state` query parameter.
#'
#' @return A named list payload (state, client_id, redirect_uri, scopes,
#'   provider, client_policy, issued_at) on success; otherwise throws an error
#'   via `err_invalid_state()`.
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#' @param audit_success Whether successful payload validation should emit the
#'   standard callback validation audit event. Defaults to `FALSE` because
#'   callback handlers normally still need to validate the browser-bound token
#'   and consume the single-use state entry before success is final. Failures
#'   are still audited.
#' @keywords internal
state_payload_decrypt_validate <- function(
  client,
  encrypted_payload,
  shiny_session = NULL,
  audit_success = FALSE
) {
  S7::check_is_S7(client, class = OAuthClient)

  # Centralized failure auditing for decrypt + validation to align sync/async flows
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

      if (isTRUE(audit_success)) {
        audit_callback_validation_success(client, pld, shiny_session)
      }
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

#' Audit successful callback state validation
#'
#' Used after a callback has completed its state, browser-token, and single-use
#' validation steps.
#'
#' @param client [OAuthClient] instance.
#' @param payload Decrypted state payload.
#' @param shiny_session Optional Shiny session context.
#' @return Invisibly returns `NULL`.
#' @keywords internal
#' @noRd
audit_callback_validation_success <- function(
  client,
  payload,
  shiny_session = NULL
) {
  with_trace_id(
    payload[["trace_id"]] %||% NULL,
    try(
      audit_event(
        "callback_validation_success",
        context = list(
          provider = client@provider@name %||% NA_character_,
          issuer = client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(client@client_id),
          state_digest = string_digest(payload[["state"]])
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
  )

  invisible(NULL)
}

## 1.2 Policy fingerprints -----------------------------------------------------

#' Build a stable state-policy fingerprint
#'
#' Computes an unkeyed SHA-256 digest over normalized state-policy components so
#' callback validation can confirm it is resuming under the same effective
#' security policy that initiated login.
#'
#' @param components Named list of normalized policy components.
#' @return A length-1 character string in `sha256:<digest>` format.
#' @keywords internal
#' @noRd
state_policy_digest <- function(components) {
  component_names <- names(components)
  canonical <- vapply(
    component_names,
    function(component_name) {
      value <- state_policy_component_string(components[[component_name]])
      paste0(
        component_name,
        ":",
        nchar(value, type = "bytes"),
        ":",
        value
      )
    },
    ""
  )

  paste0(
    "sha256:",
    string_digest(enc2utf8(paste(canonical, collapse = "\n")), key = NULL)
  )
}

#' Normalize one state-policy component into a stable string
#'
#' Used by `state_policy_digest()` before hashing policy components.
#'
#' @param value Arbitrary policy component value.
#' @return Canonical UTF-8 string.
#' @keywords internal
#' @noRd
state_policy_component_string <- function(value) {
  normalized <- state_policy_normalize_value(value)
  enc2utf8(jsonlite::toJSON(
    normalized,
    auto_unbox = TRUE,
    null = "null",
    pretty = FALSE
  ))
}

#' Normalize a state-policy value for canonical serialization
#'
#' Used by `state_policy_component_string()` to convert policy fields into a
#' JSON-serializable shape with stable ordering and explicit scalar encoding.
#'
#' @param value Arbitrary policy component value.
#' @return JSON-serializable value.
#' @keywords internal
#' @noRd
state_policy_normalize_value <- function(value) {
  if (is.null(value)) {
    return(NULL)
  }

  if (is.function(value)) {
    return(list(`__function__` = paste(deparse(value), collapse = "\n")))
  }

  if (is.raw(value)) {
    return(paste0(sprintf("%02x", as.integer(value)), collapse = ""))
  }

  if (is.list(value)) {
    if (length(value) == 0L) {
      return(list())
    }

    value_names <- names(value)
    if (length(value_names) > 0L && !is.null(value_names)) {
      ord <- order(value_names)
      value <- value[ord]
      value_names <- value_names[ord]
      out <- lapply(value, state_policy_normalize_value)
      names(out) <- value_names
      return(out)
    }

    return(lapply(value, state_policy_normalize_value))
  }

  if (is.atomic(value)) {
    value_names <- names(value)
    if (length(value_names) > 0L && !is.null(value_names)) {
      ord <- order(value_names)
      value <- value[ord]
      out <- as.list(vapply(
        seq_along(value),
        function(i) state_policy_scalar_string(value[[i]]),
        ""
      ))
      names(out) <- value_names[ord]
      return(out)
    }

    return(unname(vapply(
      seq_along(value),
      function(i) state_policy_scalar_string(value[[i]]),
      ""
    )))
  }

  state_policy_scalar_string(value)
}

#' Convert one scalar policy value to a stable string
#'
#' Used by `state_policy_normalize_value()` for atomic leaves.
#'
#' @param value Scalar policy value.
#' @return Length-1 UTF-8 string.
#' @keywords internal
#' @noRd
state_policy_scalar_string <- function(value) {
  if (is.null(value) || length(value) == 0L) {
    return("")
  }

  if (is.logical(value)) {
    return(
      if (is.na(value[[1L]])) {
        "<na>"
      } else if (isTRUE(value[[1L]])) {
        "true"
      } else {
        "false"
      }
    )
  }

  if (is.numeric(value)) {
    if (is.na(value[[1L]])) {
      return("<na>")
    }
    return(format(
      signif(as.numeric(value[[1L]]), digits = 17),
      scientific = FALSE,
      trim = TRUE
    ))
  }

  value_chr <- tryCatch(as.character(value[[1L]]), error = function(...) {
    "<unsupported>"
  })
  if (!is.character(value_chr) || length(value_chr) != 1L || is.na(value_chr)) {
    return("<na>")
  }

  enc2utf8(value_chr)
}

#' Normalize a character-like set for policy fingerprints
#'
#' Used by client/provider policy fingerprint helpers when option order does not
#' affect behavior.
#'
#' @param value Character-like vector.
#' @param transform Optional normalization function applied elementwise.
#' @return Sorted unique character vector with empty and `NA` entries removed.
#' @keywords internal
#' @noRd
state_policy_string_set <- function(value, transform = identity) {
  values <- as.character(value %||% character(0))
  values <- values[!is.na(values) & nzchar(values)]
  values <- transform(values)
  sort(unique(enc2utf8(as.character(values))))
}

#' Compute a DPoP key thumbprint for state binding
#'
#' Used by `state_client_policy_fingerprint()` when a client enables DPoP.
#'
#' @param client OAuth client carrying DPoP configuration.
#' @return RFC 7638 JWK thumbprint string, or `NA_character_` when DPoP is not
#'   configured.
#' @keywords internal
#' @noRd
state_policy_dpop_key_thumbprint <- function(client) {
  if (!client_has_dpop(client)) {
    return(NA_character_)
  }

  compute_jwk_thumbprint(dpop_public_jwk(resolve_dpop_private_key(client)))
}

#' Compute an mTLS certificate thumbprint for state binding
#'
#' Used by `state_client_policy_fingerprint()` when a client presents a TLS
#' certificate during token or protected-resource requests.
#'
#' @param client OAuth client carrying mTLS configuration.
#' @return Base64url SHA-256 certificate thumbprint, or `NA_character_` when no
#'   mTLS certificate is configured.
#' @keywords internal
#' @noRd
state_policy_mtls_cert_thumbprint <- function(client) {
  if (!client_has_mtls_certificate(client)) {
    return(NA_character_)
  }

  tls_client_cert_thumbprint_s256(
    client@tls_client_cert_file,
    key_file = client@tls_client_key_file,
    key_password = if (is_valid_string(client@tls_client_key_password)) {
      client@tls_client_key_password
    } else {
      NULL
    }
  )
}

#' Build a client-side callback policy fingerprint
#'
#' Computes a stable digest over client settings that affect callback handling,
#' token/userinfo validation, or sender-constrained token enforcement so the
#' callback cannot resume under a looser client policy on another worker.
#'
#' @param client [OAuthClient] instance to fingerprint.
#' @return A length-1 character string in `sha256:<digest>` format.
#' @keywords internal
#' @noRd
state_client_policy_fingerprint <- function(client) {
  S7::check_is_S7(client, class = OAuthClient)

  components <- list(
    enforce_callback_issuer = isTRUE(client@enforce_callback_issuer),
    resource = state_policy_string_set(client@resource),
    claims = client@claims,
    state_payload_max_age = client_state_payload_max_age(client),
    scope_validation = client@scope_validation,
    claims_validation = client@claims_validation,
    userinfo_jwt_required_temporal_claims = state_policy_string_set(
      client@userinfo_jwt_required_temporal_claims,
      transform = tolower
    ),
    required_acr_values = state_policy_string_set(client@required_acr_values),
    introspect = isTRUE(client@introspect),
    introspect_elements = state_policy_string_set(client@introspect_elements),
    dpop_require_access_token = isTRUE(client@dpop_require_access_token),
    mtls_request_certificate_bound_access_tokens = isTRUE(
      client@mtls_request_certificate_bound_access_tokens
    ),
    dpop_signing_alg = if (client_has_dpop(client)) {
      resolve_dpop_alg(client)
    } else {
      NA_character_
    },
    dpop_private_key_kid = client@dpop_private_key_kid,
    dpop_key_thumbprint = state_policy_dpop_key_thumbprint(client),
    mtls_cert_thumbprint = state_policy_mtls_cert_thumbprint(client)
  )

  state_policy_digest(components)
}

## 1.3 Payload binding and freshness -------------------------------------------

#' Verify encrypted state payload freshness
#'
#' Used by [state_payload_decrypt_validate()].
#'
#' @param client OAuth client carrying the payload age policy.
#' @param payload Decrypted state payload list.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   state error.
#' @keywords internal
#' @noRd
payload_verify_issued_at <- function(client, payload) {
  # Freshness backstop for the encrypted state payload (independent of store TTL)
  max_age <- client_state_payload_max_age(client)

  # Validate issued_at (integer seconds OK)
  ia <- payload[["issued_at"]]
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

#' Verify encrypted state payload client binding
#'
#' Used by [state_payload_decrypt_validate()].
#'
#' @param client OAuth client expected to match the payload.
#' @param payload Decrypted state payload list.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   state error.
#' @keywords internal
#' @noRd
payload_verify_client_binding <- function(client, payload) {
  # Helpers --------------------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  # Client ID ------------------------------------------------------------------

  expected_client_id <- client@client_id
  payload_client_id <- payload[["client_id"]]

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
  payload_redirect <- payload[["redirect_uri"]]

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
  payload_scopes <- as_scope_tokens(payload[["scopes"]] %||% NULL)

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
  payload_fp <- payload[["provider"]]

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

  # Client-side callback policy fingerprint -----------------------------------

  expected_client_policy <- state_client_policy_fingerprint(client)
  payload_client_policy <- payload[["client_policy"]]

  if (!is_valid_string(payload_client_policy)) {
    err_invalid_state(
      "Invalid payload: missing or invalid client policy fingerprint"
    )
  }
  if (!identical(payload_client_policy, expected_client_policy)) {
    err_invalid_state(sprintf(
      "Invalid payload: client policy mismatch (got %s)",
      payload_client_policy
    ))
  }

  invisible(TRUE)
}

# 2 State store helpers --------------------------------------------------------

## 2.1 Read state entry --------------------------------------------------------

#' Read a state-store entry without consuming it
#'
#' Used when the caller must validate browser-bound data before burning the
#' single-use state entry. Single-use enforcement must still happen later via
#' [state_store_get_remove()].
#'
#' @param client [OAuthClient] instance
#' @param state Plain (decrypted) state string used as the logical key
#' @param shiny_session Optional pre-captured Shiny session context.
#' @return Validated state-store value list.
#' @keywords internal
#' @noRd
state_store_get <- function(client, state, shiny_session = NULL) {
  S7::check_is_S7(client, class = OAuthClient)
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
  ssv <- NULL
  get_error_class <- NULL
  get_error_message <- NULL

  tryCatch(
    {
      ssv <- store$get(key, missing = NULL)
      ssv <- validate_state_store_value(
        ssv,
        client,
        validate_policy_fields = FALSE
      )
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

  if (!is.null(get_error_message) || is.null(ssv)) {
    err_invalid_state(
      get_error_message %||% "State store entry is missing or malformed",
      context = list(
        provider = client@provider@name %||% NA_character_,
        issuer = client@provider@issuer %||% NA_character_,
        client_id_digest = string_digest(client@client_id),
        state_digest = string_digest(state),
        get_error_class = get_error_class %||% NA_character_,
        phase = "state_store_lookup"
      )
    )
  }

  ssv
}

## 2.2 Fetch and remove state entry --------------------------------------------

#' Fetch and remove the single-use state entry
#'
#' Uses the client's `state_store` to read and remove the state-bound values
#' after the encrypted callback payload has been decrypted and validated.
#'
#' When the store exposes an atomic `$take(key, missing)` method (see
#' [custom_cache()]), that path is used first so single-use semantics still
#' hold under concurrent access.
#' When `$take()` is unavailable, the function falls back to `$get()` +
#' `$remove()` with a post-removal absence check.
#' That fallback is safe for per-process caches such as [cachem::cache_mem()].
#' For shared stores it errors by default, because non-atomic get+remove cannot
#' guarantee single-use semantics under concurrent access; operators may opt in
#' to that weaker fallback with
#' `options(shinyOAuth.allow_non_atomic_state_store = TRUE)`, but doing so is
#' discouraged.
#'
#' @param client [OAuthClient] instance
#' @param state Plain (decrypted) state string used as the logical key
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#'
#' @return Validated state-store value list. On failure this function raises
#'   `err_invalid_state()` instead of returning a partial result.
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
        warn_pkg(
          "Using non-atomic get()+remove() state store fallback",
          c(
            "!" = paste0(
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


## 2.3 Atomic consume path -----------------------------------------------------

#' Consume a state-store entry atomically
#'
#' @param store State-store backend exposing `$take()`.
#' @param key Computed store key.
#' @param client OAuth client used for audit context.
#' @param state Raw state string.
#' @param shiny_session Optional Shiny session context.
#' @return Validated state-store value list.
#' @keywords internal
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
      ssv <- validate_state_store_value(ssv, client)
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


## 2.4 Non-atomic fallback path ------------------------------------------------

#' Consume a state-store entry with a fallback path
#'
#' @param store State-store backend exposing `$get()` and `$remove()`.
#' @param key Computed store key.
#' @param client OAuth client used for audit context.
#' @param state Raw state string.
#' @param shiny_session Optional Shiny session context.
#' @return Validated state-store value list.
#' @keywords internal
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
      ssv <- validate_state_store_value(ssv, client)
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


## 2.5 Shared state-store validation -------------------------------------------

#' Validate a retrieved state-store value
#'
#' @param ssv Retrieved state-store value.
#' @param client OAuth client whose policy determines whether PKCE and nonce
#'   values are required.
#' @param validate_policy_fields Whether to require and validate the PKCE and
#'   nonce fields that are controlled by the client policy. Set this to `FALSE`
#'   only for pre-consumption browser-token checks.
#' @return Invisibly returns `ssv` on success. Otherwise this function raises a
#'   state error.
#' @keywords internal
#' @noRd
validate_state_store_value <- function(
  ssv,
  client,
  validate_policy_fields = TRUE
) {
  if (is.null(ssv) || !is.list(ssv)) {
    abort_pkg(
      "State store entry is missing or malformed",
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }

  # Custom stores may serialize away unused NULLs. Only require the fields
  # that the current client policy can actually consume later.
  required_keys <- "browser_token"
  if (isTRUE(validate_policy_fields) && isTRUE(client@provider@use_pkce)) {
    required_keys <- c(required_keys, "pkce_code_verifier")
  }
  if (isTRUE(validate_policy_fields) && isTRUE(client@provider@use_nonce)) {
    required_keys <- c(required_keys, "nonce")
  }

  missing_keys <- setdiff(required_keys, names(ssv))
  if (length(missing_keys) > 0) {
    abort_pkg(
      "State store entry is malformed: missing required fields",
      c(
        "i" = paste0("Missing: ", paste(missing_keys, collapse = ", "))
      ),
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }
  if (!is_valid_string(ssv$browser_token)) {
    abort_pkg(
      "State store entry is malformed: browser_token must be a non-empty string",
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }

  if (
    isTRUE(validate_policy_fields) &&
      isTRUE(client@provider@use_pkce) &&
      !is_valid_string(ssv$pkce_code_verifier)
  ) {
    abort_pkg(
      paste0(
        "State store entry is malformed: pkce_code_verifier must be ",
        "a non-empty string when PKCE is enabled"
      ),
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }

  if (
    isTRUE(validate_policy_fields) &&
      isTRUE(client@provider@use_nonce) &&
      !is_valid_string(ssv$nonce)
  ) {
    abort_pkg(
      paste0(
        "State store entry is malformed: nonce must be a non-empty string ",
        "when nonce validation is enabled"
      ),
      class = c("shinyOAuth_state_error", "shinyOAuth_error")
    )
  }

  invisible(ssv)
}
