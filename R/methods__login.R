# Prepare call ------------------------------------------------------------

#' Prepare a OAuth 2.0 authorization call and build an authorization URL
#'
#' This function prepares an OAuth 2.0 authorization call by generating necessary
#' state, PKCE, and nonce values, storing them securely, and constructing
#' the authorization URL to redirect the user to. The state and accompanying
#' values are stored in the client's state store for later verification during
#' the callback phase of the OAuth 2.0 flow.
#'
#' @param oauth_client An [OAuthClient] object representing the OAuth client configuration.
#' @param browser_token A string token (e.g., from a browser cookie) to identify the user/session.
#'
#' @return A string containing the constructed authorization URL. This URL
#'  should be used to redirect the user to the OAuth provider's authorization endpoint.
#'
#' @example inst/examples/call_methods.R
#'
#' @export
prepare_call <- function(
  oauth_client,
  browser_token
) {
  # Verify input  --------------------------------------------------------------

  # Verify oauth_client
  S7::check_is_S7(oauth_client, OAuthClient)

  # Verify browser_token
  if (is.null(browser_token) && isTRUE(allow_skip_browser_token())) {
    browser_token <- "__SKIPPED__"
  } else if (is.null(browser_token)) {
    err_invalid_state(
      "`browser_token` is NULL",
      context = list(phase = "prepare_call")
    )
  }
  validate_browser_token(browser_token)

  # State, code_challenge & code_verifier, nonce -------------------------------

  # State is a random value that we send with the initial auth request
  # We expect to see it back later during the callback

  state <- random_urlsafe(n = oauth_client@state_entropy %||% 64)

  # Ensure state meets minimal criteria (minimal length, URL-safe)
  validate_state(state)

  # PKCE is a mechanism to ensure that the entity that initiates the
  #   authorization request is the same entity that completes the flow
  # We sent a code_challenge now, and later a code_verifier, to proof our
  #   identity during the token exchange step
  # This prevents code interception attacks

  pkce_code_challenge <- NULL
  pkce_code_verifier <- NULL
  pkce_method <- NULL
  if (isTRUE(oauth_client@provider@use_pkce)) {
    method <- oauth_client@provider@pkce_method %||% "S256"
    if (method == "S256") {
      pkce_code_verifier <- gen_code_verifier(64)
      sha256 <- openssl::sha256(charToRaw(pkce_code_verifier))
      # RFC 7636 requires base64url-encoded SHA-256 without padding
      pkce_code_challenge <- base64url_encode(sha256)
      pkce_method <- "S256"
    } else if (method == "plain") {
      pkce_code_verifier <- gen_code_verifier(64)
      pkce_code_challenge <- pkce_code_verifier
      pkce_method <- "plain"
    } else {
      err_pkce(paste0("Unsupported PKCE method: ", method))
    }
  }

  # Nonce is a random value that we sent with the initial auth request
  # We expect to see it back later in the OIDC ID token

  nonce <- NULL
  if (oauth_client@provider@use_nonce) {
    nonce <- random_urlsafe(n = 32)
  }

  # Create + seal (AES-GCM AEAD) payload --------------------------------------

  # We seal the payload using AES-GCM AEAD, which provides confidentiality and
  #   integrity via an authentication tag, preventing tampering.
  # We will include some details about the provider & client, to prevent
  #   possible mixups if multiple clients/providers are in use
  # We will include an issued_at timestamp, as extra protection against replay
  #   attacks (won't accept payloads older than some threshold)

  payload <- list(
    state = state,
    client_id = oauth_client@client_id,
    redirect_uri = oauth_client@redirect_uri,
    scopes = oauth_client@scopes,
    provider = oauth_client@provider |> provider_fingerprint(),
    issued_at = as.numeric(Sys.time())
  ) |>
    state_encrypt_gcm(key = oauth_client@state_key)

  # Store in state store -------------------------------------------------------

  # We will need these values later, when we get the callback
  # - Browser token is needed to identify the user/session
  #   We use it to check if browser initiating the flow is the same
  #   as the one completing it
  # - PKCE code verifier is needed to complete the PKCE proof (see above)
  # - Nonce is needed to validate the OIDC ID token (if applicable) (see above)
  # Note: write AFTER successful encryption so we don't leave stale entries if
  # encryption fails due to invalid/misconfigured state_key.
  # Note: 'cachem' requires lowercase letters/numbers in keys; derive a lowercase-hex
  # key from the high-entropy state to store associated values
  tryCatch(
    {
      oauth_client@state_store$set(
        key = state_cache_key(state),
        value = list(
          browser_token = browser_token,
          pkce_code_verifier = pkce_code_verifier,
          nonce = nonce
        )
      )
    },
    error = function(e) {
      # Surface cache backend failures as state errors with context
      err_invalid_state(
        sprintf(
          "Failed to persist state in state_store: %s",
          conditionMessage(e)
        ),
        context = list(phase = "prepare_call::state_store_set")
      )
    }
  )

  # Build authorization URL ----------------------------------------------------

  auth_url <- build_auth_url(
    oauth_client,
    payload = payload,
    pkce_code_challenge = pkce_code_challenge,
    pkce_method = pkce_method,
    nonce = nonce
  )

  # Audit: redirect issuance (redacted identifiers only)
  try(
    {
      audit_event(
        "redirect_issued",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          state_digest = string_digest(state),
          browser_token_digest = string_digest(browser_token),
          pkce_method = pkce_method %||% NA_character_,
          nonce_present = isTRUE(oauth_client@provider@use_nonce),
          scopes_count = length(oauth_client@scopes %||% character()),
          redirect_uri = oauth_client@redirect_uri %||% NA_character_
        )
      )
    },
    silent = TRUE
  )

  # Return ---------------------------------------------------------------------

  return(auth_url)
}

# Helper: turn key provider properties into a stable fingerprint string
provider_fingerprint <- function(provider) {
  norm_chr <- function(x) {
    if (is.null(x) || length(x) != 1L || is.na(x)) {
      return("")
    }
    as.character(x)
  }

  iss <- norm_chr(provider@issuer)
  au <- norm_chr(provider@auth_url)
  tu <- norm_chr(provider@token_url)
  ui <- norm_chr(provider@userinfo_url)
  it <- norm_chr(provider@introspection_url)

  # Use a length-prefixed canonical representation to avoid delimiter-based
  # collisions when any component contains separators.
  iss_u <- enc2utf8(iss)
  au_u <- enc2utf8(au)
  tu_u <- enc2utf8(tu)
  ui_u <- enc2utf8(ui)
  it_u <- enc2utf8(it)

  canonical <- paste0(
    "iss:",
    nchar(iss_u, type = "bytes"),
    ":",
    iss_u,
    "\n",
    "au:",
    nchar(au_u, type = "bytes"),
    ":",
    au_u,
    "\n",
    "tu:",
    nchar(tu_u, type = "bytes"),
    ":",
    tu_u,
    "\n",
    "ui:",
    nchar(ui_u, type = "bytes"),
    ":",
    ui_u,
    "\n",
    "it:",
    nchar(it_u, type = "bytes"),
    ":",
    it_u
  )

  # Use unkeyed digest (key = NULL) so fingerprint is stable across processes.
  # Keyed digests are only for audit logs where correlation prevention matters.
  paste0("sha256:", string_digest(enc2utf8(canonical), key = NULL))
}

# Helper: build authorization URL with all params
build_auth_url <- function(
  oauth_client,
  payload,
  pkce_code_challenge,
  pkce_method,
  nonce
) {
  # Type checks
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is_valid_string(payload)) {
    err_invalid_state("build_auth_url: 'payload' must be a valid string")
  }

  if (isTRUE(oauth_client@provider@use_pkce)) {
    if (
      !is_valid_string(pkce_code_challenge) || !is_valid_string(pkce_method)
    ) {
      err_invalid_state(
        "build_auth_url: PKCE is enabled but 'pkce_code_challenge' or 'pkce_method' is missing or invalid"
      )
    }
  } else {
    if (!is.null(pkce_code_challenge) || !is.null(pkce_method)) {
      err_invalid_state(
        "build_auth_url: PKCE is disabled but 'pkce_code_challenge' or 'pkce_method' was provided"
      )
    }
  }

  if (isTRUE(oauth_client@provider@use_nonce)) {
    if (!is_valid_string(nonce)) {
      err_invalid_state(
        "build_auth_url: Nonce is enabled but 'nonce' is missing or invalid"
      )
    }
  } else {
    if (!is.null(nonce)) {
      err_invalid_state(
        "build_auth_url: Nonce is disabled but 'nonce' was provided"
      )
    }
  }

  # Base params
  params <- list(
    response_type = "code",
    client_id = oauth_client@client_id,
    redirect_uri = oauth_client@redirect_uri,
    state = payload
  )

  # Add optional params only when present
  if (isTRUE(oauth_client@provider@use_pkce)) {
    params$code_challenge <- pkce_code_challenge
    params$code_challenge_method <- pkce_method
  }
  if (isTRUE(oauth_client@provider@use_nonce)) {
    params$nonce <- nonce
  }

  effective_scopes <- ensure_openid_scope(
    oauth_client@scopes,
    oauth_client@provider
  )
  if (length(effective_scopes) > 0) {
    params$scope <- paste(effective_scopes, collapse = " ")
  }

  # OIDC claims parameter (OIDC Core §5.5): JSON-encode if a list,
  # otherwise use as-is
  if (!is.null(oauth_client@claims)) {
    if (is.list(oauth_client@claims)) {
      # JSON-encode the list with auto_unbox to avoid wrapping single values
      # in arrays, and null = "null" to preserve explicit null values which
      # OIDC uses to request claims without additional parameters
      params$claims <- jsonlite::toJSON(
        oauth_client@claims,
        auto_unbox = TRUE,
        null = "null"
      )
    } else {
      # Assume pre-encoded JSON string
      params$claims <- oauth_client@claims
    }
  }

  if (length(oauth_client@provider@extra_auth_params) > 0) {
    extra <- oauth_client@provider@extra_auth_params

    # Block parameters that are critical to OAuth security. Allowing these to be
    # overridden via extra_auth_params would break state binding, redirect_uri
    # validation, or PKCE integrity and could lead to unsafe configurations.
    # Users can unblock specific keys via shinyOAuth.unblock_auth_params.
    default_blocked_params <- c(
      "state",
      "redirect_uri",
      "response_type",
      "client_id",
      "scope",
      "nonce",
      "code_challenge",
      "code_challenge_method",
      "claims" # Managed via oauth_client(..., claims = ...)
    )
    unblocked <- getOption("shinyOAuth.unblock_auth_params", character())
    blocked_params <- setdiff(default_blocked_params, unblocked)

    conflicts <- intersect(names(extra), blocked_params)
    if (length(conflicts) > 0) {
      err_config(c(
        paste0(
          "OAuthProvider.extra_auth_params must not override core OAuth parameters: ",
          paste(conflicts, collapse = ", ")
        ),
        "i" = "These parameters are managed internally to ensure OAuth security.",
        "i" = "Set scopes via oauth_client(..., scopes = ...) and redirect_uri via oauth_client(..., redirect_uri = ...).",
        "i" = "To unblock, set options(shinyOAuth.unblock_auth_params = c(...))"
      ))
    }
    params <- c(params, extra)
  }

  # Critically: drop NULLs so httr2 doesn't choke
  params <- params[!vapply(params, is.null, logical(1))]

  httr2::url_modify(oauth_client@provider@auth_url, query = params)
}


# Handle callback ---------------------------------------------------------

#' Handle OAuth 2.0 callback: verify state, swap code for token, verify token
#'
#' @param oauth_client An [OAuthClient] object representing the OAuth client configuration.
#' @param code The authorization code received from the OAuth provider during the callback.
#' @param payload The encrypted state payload received from the OAuth provider during the callback
#' (this should be the same value that was generated and sent in `prepare_call()`).
#' @param browser_token Browser token present in the user's session (this is managed
#' by `oauth_module_server()` and should match the one used in `prepare_call()`).
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#'
#' @return An [OAuthToken] object containing the access token, refresh token,
#' expiration time, user information (if requested), and ID token (if applicable).
#' If any step of the process fails (e.g., state verification, token exchange,
#' token validation), an error is thrown indicating the failure reason.
#'
#' @example inst/examples/call_methods.R
#'
#' @export
handle_callback <- function(
  oauth_client,
  code,
  payload,
  browser_token,
  shiny_session = NULL
) {
  handle_callback_internal(
    oauth_client = oauth_client,
    code = code,
    payload = payload,
    browser_token = browser_token,
    decrypted_payload = NULL,
    state_store_values = NULL,
    shiny_session = shiny_session
  )
}

# Internal helper that supports pre-validated bypass parameters for async flows.
# NOT exported: only called by oauth_module_server() when dispatching to async
# workers where state-store and payload validation must occur on the main thread.
handle_callback_internal <- function(
  oauth_client,
  code,
  payload,
  browser_token,
  decrypted_payload = NULL,
  state_store_values = NULL,
  shiny_session = NULL
) {
  # Type checks ----------------------------------------------------------------

  S7::check_is_S7(oauth_client, class = OAuthClient)

  # Read introspection settings from client (already validated by OAuthClient)
  introspect <- isTRUE(oauth_client@introspect)
  introspect_elements <- oauth_client@introspect_elements %||% character(0)

  # Validate required callback params without leaking raw assertion messages
  if (!is_valid_string(code)) {
    err_invalid_state("Callback missing authorization code")
  }
  if (!is_valid_string(payload)) {
    err_invalid_state("Callback missing state payload")
  }
  # (Browser token gets validated below)

  # Defensive: avoid hashing/storing arbitrarily large query-derived inputs.
  # This duplicates the check in oauth_module_server's .process_query() by
  # design, so that direct callers of handle_callback() are also protected.
  validate_untrusted_query_param(
    "code",
    code,
    max_bytes = get_option_positive_number(
      "shinyOAuth.callback_max_code_bytes",
      4096
    )
  )
  validate_untrusted_query_param(
    "state",
    payload,
    max_bytes = get_option_positive_number(
      "shinyOAuth.callback_max_state_bytes",
      8192
    )
  )
  # Browser token is not query-derived in the module, but handle_callback() is
  # exported and may be called directly with attacker-controlled inputs.
  # Cap it before any hashing/auditing to avoid a DoS footgun.
  validate_untrusted_query_param(
    "browser_token",
    browser_token,
    max_bytes = get_option_positive_number(
      "shinyOAuth.callback_max_browser_token_bytes",
      256
    )
  )

  # Audit: callback received
  try(
    {
      audit_event(
        "callback_received",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          code_digest = string_digest(code),
          state_digest = string_digest(payload),
          browser_token_digest = string_digest(browser_token)
        ),
        shiny_session = shiny_session
      )
    },
    silent = TRUE
  )

  # Decrypt & verify payload ---------------------------------------------------

  # Allow callers to provide a pre-decrypted/validated payload to support
  # async flows that prefetch state on the main thread.
  if (!is.null(decrypted_payload)) {
    payload <- decrypted_payload
  } else {
    # Centralized auditing now occurs inside state_payload_decrypt_validate()
    payload <- state_payload_decrypt_validate(
      oauth_client,
      payload,
      shiny_session = shiny_session
    )
  }

  # Retrieve state_info from state store ---------------------------------------
  # State is the key; value is a list with browser_token, pkce_code_verifier, nonce
  if (is.null(state_store_values)) {
    # Centralized auditing for state store lookup occurs in state_store_get_remove()
    state_store_values <- state_store_get_remove(
      oauth_client,
      payload$state,
      shiny_session = shiny_session
    )
  }

  # Verify browser token -------------------------------------------------------

  # Verify browser_token matches
  tryCatch(
    {
      # First validate the format of the provided browser_token. If validation
      # fails, reclassify to a state error so downstream handling/auditing
      # consistently treats it as a state mismatch rather than PKCE.
      tryCatch(
        validate_browser_token(browser_token),
        error = function(e) {
          err_invalid_state(
            "Invalid browser token",
            context = list(
              original_error_class = paste(class(e), collapse = ", ")
            )
          )
        }
      )

      # Then verify the browser_token matches what was stored for this state.
      # Use a timing-safe comparison to avoid leaking information via
      # early-exit string comparisons.
      if (
        !constant_time_compare(state_store_values$browser_token, browser_token)
      ) {
        err_invalid_state("Browser token mismatch")
      }
    },
    error = function(e) {
      try(
        audit_event(
          "callback_validation_failed",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            state_digest = string_digest(payload$state %||% NA_character_),
            browser_token_digest = string_digest(browser_token),
            error_class = paste(class(e), collapse = ", "),
            phase = "browser_token_validation"
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      rlang::abort(message = conditionMessage(e), parent = e)
    }
  )

  # Swap code for token --------------------------------------------------------

  # Now we can call the token endpoint to swap the code for token(s)

  # Verify PKCE code verifier is present if needed
  code_verifier <- state_store_values$pkce_code_verifier
  tryCatch(
    {
      # validate_code_verifier() throws on invalid input; no return value check
      # needed since the function either succeeds or aborts.
      if (isTRUE(oauth_client@provider@use_pkce)) {
        validate_code_verifier(code_verifier)
      }
    },
    error = function(e) {
      try(
        audit_event(
          "callback_validation_failed",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            state_digest = string_digest(payload$state %||% NA_character_),
            error_class = paste(class(e), collapse = ", "),
            phase = "pkce_verifier_validation"
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      rlang::abort(message = conditionMessage(e), parent = e)
    }
  )

  # Perform token exchange
  token_set <- tryCatch(
    {
      ts <- swap_code_for_token_set(
        oauth_client,
        code = code,
        code_verifier = code_verifier
      )
      try(
        audit_event(
          "token_exchange",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            code_digest = string_digest(code),
            used_pkce = isTRUE(oauth_client@provider@use_pkce),
            received_id_token = isTRUE(is_valid_string(
              ts$id_token %||% NA_character_
            )),
            received_refresh_token = isTRUE(is_valid_string(
              ts$refresh_token %||% NA_character_
            ))
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      ts
    },
    error = function(e) {
      try(
        audit_event(
          "token_exchange_error",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            code_digest = string_digest(code),
            error_class = paste(class(e), collapse = ", ")
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      rlang::abort(message = conditionMessage(e), parent = e)
    }
  )

  # Note that token_set is a named list with various fields; may include:
  # - access_token
  # - token_type
  # - expires_in
  # - refresh_token
  # - scope
  # - id_token
  # - ... plus any extra fields returned by the provider

  # Validate token_type immediately after token exchange, before any userinfo
  # call. This prevents sending an inappropriate Bearer token to the provider
  # when a non-Bearer token_type (e.g., DPoP) is returned.
  verify_token_type_allowlist(oauth_client, token_set)

  # Verify token ---------------------------------------------------------------
  #
  # Validate ID token signature/claims (including nonce) BEFORE fetching
  # userinfo. This ensures cryptographic validation occurs before making
  # external calls or exposing PII via userinfo endpoint.

  # Verify nonce is present if needed
  nonce <- state_store_values$nonce
  tryCatch(
    {
      # validate_oidc_nonce() throws on invalid input; no return value check
      # needed since the function either succeeds or aborts.
      if (oauth_client@provider@use_nonce) {
        validate_oidc_nonce(nonce)
      }
    },
    error = function(e) {
      try(
        audit_event(
          "callback_validation_failed",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            state_digest = string_digest(payload$state %||% NA_character_),
            error_class = paste(class(e), collapse = ", "),
            phase = "nonce_validation"
          ),
          shiny_session = shiny_session
        ),
        silent = TRUE
      )
      rlang::abort(message = conditionMessage(e), parent = e)
    }
  )

  # Verify token set: validates ID token signature + claims (including nonce),
  # scope reconciliation, and token_type. Userinfo is NOT yet present; the
  # subject match check will run after userinfo is fetched below.
  token_set <- verify_token_set(
    oauth_client,
    token_set = token_set,
    nonce = nonce,
    is_refresh = FALSE
  )

  # Fetch userinfo -------------------------------------------------------------

  # Fetch userinfo AFTER ID token validation. This ordering ensures we only
  # make external calls after cryptographic validation passes.

  if (isTRUE(oauth_client@provider@userinfo_required)) {
    userinfo <- get_userinfo(
      oauth_client,
      token = token_set[["access_token"]]
    )
    token_set[["userinfo"]] <- userinfo

    # Verify userinfo subject matches ID token subject (if configured).
    # ID token is guaranteed present here: verify_token_set() already enforces
    # id_token_required when userinfo_id_token_match = TRUE (see line ~1303).
    if (isTRUE(oauth_client@provider@userinfo_id_token_match)) {
      verify_userinfo_id_token_subject_match(
        oauth_client,
        userinfo = userinfo,
        id_token = token_set[["id_token"]]
      )
    }
  }

  # Return ---------------------------------------------------------------------

  # Turn into OAuthToken & return

  token <- OAuthToken(
    access_token = token_set[["access_token"]] %||%
      err_token("Token response missing access_token"),
    refresh_token = token_set$refresh_token %||% NA_character_,
    expires_at = if (
      is.numeric(token_set$expires_in) && is.finite(token_set$expires_in)
    ) {
      as.numeric(Sys.time()) + as.numeric(token_set$expires_in)
    } else {
      resolve_missing_expires_in(phase = "exchange_code")
    },
    id_token = token_set$id_token %||% NA_character_,
    id_token_validated = isTRUE(token_set[[".id_token_validated"]])
  )
  # Set userinfo separately for compatibility with some S7 dispatchers
  token@userinfo <- token_set$userinfo %||% list()

  # Optional token introspection validation -----------------------------------

  if (isTRUE(introspect)) {
    intro_res <- introspect_token(
      oauth_client = oauth_client,
      oauth_token = token,
      which = "access",
      async = FALSE
    )

    # Fail login if introspection is unsupported when requested

    if (!isTRUE(intro_res$supported)) {
      err_token(c(
        "x" = "Token introspection required but provider does not support it",
        "i" = "Set `introspect = FALSE` or configure an introspection_url on the provider"
      ))
    }

    # Fail login if token is not active
    if (!isTRUE(intro_res$active)) {
      err_token(c(
        "x" = "Token introspection indicates the access token is not active",
        "i" = paste0("Introspection status: ", intro_res$status %||% "unknown")
      ))
    }

    ## Extra requirements for token introspection ------------------------------

    raw <- intro_res$raw %||% list()
    if (!is.list(raw)) {
      raw <- list()
    }

    # client_id requirement
    if ("client_id" %in% introspect_elements) {
      cid <- raw$client_id %||% NA_character_
      if (!is_valid_string(cid)) {
        err_token(c(
          "x" = "Token introspection response missing required client_id",
          "i" = "Disable this check or ensure your provider returns client_id in introspection"
        ))
      }
      if (
        !identical(
          as.character(cid)[1],
          as.character(oauth_client@client_id)[1]
        )
      ) {
        err_token(c(
          "x" = "Token introspection client_id does not match configured client_id",
          "!" = paste0("Got: ", as.character(cid)[1])
        ))
      }
    }

    # sub requirement (binds access token identity to ID token or userinfo)
    if ("sub" %in% introspect_elements) {
      intro_sub <- raw$sub %||% NA_character_
      if (!is_valid_string(intro_sub)) {
        err_token(c(
          "x" = "Token introspection response missing required sub",
          "i" = "Disable this check or ensure your provider returns sub in introspection"
        ))
      }

      expected_sub <- NA_character_
      # Prefer ID token subject if present
      if (is_valid_string(token@id_token)) {
        pl <- try(parse_jwt_payload(token@id_token), silent = TRUE)
        if (!inherits(pl, "try-error")) {
          expected_sub <- pl$sub %||% NA_character_
        }
      }
      # Fallback: userinfo subject
      if (!is_valid_string(expected_sub)) {
        ui <- token@userinfo %||% list()
        if (is.list(ui)) {
          expected_sub <- ui$sub %||% NA_character_
        }
      }

      if (!is_valid_string(expected_sub)) {
        err_token(c(
          "x" = "Cannot validate introspection sub: no subject is available from ID token or userinfo",
          "i" = "Enable ID token validation and/or userinfo, or disable the sub requirement"
        ))
      }

      if (
        !identical(as.character(intro_sub)[1], as.character(expected_sub)[1])
      ) {
        err_token(c(
          "x" = "Token introspection sub does not match authenticated subject",
          "i" = "This may indicate a provider inconsistency or a token mix-up"
        ))
      }
    }

    # scope requirement
    if ("scope" %in% introspect_elements) {
      scope_validation_mode <- oauth_client@scope_validation %||% "strict"

      # Mirror token response scope reconciliation behavior:
      # - "none": skip scope checks
      # - "warn": warn (do not fail login)
      # - "strict": error
      requested_scopes <- as_scope_tokens(oauth_client@scopes %||% NULL)
      requested_scopes <- sort(unique(requested_scopes[nzchar(
        requested_scopes
      )]))

      if (
        !identical(scope_validation_mode, "none") &&
          length(requested_scopes) > 0
      ) {
        intro_scope_raw <- raw$scope %||% NULL

        if (is.null(intro_scope_raw)) {
          msg <- "Token introspection response missing scope; cannot validate requested scopes"
          if (identical(scope_validation_mode, "strict")) {
            err_token(c(
              "x" = msg,
              "i" = "Set scope_validation = 'warn' or 'none', or disable the scope introspection requirement"
            ))
          } else if (identical(scope_validation_mode, "warn")) {
            rlang::warn(
              c(
                "!" = msg,
                "i" = "Set scope_validation = 'none' to suppress this warning"
              ),
              .frequency = "once",
              .frequency_id = "introspection-scope-validation-missing-scope"
            )
          }
        } else {
          # Normalize scope to vector (providers may return space- or comma-separated scopes)
          if (length(intro_scope_raw) == 1L) {
            if (
              grepl(",", intro_scope_raw, fixed = TRUE) &&
                !grepl(" ", intro_scope_raw, fixed = TRUE)
            ) {
              intro_scopes <- unlist(
                strsplit(intro_scope_raw, ",", fixed = TRUE),
                use.names = FALSE
              )
            } else {
              intro_scopes <- unlist(
                strsplit(intro_scope_raw, " ", fixed = TRUE),
                use.names = FALSE
              )
            }
          } else {
            intro_scopes <- as.character(intro_scope_raw)
          }
          intro_scopes <- sort(unique(intro_scopes[nzchar(intro_scopes)]))

          missing <- setdiff(requested_scopes, intro_scopes)
          if (length(missing) > 0) {
            msg <- paste0(
              "Introspected scopes missing requested entries: ",
              paste(missing, collapse = ", ")
            )
            if (identical(scope_validation_mode, "strict")) {
              err_token(c(
                "x" = msg,
                "i" = "Set scope_validation = 'warn' or 'none' to allow reduced scopes"
              ))
            } else if (identical(scope_validation_mode, "warn")) {
              rlang::warn(
                c(
                  "!" = msg,
                  "i" = "Set scope_validation = 'none' to suppress this warning"
                ),
                .frequency = "once",
                .frequency_id = "introspection-scope-validation-missing-scopes"
              )
            }
          }
        }
      }
    }
  }

  # Audit: login success with redacted identifiers
  try(
    {
      # Best-effort subject extraction: prefer userinfo via selector, else ID token sub
      # Track source for audit transparency (userinfo is trusted; ID token may not be)
      sub_val <- NA_character_
      sub_source <- NA_character_
      if (!is.null(token@userinfo) && length(token@userinfo)) {
        sel <- oauth_client@provider@userinfo_id_selector
        if (!is.null(sel) && is.function(sel)) {
          sub_val <- try(sel(token@userinfo), silent = TRUE)
          if (inherits(sub_val, "try-error")) sub_val <- NA_character_
        } else {
          sub_val <- token@userinfo$sub %||% NA_character_
        }
        if (is_valid_string(sub_val)) sub_source <- "userinfo"
      }
      if (!is_valid_string(sub_val)) {
        # Attempt parse id_token payload for sub (without revalidation)
        it <- token@id_token
        if (is_valid_string(it)) {
          pl <- try(parse_jwt_payload(it), silent = TRUE)
          if (!inherits(pl, "try-error")) {
            sub_val <- pl$sub %||% NA_character_
            if (is_valid_string(sub_val)) {
              # Mark whether ID token was validated (signature + claims checked)
              id_token_was_validated <- isTRUE(
                oauth_client@provider@id_token_validation
              ) ||
                isTRUE(oauth_client@provider@use_nonce)
              sub_source <- if (id_token_was_validated) {
                "id_token"
              } else {
                "id_token_unverified"
              }
            }
          }
        }
      }
      audit_event(
        "login_success",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = string_digest(sub_val),
          sub_source = sub_source,
          refresh_token_present = isTRUE(is_valid_string(token@refresh_token)),
          expires_at = token@expires_at
        ),
        shiny_session = shiny_session
      )
    },
    silent = TRUE
  )

  return(token)
}

# Verify payload is not too old
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

# Verify match of client_id, redirect_uri, scopes, and provider fingerprint
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

  expected_scopes <- as_scope_tokens(client@scopes %||% NULL)
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

swap_code_for_token_set <- function(
  client,
  code,
  code_verifier
) {
  S7::check_is_S7(client, class = OAuthClient)

  params <- list(
    grant_type = "authorization_code",
    code = code,
    redirect_uri = client@redirect_uri,
    code_verifier = code_verifier
  )

  if (length(client@provider@extra_token_params) > 0) {
    params <- c(params, client@provider@extra_token_params)
  }

  req <- httr2::request(client@provider@token_url)

  tas <- client@provider@token_auth_style %||% "header"
  if (identical(tas, "header")) {
    req <- req |>
      httr2::req_auth_basic(client@client_id, client@client_secret)
  } else if (identical(tas, "body")) {
    params$client_id <- client@client_id
    # Only include client_secret if provided (public clients with PKCE may not have one)
    if (is_valid_string(client@client_secret)) {
      params$client_secret <- client@client_secret
    }
  } else if (
    identical(tas, "client_secret_jwt") || identical(tas, "private_key_jwt")
  ) {
    params$client_id <- client@client_id
    params$client_assertion_type <-
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    params$client_assertion <- build_client_assertion(
      client,
      aud = resolve_client_assertion_audience(client, req)
    )
  }

  # Apply defaults first; disable redirects to prevent leaking secrets
  req <- add_req_defaults(req)
  req <- req_no_redirect(req)

  # Add any extra token headers without using rlang splicing so tests can stub
  extra_headers <- as.list(client@provider@extra_token_headers)
  if (length(extra_headers) > 0) {
    req <- do.call(httr2::req_headers, c(list(req), extra_headers))
  }

  # Drop NULL entries (e.g., code_verifier when PKCE disabled) before adding form body
  params <- Filter(function(x) !is.null(x), params)

  # Add form body without using !!! so it works with simple stubs
  req <- do.call(httr2::req_body_form, c(list(req), params))

  # Perform request with retry for transient failures
  resp <- req_with_retry(req)
  # Security: reject redirect responses to prevent credential leakage
  reject_redirect_response(resp, context = "token_exchange")
  if (httr2::resp_is_error(resp)) {
    err_http(
      "Token exchange failed",
      resp,
      context = list(phase = "exchange_code")
    )
  }

  token_set <- parse_token_response(resp)

  # Some providers return expires_in as a character string (e.g., form-encoded
  # responses or JSON where the value is quoted). Convert digit-only strings to
  # numeric prior to validation to avoid false negatives.
  if (!is.null(token_set$expires_in)) {
    token_set$expires_in <- coerce_expires_in(token_set$expires_in)
  }

  # Verify 'access_token' is present in response
  if (!is_valid_string(token_set[["access_token"]])) {
    err_token("Token response missing access_token")
  }

  # If ID token is required, verify it's present
  if (
    (isTRUE(client@provider@id_token_required) ||
      isTRUE(client@provider@id_token_validation)) &&
      !is_valid_string(token_set[["id_token"]])
  ) {
    err_id_token("ID token required but missing from token response")
  }

  # Verify expires at is valid if present
  if (!is.null(token_set$expires_in)) {
    if (
      !is.numeric(token_set$expires_in) ||
        length(token_set$expires_in) != 1L ||
        !is.finite(token_set$expires_in) ||
        token_set$expires_in < 0
    ) {
      err_token("Invalid expires_in in token response")
    }

    if (token_set$expires_in <= 0) {
      warn_about_nonpositive_expires_in(
        token_set$expires_in,
        phase = "exchange_code"
      )
    }
  }

  return(token_set)
}

verify_token_set <- function(
  client,
  token_set,
  nonce,
  is_refresh = FALSE,
  original_id_token = NULL
) {
  # Helpers/types --------------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(token_set) || length(token_set) == 0) {
    err_token("Invalid token set: must be a non-empty list")
  }

  verify_token_type_allowlist(client, token_set)

  # Scope reconciliation --------------------------------------------------------

  # If requested scopes exist, verify the provider returned them (or a superset).
  # RFC 6749 Section 3.3 allows servers to reduce scopes; behavior is controlled
  # by client@scope_validation: "strict" (error), "warn", or "none" (skip).
  #
  # Refresh exception (RFC 6749 Section 6): providers MAY omit scope from refresh
  # responses when unchanged. When is_refresh=TRUE and scope is NULL, we skip
  # validation entirely—this is compliant behavior, not an error.
  #
  # Note: Some providers omit scope from the token response entirely. In strict
  # mode this is treated as an error (we cannot verify scopes were granted);
  # in warn mode we issue a warning.
  scope_validation_mode <- client@scope_validation %||% "strict"
  requested_scopes <- as_scope_tokens(client@scopes %||% NULL)
  requested_scopes <- sort(unique(requested_scopes[nzchar(requested_scopes)]))

  # Helper to check if scope is missing or empty (some providers return "" for unset)
  scope_is_missing <- is.null(token_set$scope) ||
    (length(token_set$scope) == 1L && !nzchar(token_set$scope))

  # Skip scope validation during refresh when provider omits scope (or returns empty)
  # Per RFC 6749 Section 6, omitted scope in refresh response = unchanged from original
  if (
    !identical(scope_validation_mode, "none") &&
      length(requested_scopes) > 0 &&
      !(isTRUE(is_refresh) && scope_is_missing)
  ) {
    if (scope_is_missing) {
      # Provider did not return scope — we cannot verify requested scopes were granted
      msg <- "Token response missing scope; cannot verify requested scopes were granted"
      if (identical(scope_validation_mode, "strict")) {
        err_token(c(
          "x" = msg,
          "i" = "Set scope_validation = 'warn' or 'none' to allow missing scope in response"
        ))
      } else if (identical(scope_validation_mode, "warn")) {
        rlang::warn(
          c(
            "!" = msg,
            "i" = "Set scope_validation = 'none' to suppress this warning"
          ),
          .frequency = "once",
          .frequency_id = "scope-validation-missing-scope"
        )
      }
    } else {
      granted_raw <- token_set$scope
      # Providers may return space- or comma-separated scopes; normalize to vector
      if (length(granted_raw) == 1L) {
        # Prefer space separation per RFC; fall back to comma when spaces absent
        if (
          grepl(",", granted_raw, fixed = TRUE) &&
            !grepl(" ", granted_raw, fixed = TRUE)
        ) {
          granted <- unlist(
            strsplit(granted_raw, ",", fixed = TRUE),
            use.names = FALSE
          )
        } else {
          granted <- unlist(
            strsplit(granted_raw, " ", fixed = TRUE),
            use.names = FALSE
          )
        }
      } else {
        granted <- as.character(granted_raw)
      }
      granted <- sort(unique(granted[nzchar(granted)]))
      missing <- setdiff(requested_scopes, granted)
      if (length(missing) > 0) {
        msg <- paste0(
          "Granted scopes missing requested entries: ",
          paste(missing, collapse = ", ")
        )
        if (identical(scope_validation_mode, "strict")) {
          err_token(c(
            "x" = msg,
            "i" = "Set scope_validation = 'warn' or 'none' to allow reduced scopes"
          ))
        } else if (identical(scope_validation_mode, "warn")) {
          rlang::warn(
            c(
              "!" = msg,
              "i" = "Set scope_validation = 'none' to suppress this warning"
            ),
            .frequency = "once",
            .frequency_id = "scope-validation-missing-scopes"
          )
        }
      }
    }
  }

  # ID token -------------------------------------------------------------------

  # Check that it is present if required
  id_token_present <- isTRUE(is_valid_string(token_set[["id_token"]]))

  # Strict refresh policy: if a refresh response includes an ID token, we
  # require an original ID token from the initial login so we can enforce
  # OIDC Core section 12.2 subject continuity (sub MUST match). Without an original
  # token, we cannot bind identity across refresh and must reject.
  if (
    isTRUE(is_refresh) &&
      isTRUE(id_token_present) &&
      !is_valid_string(original_id_token)
  ) {
    err_id_token(
      "Refresh returned an ID token but no original ID token is available to verify sub claim (OIDC 12.2)"
    )
  }

  # ID token is required when (only during initial login, not refresh):
  # - id_token_required = TRUE
  # - id_token_validation = TRUE
  # - userinfo_id_token_match = TRUE (need both to compare subjects)
  # - nonce was sent (must validate nonce claim in ID token)
  # During refresh, none of these apply. OIDC Core Section 12.2 allows refresh
  # responses to omit the ID token. Identity was already established at login.
  id_token_required <- !isTRUE(is_refresh) &&
    (isTRUE(client@provider@id_token_required) |
      isTRUE(client@provider@id_token_validation) |
      isTRUE(client@provider@userinfo_id_token_match) |
      isTRUE(is_valid_string(nonce)))

  if (isTRUE(id_token_required) && !isTRUE(id_token_present)) {
    err_id_token("ID token required but not present")
  }

  # OIDC Core 12.2: During refresh, if a new ID token is returned, its sub
  # claim MUST match the original. We always enforce this sub continuity when
  # a refresh returns an ID token, even if signature/claim validation is
  # disabled (id_token_validation = FALSE).
  expected_sub <- NULL
  original_iss <- NULL
  original_aud <- NULL
  should_validate_id_token <- isTRUE(id_token_present) &&
    (isTRUE(client@provider@id_token_validation) ||
      isTRUE(client@provider@use_nonce) ||
      isTRUE(is_valid_string(nonce)))

  # Track whether the ID token was actually validated for downstream consumers.
  # This flag starts FALSE and is set to TRUE only when validate_id_token()
  # succeeds (i.e. signature + claims are cryptographically verified).
  id_token_validated <- FALSE

  id_token <- token_set[["id_token"]]
  if (isTRUE(is_refresh) && isTRUE(id_token_present)) {
    original_payload <- tryCatch(
      parse_jwt_payload(original_id_token),
      error = function(e) NULL
    )
    # Security: if we have an original ID token but can't extract its sub,
    # that's an error - don't silently skip the check.
    if (is.null(original_payload)) {
      err_id_token(
        "Cannot parse original ID token to verify sub claim (OIDC 12.2)"
      )
    }
    if (!is_valid_string(original_payload$sub)) {
      err_id_token("Original ID token missing sub claim (OIDC 12.2)")
    }
    expected_sub <- original_payload$sub

    # OIDC Core 12.2: extract original iss and aud for cross-comparison.
    # The new ID token's iss and aud MUST match the original's actual values,
    # not just the provider config. This guards against multi-tenant issuers
    # that rotate issuer URIs or aud arrays that include extra audiences.
    original_iss <- original_payload$iss
    original_aud <- original_payload$aud

    if (!isTRUE(should_validate_id_token)) {
      # Even when full ID token validation is disabled (id_token_validation = FALSE),
      # we still must enforce OIDC 12.2 subject continuity on refresh when the
      # provider returns an ID token. That requires parsing the (unsigned/unchecked)
      # payload so we can compare its sub claim to the original.
      new_payload <- tryCatch(
        parse_jwt_payload(id_token),
        error = function(e) NULL
      )
      if (is.null(new_payload)) {
        err_id_token(
          "Cannot parse refreshed ID token to verify sub claim (OIDC 12.2)"
        )
      }
      if (!is_valid_string(new_payload$sub)) {
        err_id_token("Refreshed ID token missing sub claim (OIDC 12.2)")
      }
      if (!identical(new_payload$sub, expected_sub)) {
        err_id_token(
          "Refresh returned an ID token with sub that does not match the original (OIDC 12.2)"
        )
      }
      # OIDC Core 12.2: iss MUST be the same as in the original ID token.
      # Strict string equality — no trailing-slash normalization.
      if (
        is_valid_string(original_iss) &&
          !identical(new_payload$iss %||% "", original_iss)
      ) {
        err_id_token(
          "Refresh returned an ID token with iss that does not match the original (OIDC 12.2)"
        )
      }
      # OIDC Core 12.2: aud MUST be the same as in the original ID token.
      if (
        !is.null(original_aud) &&
          !identical(
            sort(as.character(new_payload$aud %||% character())),
            sort(as.character(original_aud))
          )
      ) {
        err_id_token(
          "Refresh returned an ID token with aud that does not match the original (OIDC 12.2)"
        )
      }
    }
  }

  # Validate ID token when present and validation is requested.
  # Covers: id_token_validation, use_nonce, or explicit nonce passed.
  if (isTRUE(should_validate_id_token)) {
    # Verifies signature & claims of ID token
    # Will error if invalid
    # OIDC Core §3.1.2.1: when max_age was requested in extra_auth_params,
    # pass it to validate_id_token() so auth_time is enforced.
    requested_max_age <- NULL
    if (!isTRUE(is_refresh)) {
      ma <- client@provider@extra_auth_params[["max_age"]]
      if (!is.null(ma)) {
        requested_max_age <- suppressWarnings(as.numeric(ma))
        if (
          is.na(requested_max_age) ||
            !is.finite(requested_max_age) ||
            requested_max_age < 0
        ) {
          requested_max_age <- NULL
        }
      }
    }
    validate_id_token(
      client,
      id_token,
      expected_nonce = nonce,
      expected_sub = expected_sub,
      expected_access_token = token_set[["access_token"]],
      max_age = requested_max_age
    )

    # If we reach this point, validate_id_token() succeeded —
    # the ID token's signature and claims were cryptographically verified.
    id_token_validated <- TRUE

    # OIDC Core 12.2: during refresh, verify iss and aud match the original
    # ID token's actual values (not just the provider config). validate_id_token()
    # already checks iss == provider@issuer and client_id %in% aud, but 12.2
    # additionally requires exact match against the original token's claims.
    # Parse the new token payload directly (rather than depending on the return
    # value of validate_id_token) so the check is robust regardless of mocking.
    if (isTRUE(is_refresh) && !is.null(original_iss)) {
      new_payload_for_iss_aud <- tryCatch(
        parse_jwt_payload(id_token),
        error = function(e) NULL
      )
      if (!is.null(new_payload_for_iss_aud)) {
        if (
          is_valid_string(original_iss) &&
            !identical(new_payload_for_iss_aud$iss %||% "", original_iss)
        ) {
          err_id_token(
            "Refresh returned an ID token with iss that does not match the original (OIDC 12.2)"
          )
        }
        if (
          !is.null(original_aud) &&
            !identical(
              sort(as.character(new_payload_for_iss_aud$aud %||% character())),
              sort(as.character(original_aud))
            )
        ) {
          err_id_token(
            "Refresh returned an ID token with aud that does not match the original (OIDC 12.2)"
          )
        }
      }
    }
  }

  # Validate match between userinfo & ID token ---------------------------------

  # During initial login (is_refresh = FALSE): this check is now performed by
  # handle_callback() AFTER userinfo is fetched, not here. This function is
  # called before userinfo fetch in the new flow, so we skip this check.
  # During refresh: validate only if BOTH userinfo and id_token are present.
  # (userinfo is fetched when userinfo_required = TRUE; id_token may be omitted
  # per OIDC 12.2). When both are available, verify subjects still match.

  if (isTRUE(is_refresh)) {
    id_token_present <- is_valid_string(token_set[["id_token"]])
    userinfo_present <- is.list(token_set[["userinfo"]]) &&
      length(token_set[["userinfo"]]) > 0

    should_match <- isTRUE(client@provider@userinfo_id_token_match) &&
      id_token_present &&
      userinfo_present

    if (should_match) {
      verify_userinfo_id_token_subject_match(
        client,
        userinfo = token_set[["userinfo"]],
        id_token = token_set[["id_token"]]
      )
    }
  }

  # Attach the validation flag so callers can propagate it to OAuthToken.
  token_set[[".id_token_validated"]] <- id_token_validated

  return(token_set)
}

verify_token_type_allowlist <- function(client, token_set) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(token_set)) {
    err_token("Invalid token set: must be a list")
  }

  # Token type guardrail -------------------------------------------------------
  # Policy:
  # - If provider@allowed_token_types is empty (length 0 or NULL), we do not
  #   enforce token_type presence or value (provider may omit it).
  # - If allowed_token_types is non-empty, token_type MUST be present and one
  #   of the allowed values (case-insensitive).
  allowed_vec <- client@provider@allowed_token_types %||% character(0)
  if (length(allowed_vec) > 0) {
    tt <- token_set$token_type
    if (is.null(tt)) {
      err_token("Token response missing token_type")
    }
    tt <- as.character(tt)[1]
    if (!is_valid_string(tt)) {
      err_token("Invalid token_type in token response")
    }
    allowed <- tolower(as.character(allowed_vec))
    if (!tolower(tt) %in% allowed) {
      err_token(c(
        "x" = "Unsupported token_type received",
        "!" = paste0("Got: ", tt),
        "i" = paste0(
          "Expected one of: ",
          paste(unique(allowed_vec), collapse = ", ")
        )
      ))
    }
  }

  invisible(TRUE)
}
