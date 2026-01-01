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
  iss <- provider@issuer %||% ""
  au <- provider@auth_url %||% ""
  tu <- provider@token_url %||% ""

  # Use a length-prefixed canonical representation to avoid delimiter-based
  # collisions when any component contains separators.
  iss_u <- enc2utf8(iss)
  au_u <- enc2utf8(au)
  tu_u <- enc2utf8(tu)

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
    tu_u
  )

  paste0("sha256:", string_digest(enc2utf8(canonical)))
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

  stopifnot(
    is_valid_string(payload),
    (isTRUE(oauth_client@provider@use_pkce) &&
      is_valid_string(pkce_code_challenge) &&
      is_valid_string(pkce_method)) ||
      (isFALSE(oauth_client@provider@use_pkce) &&
        is.null(pkce_code_challenge) &&
        is.null(pkce_method)),
    (isTRUE(oauth_client@provider@use_nonce) && is_valid_string(nonce)) ||
      (isFALSE(oauth_client@provider@use_nonce) && is.null(nonce))
  )

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

  if (length(oauth_client@scopes) > 0) {
    params$scope <- paste(oauth_client@scopes, collapse = " ")
  }
  if (length(oauth_client@provider@extra_auth_params) > 0) {
    params <- c(params, oauth_client@provider@extra_auth_params)
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
#' @param decrypted_payload Optional pre-decrypted and validated payload list
#'   (as returned by `state_decrypt_gcm()` followed by internal validation).
#'   Supplying this allows callers to validate and bind the state on the main
#'   thread before dispatching to a background worker for async flows.
#' @param state_store_values Optional pre-fetched state store entry (a list with
#'   `browser_token`, `pkce_code_verifier`, and `nonce`). When supplied, the
#'   function will skip reading/removing from `oauth_client@state_store` and use
#'   the provided values instead. This supports async flows that prefetch and
#'   remove the single-use state entry on the main thread to avoid cross-process
#'   cache visibility issues.
#'
#' @return An [OAuthToken]` object containing the access token, refresh token,
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
  decrypted_payload = NULL,
  state_store_values = NULL
) {
  # Type checks ----------------------------------------------------------------

  S7::check_is_S7(oauth_client, class = OAuthClient)

  # Validate required callback params without leaking raw assertion messages
  if (!is_valid_string(code)) {
    err_invalid_state("Callback missing authorization code")
  }
  if (!is_valid_string(payload)) {
    err_invalid_state("Callback missing state payload")
  }
  # (Browser token gets validated below)

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
        )
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
    payload <- state_payload_decrypt_validate(oauth_client, payload)
  }

  # Retrieve state_info from state store ---------------------------------------
  # State is the key; value is a list with browser_token, pkce_code_verifier, nonce
  if (is.null(state_store_values)) {
    # Centralized auditing for state store lookup occurs in state_store_get_remove()
    state_store_values <- state_store_get_remove(oauth_client, payload$state)
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
          )
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
      if (
        isTRUE(oauth_client@provider@use_pkce) &&
          !validate_code_verifier(code_verifier)
      ) {
        err_invalid_state(
          "Missing (valid) PKCE code verifier in state store values"
        )
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
          )
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
          )
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
          )
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

  # Fetch userinfo -------------------------------------------------------------

  if (isTRUE(oauth_client@provider@userinfo_required)) {
    userinfo <- get_userinfo(
      oauth_client,
      token = token_set[["access_token"]]
    )

    token_set[["userinfo"]] <- userinfo
  }

  # Verify token ---------------------------------------------------------------

  # Verify nonce is present if needed
  nonce <- state_store_values$nonce
  tryCatch(
    {
      if (oauth_client@provider@use_nonce && !validate_oidc_nonce(nonce)) {
        err_invalid_state("Missing (valid) nonce in state store values")
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
          )
        ),
        silent = TRUE
      )
      rlang::abort(message = conditionMessage(e), parent = e)
    }
  )

  # Now verify + modify token_set as needed
  # If userinfo is requested, will also fetch user info and add to token_set
  # If OIDC ID token, will validate its signature + claims (including nonce)
  # If userinfo & OIDC ID token, verify the subject matches
  token_set <- verify_token_set(
    oauth_client,
    token_set = token_set,
    nonce = nonce
  )

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
      Inf
    },
    id_token = token_set$id_token %||% NA_character_
  )
  # Set userinfo separately for compatibility with some S7 dispatchers
  token@userinfo <- token_set$userinfo %||% list()

  # Audit: login success with redacted identifiers
  try(
    {
      # Best-effort subject extraction: prefer userinfo via selector, else ID token sub
      sub_val <- NA_character_
      if (!is.null(token@userinfo) && length(token@userinfo)) {
        sel <- oauth_client@provider@userinfo_id_selector
        if (!is.null(sel) && is.function(sel)) {
          sub_val <- try(sel(token@userinfo), silent = TRUE)
          if (inherits(sub_val, "try-error")) sub_val <- NA_character_
        } else {
          sub_val <- token@userinfo$sub %||% NA_character_
        }
      }
      if (!is_valid_string(sub_val)) {
        # Attempt parse id_token payload for sub (without revalidation)
        it <- token@id_token
        if (is_valid_string(it)) {
          pl <- try(parse_jwt_payload(it), silent = TRUE)
          if (!inherits(pl, "try-error")) {
            sub_val <- pl$sub %||% NA_character_
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
          refresh_token_present = isTRUE(is_valid_string(token@refresh_token)),
          expires_at = token@expires_at
        )
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

  # Compute age in seconds using double math (robust even after 2038)
  age <- as.numeric(Sys.time()) - as.numeric(ia)

  if (age < 0) {
    err_invalid_state("Invalid payload: issued_at is in the future")
  }
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
      aud = client@provider@token_url
    )
  }

  # Apply defaults first
  req <- add_req_defaults(req)

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

verify_token_set <- function(client, token_set, nonce) {
  # Helpers/types --------------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(token_set) || length(token_set) == 0) {
    err_token("Invalid token set: must be a non-empty list")
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

  # Scope reconciliation --------------------------------------------------------
  # If the provider returned granted scopes, ensure all requested scopes are present.
  # RFC 6749 allows servers to reduce scopes; we choose to fail fast to avoid
  # surprising downstream authorization failures.
  requested_scopes <- as.character(client@scopes %||% character())
  if (length(requested_scopes) > 0 && !is.null(token_set$scope)) {
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
    requested <- sort(unique(as.character(requested_scopes[nzchar(
      requested_scopes
    )])))
    missing <- setdiff(requested, granted)
    if (length(missing) > 0) {
      err_token(paste0(
        "Granted scopes missing requested entries: ",
        paste(missing, collapse = ", ")
      ))
    }
  }

  # ID token -------------------------------------------------------------------

  # Check if ID token is required
  id_token_required <- isTRUE(client@provider@id_token_validation) |
    isTRUE(client@provider@id_token_required) |
    isTRUE(client@provider@userinfo_id_token_match) |
    isTRUE(is_valid_string(nonce))

  # Check that it is present if required
  id_token_present <- isTRUE(is_valid_string(token_set[["id_token"]]))

  if (isTRUE(id_token_required) && !isTRUE(id_token_present)) {
    err_id_token("ID token required but not present")
  }

  if (
    isTRUE(client@provider@id_token_validation) ||
      isTRUE(client@provider@use_nonce) ||
      isTRUE(is_valid_string(nonce))
  ) {
    id_token <- token_set[["id_token"]]
    # Verifies signature & claims of ID token
    # Will error if invalid
    validate_id_token(client, id_token, expected_nonce = nonce)
  }

  # Validate match between userinfo & ID token ---------------------------------

  if (isTRUE(client@provider@userinfo_id_token_match)) {
    verify_userinfo_id_token_subject_match(
      client,
      userinfo = token_set[["userinfo"]],
      id_token = token_set[["id_token"]]
    )
  }

  return(token_set)
}
