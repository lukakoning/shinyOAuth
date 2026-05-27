# This file contains the functions that run the login and callback flow
# Used for building the browser redirect, processing the provider callback,
# exchanging the returned code for tokens, and validating identity data

# 1 Authorization request ------------------------------------------------------

## 1.1 Entry point -------------------------------------------------------------

#' Prepare a OAuth 2.0 authorization call and build an authorization URL
#'
#' Prepares an OAuth 2.0 authorization request and returns the browser redirect
#' URL. It generates the needed state, PKCE, and nonce values, stores the
#' one-time callback data, and builds the final authorization URL.
#'
#' @param oauth_client An [OAuthClient] object.
#' @param browser_token Browser-bound token used to tie the login attempt to the
#'   current browser session.
#' @param request_uri_publisher Optional function used when
#'   `request_object_mode = "request_uri"`. It must accept
#'   `request_object`, `request_handle_id`, `expires_at`, and `oauth_client`
#'   arguments and return an absolute request-object URL.
#'
#' @return A length-1 string containing the authorization URL to send the user
#'   to. When PAR is used, the returned string also carries
#'   `shinyOAuth.par_request_uri`, `shinyOAuth.par_expires_in`, and
#'   `shinyOAuth.par_expires_at` attributes so callers can tell when the pushed
#'   authorization request should be regenerated.
#'
#' @example inst/examples/call_methods.R
#'
#' @export
prepare_call <- function(
  oauth_client,
  browser_token,
  request_uri_publisher = NULL
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

  flow_trace_id <- gen_trace_id()
  effective_scopes <- effective_client_scopes(oauth_client)
  request_mode <- oauth_client@request_object_mode %||% "parameters"
  request_object_used <-
    is.character(request_mode) &&
    length(request_mode) == 1L &&
    !is.na(request_mode) &&
    request_mode %in% c("request", "request_uri")
  request_uri_used <-
    is.character(request_mode) &&
    length(request_mode) == 1L &&
    !is.na(request_mode) &&
    identical(request_mode, "request_uri")
  par_used <-
    is_valid_string(oauth_client@provider@par_url %||% NA_character_) &&
    !isTRUE(request_uri_used)
  with_trace_id(
    flow_trace_id,
    with_otel_span(
      "shinyOAuth.login.request",
      {
        login_span_headers <- otel_capture_context()

        # State, code_challenge & code_verifier, nonce -----------------------------

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

        # Create + seal (AES-GCM AEAD) payload ------------------------------------

        # We seal the payload using AES-GCM AEAD, which provides confidentiality and
        #   integrity via an authentication tag, preventing tampering.
        # We will include some details about the provider & client, to prevent
        #   possible mixups if multiple clients/providers are in use
        # We will include an issued_at timestamp, as extra protection against replay
        #   attacks (won't accept payloads older than some threshold)

        payload <- compact_list(list(
          state = state,
          client_id = oauth_client@client_id,
          redirect_uri = oauth_client@redirect_uri,
          scopes = effective_scopes,
          provider = oauth_client@provider |> provider_fingerprint(),
          client_policy = state_client_policy_fingerprint(oauth_client),
          issued_at = as.numeric(Sys.time()),
          trace_id = flow_trace_id,
          otel_login_span_headers = login_span_headers
        )) |>
          state_encrypt_gcm(key = oauth_client@state_key)

        # Store in state store -----------------------------------------------------

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

        # Build authorization URL --------------------------------------------------

        auth_url <- tryCatch(
          {
            build_auth_url(
              oauth_client = oauth_client,
              payload = payload,
              scopes = effective_scopes,
              pkce_code_challenge = pkce_code_challenge,
              pkce_method = pkce_method,
              nonce = nonce,
              request_uri_publisher = request_uri_publisher,
              request_handle_id = state_cache_key(state)
            )
          },
          error = function(e) {
            try(
              oauth_client@state_store$remove(state_cache_key(state)),
              silent = TRUE
            )
            stop(e)
          }
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
                par_used = isTRUE(par_used),
                request_object_used = isTRUE(request_object_used),
                request_uri_used = isTRUE(request_uri_used),
                nonce_present = isTRUE(oauth_client@provider@use_nonce),
                scopes_count = length(effective_scopes),
                redirect_uri = oauth_client@redirect_uri %||% NA_character_
              )
            )
          },
          silent = TRUE
        )

        auth_url
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        phase = "login.request",
        extra = list(
          oauth.used_pkce = isTRUE(oauth_client@provider@use_pkce),
          oauth.nonce_enabled = isTRUE(oauth_client@provider@use_nonce),
          oauth.scopes.requested = otel_scope_string(effective_scopes),
          oauth.scopes.requested_count = otel_scope_count(effective_scopes),
          oauth.claims.requested = otel_claims_requested(oauth_client@claims),
          oauth.claims.targets = otel_claim_targets(oauth_client@claims),
          oauth.required_acr_values = otel_required_acr_values(
            oauth_client@required_acr_values %||% character(0)
          ),
          oauth.required_acr_values_count = otel_count_items(
            oauth_client@required_acr_values %||% character(0)
          ),
          oauth.max_age.requested = otel_requested_max_age(
            oauth_client@provider
          ),
          oauth.request_object_used = isTRUE(request_object_used),
          oauth.request_uri_used = isTRUE(request_uri_used),
          oauth.extra_auth_params_count = otel_count_items(
            oauth_client@provider@extra_auth_params
          )
        )
      ),
      parent = NA
    )
  )
}

## 1.2 Request construction helpers --------------------------------------------

#' Build authorization request parameters
#'
#' Creates the parameter set sent to the provider's authorization endpoint for
#' plain redirects, signed request objects, and PAR flows. Used by
#' `build_auth_url()` once state, scope, PKCE, and nonce inputs are ready.
#'
#' @param oauth_client [OAuthClient] configuration.
#' @param payload Sealed state payload sent as the `state` parameter.
#' @param scopes Requested scopes, defaulting to the client's effective scopes
#'   when omitted.
#' @param pkce_code_challenge PKCE challenge when PKCE is enabled.
#' @param pkce_method PKCE method when PKCE is enabled.
#' @param nonce OIDC nonce when the provider requires one.
#' @return A named list of authorization parameters with `NULL` entries
#'   removed.
#' @keywords internal
#' @noRd
build_authorization_params <- function(
  oauth_client,
  payload,
  scopes,
  pkce_code_challenge,
  pkce_method,
  nonce
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is_valid_string(payload)) {
    err_invalid_state(
      "build_authorization_params: 'payload' must be a valid string"
    )
  }

  if (isTRUE(oauth_client@provider@use_pkce)) {
    if (
      !is_valid_string(pkce_code_challenge) || !is_valid_string(pkce_method)
    ) {
      err_invalid_state(
        paste(
          "build_authorization_params: PKCE is enabled but",
          "'pkce_code_challenge' or 'pkce_method' is missing or invalid"
        )
      )
    }
  } else if (!is.null(pkce_code_challenge) || !is.null(pkce_method)) {
    err_invalid_state(
      paste(
        "build_authorization_params: PKCE is disabled but",
        "'pkce_code_challenge' or 'pkce_method' was provided"
      )
    )
  }

  if (isTRUE(oauth_client@provider@use_nonce)) {
    if (!is_valid_string(nonce)) {
      err_invalid_state(
        paste(
          "build_authorization_params: Nonce is enabled but",
          "'nonce' is missing or invalid"
        )
      )
    }
  } else if (!is.null(nonce)) {
    err_invalid_state(
      "build_authorization_params: Nonce is disabled but 'nonce' was provided"
    )
  }

  if (missing(scopes)) {
    scopes <- effective_client_scopes(oauth_client)
  }

  params <- list(
    response_type = "code",
    client_id = oauth_client@client_id,
    redirect_uri = oauth_client@redirect_uri,
    state = payload
  )

  if (client_has_dpop(oauth_client)) {
    params[["dpop_jkt"]] <- compute_jwk_thumbprint(
      dpop_public_jwk(resolve_dpop_private_key(oauth_client))
    )
  }

  if (isTRUE(oauth_client@provider@use_pkce)) {
    params[["code_challenge"]] <- pkce_code_challenge
    params[["code_challenge_method"]] <- pkce_method
  }
  if (isTRUE(oauth_client@provider@use_nonce)) {
    params[["nonce"]] <- nonce
  }

  scopes <- as_scope_tokens(scopes %||% NULL)
  if (length(scopes) > 0) {
    params[["scope"]] <- paste(scopes, collapse = " ")
  }
  if (length(oauth_client@resource) > 0) {
    params[["resource"]] <- oauth_client@resource
  }

  # OIDC claims parameter (OIDC Core Section 5.5): JSON-encode claim lists while
  # preserving explicit null values used to request claims without parameters.
  if (!is.null(oauth_client@claims)) {
    if (is.list(oauth_client@claims)) {
      params[["claims"]] <- jsonlite::toJSON(
        oauth_client@claims,
        auto_unbox = TRUE,
        null = "null"
      )
    } else {
      params[["claims"]] <- oauth_client@claims
    }
  }

  # OIDC Core allows acr_values as a voluntary hint to the provider.
  racr <- oauth_client@required_acr_values %||% character(0)
  if (length(racr) > 0) {
    params[["acr_values"]] <- paste(racr, collapse = " ")
  }

  response_mode_info <- resolve_oauth_client_response_mode(oauth_client)
  if (!is.null(response_mode_info[["error"]])) {
    err_config(response_mode_info[["error"]])
  }

  explicit_response_mode <- response_mode_info[["explicit_mode"]]
  extra <- response_mode_info[["extra_auth_params"]]

  if (length(extra) > 0) {
    # Block overrides for security-critical parameters unless explicitly
    # unblocked. Allowing callers to replace these can break state binding,
    # redirect_uri validation, PKCE integrity, or PAR request indirection.
    default_blocked_params <- c(
      "state",
      "redirect_uri",
      "response_type",
      "client_id",
      "request_uri",
      "request",
      "scope",
      "nonce",
      "code_challenge",
      "code_challenge_method",
      "claims"
    )
    if (client_has_dpop(oauth_client)) {
      default_blocked_params <- c(default_blocked_params, "dpop_jkt")
    }
    if (length(racr) > 0) {
      default_blocked_params <- c(default_blocked_params, "acr_values")
    }
    unblocked <- tolower(trimws(getOption(
      "shinyOAuth.unblock_auth_params",
      character()
    )))
    blocked_params <- setdiff(default_blocked_params, unblocked)

    conflicts <- intersect(tolower(trimws(names(extra))), blocked_params)
    if (length(conflicts) > 0) {
      err_config(c(
        paste0(
          "OAuthProvider.extra_auth_params must not override core OAuth parameters: ",
          paste(conflicts, collapse = ", ")
        ),
        "i" = "These parameters are managed internally to ensure OAuth security.",
        "i" = "Set scopes via oauth_client(..., scopes = ...) and redirect_uri via oauth_client(..., redirect_uri = ...).",
        "i" = "To unblock, set `options(shinyOAuth.unblock_auth_params = c(...))`"
      ))
    }
    params <- c(params, extra)
  }

  if (!is.null(explicit_response_mode)) {
    params[["response_mode"]] <- explicit_response_mode
  }

  # Drop NULLs before building query strings or form bodies.
  compact_list(params)
}

#' Send a pushed authorization request
#'
#' Posts the prepared authorization parameters to the provider's PAR endpoint
#' and validates the returned `request_uri` payload. Used by `build_auth_url()`
#' when the provider requires or supports PAR.
#'
#' @param client [OAuthClient] used to resolve endpoints and client
#'   authentication.
#' @param params Prepared authorization parameters to POST.
#' @param shiny_session Optional Shiny session context for telemetry.
#' @return A list with `request_uri` and `expires_in`.
#' @keywords internal
#' @noRd
push_authorization_request <- function(client, params, shiny_session = NULL) {
  endpoint <- resolve_provider_endpoint_url(
    client@provider,
    "par_endpoint",
    prefer_mtls = client_uses_mtls_endpoint(client)
  ) %||%
    NA_character_
  if (!is_valid_string(endpoint)) {
    err_config(
      "Pushed authorization requests require provider@par_url"
    )
  }

  if ("request_uri" %in% tolower(trimws(names(params) %||% character(0)))) {
    err_config(
      "Pushed authorization request parameters must not include request_uri"
    )
  }

  with_otel_span(
    "shinyOAuth.login.par",
    {
      req <- httr2::request(endpoint)
      prepared <- apply_direct_client_auth(
        req = req,
        params = params,
        client = client,
        context = "pushed_authorization_request"
      )
      req <- prepared[["req"]]
      params <- prepared[["params"]]
      req <- req_apply_authorization_server_mtls(req, client)

      req <- add_req_defaults(req)
      req <- req_no_redirect(req)

      extra_headers <- as.list(client@provider@extra_token_headers)
      if (length(extra_headers) > 0) {
        req <- do.call(httr2::req_headers, c(list(req), extra_headers))
      }

      req <- req_body_form_encoded(req, compact_list(params))
      req <- req_refresh_jwt_client_assertion_on_retry(
        req = req,
        params = params,
        client = client,
        context = "pushed_authorization_request",
        body_mode = "encoded"
      )
      req <- httr2::req_method(req, "POST")

      resp <- with_otel_span(
        "shinyOAuth.login.par.http",
        {
          # PAR may allocate a fresh request_uri, but it does not consume the
          # single-use credentials that make token exchange or refresh unsafe
          # to replay after a nonce challenge.
          resp <- req_with_dpop_retry(req, client, idempotent = TRUE)
          otel_record_http_result(resp)
          resp
        },
        attributes = otel_http_attributes(
          method = "POST",
          url = endpoint,
          extra = c(
            list(oauth.phase = "login.par"),
            otel_mtls_endpoint_alias_attributes(
              provider = client@provider,
              endpoint = "par_endpoint",
              url = endpoint
            )
          )
        ),
        options = list(kind = "client"),
        mark_ok = FALSE
      )

      reject_redirect_response(resp, context = "pushed_authorization_request")
      if (httr2::resp_is_error(resp)) {
        err_http(
          "Pushed authorization request failed",
          resp,
          context = list(phase = "pushed_authorization_request")
        )
      }

      status <- httr2::resp_status(resp)
      if (!identical(as.integer(status), 201L)) {
        err_http(
          c(
            "x" = "Pushed authorization request response must use HTTP 201 Created",
            "i" = "RFC 9126 Section 2.2 requires status code 201 for successful PAR responses."
          ),
          resp,
          context = list(phase = "pushed_authorization_request")
        )
      }

      check_resp_body_size(resp, context = "pushed authorization request")
      content_type <- tolower(httr2::resp_header(resp, "content-type") %||% "")
      if (!grepl("^application/json(?:\\s*;|$)", content_type, perl = TRUE)) {
        err_parse(
          c(
            "x" = "Pushed authorization request response was not JSON",
            "i" = paste0("Content-Type: ", content_type %||% "")
          ),
          context = list(
            phase = "pushed_authorization_request",
            content_type = content_type
          )
        )
      }
      body_text <- httr2::resp_body_string(resp)
      out <- try_parse_token_response_json(body_text, resp = resp)
      if (!isTRUE(out[["ok"]])) {
        err_parse("Failed to parse pushed authorization request response")
      }
      if (!isTRUE(out[["is_object"]])) {
        err_parse(
          "Pushed authorization request response JSON must be a JSON object"
        )
      }
      out <- out[["value"]]

      request_uri <- out[["request_uri"]] %||% NULL
      expires_in <- out[["expires_in"]] %||% NULL

      if (!is_valid_string(request_uri)) {
        err_token(
          "Pushed authorization request response missing request_uri"
        )
      }
      if (
        !is.numeric(expires_in) ||
          length(expires_in) != 1L ||
          !is.finite(expires_in) ||
          expires_in <= 0
      ) {
        err_token(
          "Pushed authorization request response missing valid expires_in"
        )
      }
      if (!isTRUE(expires_in == floor(expires_in))) {
        err_token(
          "Pushed authorization request response expires_in must be a positive integer"
        )
      }

      list(request_uri = request_uri, expires_in = expires_in)
    },
    attributes = otel_client_attributes(
      client = client,
      shiny_session = shiny_session,
      phase = "login.par",
      extra = list(
        oauth.client_auth_style = otel_client_auth_style(client),
        oauth.extra_auth_params_count = otel_count_items(
          client@provider@extra_auth_params
        ),
        oauth.extra_token_headers_count = otel_count_items(
          client@provider@extra_token_headers
        )
      )
    )
  )
}

#' Attach PAR metadata to a browser authorization URL
#'
#' Preserves the PAR response lifetime alongside the returned redirect URL so
#' manual callers can regenerate stale request URIs before sending the browser.
#' Used by `build_auth_url()` after a successful pushed authorization request.
#'
#' @param auth_url Length-1 authorization URL string.
#' @param par_resp List returned by `push_authorization_request()`.
#' @param issued_at Optional numeric timestamp in seconds since the Unix epoch.
#'   Defaults to the current time.
#' @return `auth_url`, with PAR metadata attributes attached when possible.
#' @keywords internal
#' @noRd
attach_par_auth_url_metadata <- function(
  auth_url,
  par_resp,
  issued_at = as.numeric(Sys.time())
) {
  if (!is_valid_string(auth_url) || !is.list(par_resp)) {
    return(auth_url)
  }

  request_uri <- par_resp[["request_uri"]] %||% NULL
  expires_in <- par_resp[["expires_in"]] %||% NULL

  if (!is_valid_string(request_uri)) {
    return(auth_url)
  }
  if (
    !is.numeric(expires_in) ||
      length(expires_in) != 1L ||
      !is.finite(expires_in) ||
      expires_in <= 0
  ) {
    return(auth_url)
  }

  expires_in <- as.integer(expires_in)
  issued_at_num <- suppressWarnings(as.numeric(issued_at))
  expires_at <- if (length(issued_at_num) == 1L && is.finite(issued_at_num)) {
    structure(
      issued_at_num + as.numeric(expires_in),
      class = c("POSIXct", "POSIXt"),
      tzone = "UTC"
    )
  } else {
    NULL
  }

  structure(
    auth_url,
    `shinyOAuth.par_request_uri` = request_uri,
    `shinyOAuth.par_expires_in` = expires_in,
    `shinyOAuth.par_expires_at` = expires_at
  )
}

#' Build the browser authorization URL
#'
#' Chooses between plain query parameters, by-value Request Objects,
#' caller-managed `request_uri` values, and PAR, then returns the final browser
#' redirect URL for the login step. Used by
#' [prepare_call()] and module login helpers before the browser is redirected.
#'
#' @param oauth_client [OAuthClient] configuration.
#' @param payload Sealed state payload.
#' @param scopes Requested scopes.
#' @param pkce_code_challenge PKCE challenge when PKCE is enabled.
#' @param pkce_method PKCE method when PKCE is enabled.
#' @param nonce OIDC nonce when required.
#' @param request_uri_publisher Optional function used to publish Request
#'   Objects when `request_object_mode = "request_uri"`.
#' @param request_handle_id Optional stable handle identifier for
#'   `request_uri_publisher` implementations.
#' @return A length-1 authorization URL string. When PAR is used, the string
#'   also carries `shinyOAuth.par_request_uri`,
#'   `shinyOAuth.par_expires_in`, and `shinyOAuth.par_expires_at`
#'   attributes.
#' @keywords internal
#' @noRd
build_auth_url <- function(
  oauth_client,
  payload,
  scopes,
  pkce_code_challenge,
  pkce_method,
  nonce,
  request_uri_publisher = NULL,
  request_handle_id = NULL
) {
  warn_if_request_uri_is_long <- function(request_uri) {
    request_uri_len <- nchar(enc2utf8(request_uri), type = "bytes")

    if (!isTRUE(request_uri_len > 512L)) {
      return(invisible(NULL))
    }

    warn_pkg(
      "request_uri exceeds RFC 9101 guidance",
      c(
        "!" = paste0(
          "The published {.code request_uri} is ",
          request_uri_len,
          " bytes long."
        ),
        "i" = paste(
          "RFC 9101 Section 5.2 recommends keeping request_uri values at or",
          "below 512 ASCII characters for interoperability."
        )
      ),
      .frequency = "once",
      .frequency_id = "shinyOAuth_request_uri_over_512"
    )

    invisible(NULL)
  }

  request_mode <- oauth_client@request_object_mode %||% "parameters"
  request_object_used <-
    is.character(request_mode) &&
    length(request_mode) == 1L &&
    !is.na(request_mode) &&
    request_mode %in% c("request", "request_uri")
  request_uri_used <-
    is.character(request_mode) &&
    length(request_mode) == 1L &&
    !is.na(request_mode) &&
    identical(request_mode, "request_uri")
  if (
    isTRUE(request_uri_used) &&
      isTRUE(oauth_client@provider@par_required)
  ) {
    err_config(
      paste(
        "build_auth_url: request_object_mode = 'request_uri' cannot",
        "be used when the provider requires PAR"
      )
    )
  }
  par_used <-
    is_valid_string(oauth_client@provider@par_url %||% NA_character_) &&
    !isTRUE(request_uri_used)

  params <- build_authorization_params(
    oauth_client = oauth_client,
    payload = payload,
    scopes = scopes,
    pkce_code_challenge = pkce_code_challenge,
    pkce_method = pkce_method,
    nonce = nonce
  )
  front_channel_mode <-
    oauth_client@provider@authorization_request_front_channel_mode %||% "compat"
  oidc_outer_params_required <-
    is_valid_string(oauth_client@provider@issuer %||% NA_character_) &&
    (isTRUE(request_uri_used) ||
      (isTRUE(request_object_used) && !isTRUE(par_used)))
  if (
    identical(front_channel_mode, "minimal") &&
      isTRUE(oidc_outer_params_required)
  ) {
    err_config(
      paste(
        "build_auth_url: OpenID Connect request and caller-managed request_uri transports require",
        "authorization_request_front_channel_mode = 'compat';",
        "use PAR if you need a minimal browser URL"
      )
    )
  }
  front_channel_params <- if (
    identical(front_channel_mode, "compat") &&
      is_valid_string(oauth_client@provider@issuer %||% NA_character_)
  ) {
    compact_list(list(
      client_id = oauth_client@client_id,
      response_type = params[["response_type"]] %||% NULL,
      scope = params[["scope"]] %||% NULL
    ))
  } else {
    list(client_id = oauth_client@client_id)
  }

  if (isTRUE(request_object_used)) {
    request_object <- build_authorization_request_object(
      oauth_client,
      params
    )

    if (isTRUE(request_uri_used)) {
      if (!is.function(request_uri_publisher)) {
        err_config(
          paste(
            "build_auth_url: request_object_mode = 'request_uri'",
            "requires a request_uri_publisher"
          )
        )
      }

      request_expires_at <- Sys.time() +
        (oauth_client@request_object_ttl %||% 45)
      request_uri <- tryCatch(
        {
          request_uri_publisher(
            request_object = request_object,
            request_handle_id = request_handle_id,
            expires_at = request_expires_at,
            oauth_client = oauth_client
          )
        },
        error = function(e) {
          err_config(c(
            "x" = "Failed to publish request_uri authorization request",
            "i" = conditionMessage(e)
          ))
        }
      )

      if (!is_valid_string(request_uri)) {
        err_config(
          "build_auth_url: request_uri_publisher must return a non-empty absolute URL"
        )
      }

      parsed_request_uri <- try(httr2::url_parse(request_uri), silent = TRUE)
      if (
        inherits(parsed_request_uri, "try-error") ||
          !nzchar(parsed_request_uri[["scheme"]] %||% "") ||
          !nzchar(parsed_request_uri[["hostname"]] %||% "")
      ) {
        err_config(
          "build_auth_url: request_uri_publisher must return a non-empty absolute URL"
        )
      }

      validate_endpoint(
        request_uri,
        getOption("shinyOAuth.allowed_hosts", default = NULL)
      )
      warn_if_request_uri_is_non_https(
        request_uri,
        subject = "request_uri_publisher() result"
      )
      warn_if_request_uri_is_long(request_uri)

      return(url_append_query_params(
        oauth_client@provider@auth_url,
        c(
          front_channel_params,
          list(request_uri = request_uri)
        )
      ))
    }

    if (isTRUE(par_used)) {
      par_resp <- push_authorization_request(
        client = oauth_client,
        params = list(
          client_id = oauth_client@client_id,
          request = request_object
        )
      )

      if (!is_valid_string(par_resp[["request_uri"]])) {
        err_config("build_auth_url: PAR response missing valid request_uri")
      }
      warn_if_request_uri_is_long(par_resp[["request_uri"]])

      auth_url <- url_append_query_params(
        oauth_client@provider@auth_url,
        c(
          front_channel_params,
          list(request_uri = par_resp[["request_uri"]])
        )
      )

      return(attach_par_auth_url_metadata(auth_url, par_resp))
    }

    return(url_append_query_params(
      oauth_client@provider@auth_url,
      c(
        front_channel_params,
        list(request = request_object)
      )
    ))
  }

  if (isTRUE(par_used)) {
    par_resp <- push_authorization_request(
      client = oauth_client,
      params = params
    )

    if (!is_valid_string(par_resp[["request_uri"]])) {
      err_config("build_auth_url: PAR response missing valid request_uri")
    }

    auth_url <- url_append_query_params(
      oauth_client@provider@auth_url,
      c(
        front_channel_params,
        list(request_uri = par_resp[["request_uri"]])
      )
    )

    return(attach_par_auth_url_metadata(auth_url, par_resp))
  }

  url_append_query_params(oauth_client@provider@auth_url, params)
}

#' Recover callback parent tracing context
#'
#' Attempts to recover tracing metadata from the sealed login state so callback
#' spans can attach to the original login request. Used by [handle_callback()]
#' and [oauth_module_server()] when callback work resumes later in the flow.
#'
#' @param oauth_client [OAuthClient] used to validate and decrypt state.
#' @param encrypted_payload Encrypted callback state string.
#' @return A list with `trace_id` and `parent` entries.
#' @keywords internal
#' @noRd
otel_callback_parent_hint <- function(oauth_client, encrypted_payload) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!otel_tracing_enabled()) {
    return(list(trace_id = NULL, parent = NULL))
  }

  if (!is_valid_string(encrypted_payload)) {
    return(list(trace_id = NULL, parent = NULL))
  }

  payload_ok <- tryCatch(
    {
      validate_untrusted_query_param(
        "state",
        encrypted_payload,
        max_bytes = get_option_positive_number(
          "shinyOAuth.callback_max_state_bytes",
          8192
        )
      )
      TRUE
    },
    error = function(...) FALSE
  )
  if (!isTRUE(payload_ok)) {
    return(list(trace_id = NULL, parent = NULL))
  }

  payload <- tryCatch(
    {
      pld <- state_decrypt_gcm(encrypted_payload, key = oauth_client@state_key)
      payload_verify_issued_at(oauth_client, pld)
      if (
        !is_valid_string(pld[["client_id"]] %||% NULL) ||
          !identical(
            pld[["client_id"]],
            oauth_client@client_id
          )
      ) {
        NULL
      } else if (
        !is_valid_string(pld[["redirect_uri"]] %||% NULL) ||
          !identical(
            pld[["redirect_uri"]],
            oauth_client@redirect_uri
          )
      ) {
        NULL
      } else {
        pld
      }
    },
    error = function(...) NULL
  )
  if (is.null(payload)) {
    return(list(trace_id = NULL, parent = NULL))
  }

  list(
    trace_id = payload[["trace_id"]] %||% NULL,
    parent = otel_span_context_from_headers(
      payload[["otel_login_span_headers"]] %||% NULL
    )
  )
}


# 2 Callback handling ----------------------------------------------------------

## 2.1 Entry point -------------------------------------------------------------

#' Handle OAuth 2.0 callback: verify state, swap code for token, verify token
#'
#' Completes the callback step of the login flow. It validates the callback
#' state, exchanges the returned code for tokens, and verifies the result.
#' This low-level helper accepts only the classic authorization-code callback
#' shape for non-JARM clients: a `code`, the sealed `state` payload returned as
#' `payload`, and an optional RFC 9207 `iss` callback parameter. It does not
#' accept a raw JARM `response` JWT, and it also does not provide a public way
#' to resume a JARM callback after separate validation. For clients configured
#' with `response_mode = "jwt"`, `"query.jwt"`, or `"form_post.jwt"`, use
#' [oauth_module_server()] (and [oauth_form_post_ui()] for `form_post.jwt`) so
#' shinyOAuth validates the callback JWT and resumes through its internal
#' prevalidated callback path.
#'
#' @param oauth_client An [OAuthClient] object.
#' @param code Authorization code received from the provider on a classic
#'   direct callback.
#' @param payload Encrypted state payload returned by the provider on a classic
#'   direct callback. This should be the same value that was originally sent in
#'   [prepare_call()].
#' @param browser_token Browser token present in the user's session. This is
#'   usually managed by [oauth_module_server()].
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#' @param iss Optional RFC 9207 callback issuer (`iss`) from the authorization
#'   response. Pass this when one callback URL can receive responses from more
#'   than one authorization server. If `oauth_client@enforce_callback_issuer`
#'   is `TRUE`, this parameter is required and must match the configured
#'   provider issuer before any token exchange occurs.
#'
#' @return An [OAuthToken] object. If callback validation, token exchange, or
#'   token verification fails, the function raises an error.
#'
#' @example inst/examples/call_methods.R
#'
#' @export
handle_callback <- function(
  oauth_client,
  code,
  payload,
  browser_token,
  shiny_session = NULL,
  iss = NULL
) {
  jarm_transport <- resolve_jarm_callback_transport(oauth_client)
  if (!is.null(jarm_transport)) {
    err_config(c(
      paste(
        "handle_callback() does not accept direct code/state callbacks for",
        "JARM clients."
      ),
      "i" = paste0(
        "Configured response_mode ",
        sQuote(jarm_transport[["mode"]]),
        " requires the callback JWT in the response parameter to be",
        " validated before code/state are processed."
      ),
      "i" = if (identical(jarm_transport[["transport"]], "form_post")) {
        paste(
          "Use oauth_form_post_ui() with oauth_module_server() so the",
          "validated form_post handle resumes through the internal",
          "prevalidated callback path."
        )
      } else {
        paste(
          "Use oauth_module_server() so the JARM response is validated",
          "before callback processing continues."
        )
      }
    ))
  }

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
  validate_untrusted_query_param(
    "browser_token",
    browser_token,
    max_bytes = get_option_positive_number(
      "shinyOAuth.callback_max_browser_token_bytes",
      256
    )
  )
  if (!is.null(iss)) {
    validate_untrusted_query_param(
      "iss",
      iss,
      max_bytes = get_option_positive_number(
        "shinyOAuth.callback_max_iss_bytes",
        2048
      )
    )
  }

  callback_hint <- otel_callback_parent_hint(oauth_client, payload)
  async_attr <- isTRUE(tryCatch(shiny_session$is_async, error = function(...) {
    NULL
  })) ||
    isTRUE(get_async_session_context()[["is_async"]]) ||
    isTRUE(is_async_worker_context())

  with_trace_id(
    callback_hint[["trace_id"]] %||% NULL,
    with_otel_span(
      "shinyOAuth.callback",
      {
        enforce_callback_issuer(
          oauth_client = oauth_client,
          iss = iss
        )
        handle_callback_internal(
          oauth_client = oauth_client,
          code = code,
          payload = payload,
          browser_token = browser_token,
          decrypted_payload = NULL,
          state_store_values = NULL,
          trace_id_seeded = is_valid_string(
            callback_hint[["trace_id"]] %||% NA_character_
          ),
          shiny_session = shiny_session
        )
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        async = async_attr,
        phase = "callback",
        extra = list(
          oauth.introspect = isTRUE(oauth_client@introspect),
          oauth.introspect_elements = otel_introspect_elements(
            oauth_client@introspect_elements %||% character(0)
          ),
          oauth.introspect_elements_count = otel_count_items(
            oauth_client@introspect_elements %||% character(0)
          ),
          oauth.userinfo.required = isTRUE(
            oauth_client@provider@userinfo_required
          ),
          oauth.userinfo.id_token_match_required = isTRUE(
            oauth_client@provider@userinfo_id_token_match
          ),
          oauth.id_token.validation_enabled = isTRUE(
            oauth_client@provider@id_token_validation
          )
        )
      ),
      parent = if (!is.null(callback_hint[["parent"]])) {
        callback_hint[["parent"]]
      } else if (isTRUE(async_attr)) {
        NULL
      } else {
        NA
      }
    )
  )
}

#' Finish callback processing from validated inputs
#'
#' Completes callback handling once callback values are available, optionally
#' reusing pre-decrypted state and already-consumed state-store values from the
#' main thread. Used by [handle_callback()] directly and by async module flows
#' after the main process has already consumed state.
#'
#' @param oauth_client [OAuthClient] configuration.
#' @param code Authorization code returned by the provider.
#' @param payload Encrypted state payload returned by the provider.
#' @param browser_token Browser-bound session token that must match stored
#'   state.
#' @param decrypted_payload Optional pre-decrypted state payload.
#' @param state_store_values Optional pre-fetched state-store record.
#' @param trace_id_seeded Whether the surrounding callback span already started
#'   with the recovered shinyOAuth trace id.
#' @param shiny_session Optional Shiny session context.
#' @return An [OAuthToken] object on success. Otherwise this function raises a
#'   typed error.
#' @keywords internal
#' @noRd
handle_callback_internal <- function(
  oauth_client,
  code,
  payload,
  browser_token,
  decrypted_payload = NULL,
  state_store_values = NULL,
  trace_id_seeded = FALSE,
  shiny_session = NULL
) {
  # Type checks ----------------------------------------------------------------

  S7::check_is_S7(oauth_client, class = OAuthClient)

  # Read introspection settings from client (already validated by OAuthClient)
  introspect <- isTRUE(oauth_client@introspect)

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

  # Decrypt & verify payload ---------------------------------------------------

  # Allow callers to provide a pre-decrypted/validated payload to support
  # async flows that prefetch state on the main thread.
  if (!is.null(decrypted_payload)) {
    payload <- state_payload_revalidate(
      oauth_client,
      decrypted_payload,
      shiny_session = shiny_session,
      audit_success = FALSE
    )
  } else {
    payload <- with_otel_span(
      "shinyOAuth.callback.validate",
      {
        # Payload-validation failures are audited inside
        # state_payload_decrypt_validate(); success is emitted only after the
        # browser token and single-use state checks succeed.
        payload <- state_payload_decrypt_validate(
          oauth_client,
          payload,
          shiny_session = shiny_session,
          audit_success = FALSE
        )
        if (!isTRUE(trace_id_seeded)) {
          otel_set_span_attributes(
            attributes = list(
              shinyoauth.trace_id = payload[["trace_id"]] %||%
                NULL
            )
          )
        }
        payload
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        phase = "callback.state_payload"
      )
    )
  }

  with_trace_id(
    payload[["trace_id"]] %||% NULL,
    {
      if (is.null(decrypted_payload) && !isTRUE(trace_id_seeded)) {
        otel_set_span_attributes(
          attributes = list(
            shinyoauth.trace_id = payload[["trace_id"]] %||%
              NULL
          )
        )
      }

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
              state_digest = string_digest(
                payload[["state"]] %||% payload
              ),
              browser_token_digest = string_digest(browser_token)
            ),
            shiny_session = shiny_session
          )
        },
        silent = TRUE
      )

      # Retrieve state_info from state store ---------------------------------------
      # State is the key; value is a list with browser_token, pkce_code_verifier, nonce
      state_store_preconsumed <- !is.null(state_store_values)
      if (is.null(state_store_values)) {
        state_store_values <- with_otel_span(
          "shinyOAuth.callback.validate",
          {
            state_store_get(
              oauth_client,
              payload[["state"]],
              shiny_session = shiny_session
            )
          },
          attributes = otel_client_attributes(
            client = oauth_client,
            shiny_session = shiny_session,
            phase = "callback.state_store_lookup"
          )
        )
      }

      # Verify browser token -------------------------------------------------------

      # Verify browser_token matches
      tryCatch(
        with_otel_span(
          "shinyOAuth.callback.validate",
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
              !constant_time_compare(
                state_store_values[["browser_token"]],
                browser_token
              )
            ) {
              err_invalid_state("Browser token mismatch")
            }
          },
          attributes = otel_client_attributes(
            client = oauth_client,
            shiny_session = shiny_session,
            phase = "callback.browser_token_validation"
          )
        ),
        error = function(e) {
          try(
            audit_event(
              "callback_validation_failed",
              context = list(
                provider = oauth_client@provider@name %||% NA_character_,
                issuer = oauth_client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(oauth_client@client_id),
                state_digest = string_digest(
                  payload[["state"]] %||% NA_character_
                ),
                browser_token_digest = string_digest(browser_token),
                error_class = paste(class(e), collapse = ", "),
                phase = "browser_token_validation"
              ),
              shiny_session = shiny_session
            ),
            silent = TRUE
          )
          rethrow_with_context(e)
        }
      )

      if (!isTRUE(state_store_preconsumed)) {
        state_store_values <- with_otel_span(
          "shinyOAuth.callback.validate",
          {
            # Centralized auditing for state store consumption occurs in
            # state_store_get_remove().
            state_store_get_remove(
              oauth_client,
              payload[["state"]],
              shiny_session = shiny_session
            )
          },
          attributes = otel_client_attributes(
            client = oauth_client,
            shiny_session = shiny_session,
            phase = "callback.state_store_consume"
          )
        )
      }
      audit_callback_validation_success(oauth_client, payload, shiny_session)

      # Swap code for token --------------------------------------------------------

      # Now we can call the token endpoint to swap the code for token(s)

      # Verify PKCE code verifier is present if needed
      code_verifier <- state_store_values[["pkce_code_verifier"]]
      tryCatch(
        with_otel_span(
          "shinyOAuth.callback.validate",
          {
            # validate_code_verifier() throws on invalid input; no return value check
            # needed since the function either succeeds or aborts.
            if (isTRUE(oauth_client@provider@use_pkce)) {
              validate_code_verifier(code_verifier)
            }
          },
          attributes = otel_client_attributes(
            client = oauth_client,
            shiny_session = shiny_session,
            phase = "callback.pkce_verifier_validation"
          )
        ),
        error = function(e) {
          try(
            audit_event(
              "callback_validation_failed",
              context = list(
                provider = oauth_client@provider@name %||% NA_character_,
                issuer = oauth_client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(oauth_client@client_id),
                state_digest = string_digest(
                  payload[["state"]] %||% NA_character_
                ),
                error_class = paste(class(e), collapse = ", "),
                phase = "pkce_verifier_validation"
              ),
              shiny_session = shiny_session
            ),
            silent = TRUE
          )
          rethrow_with_context(e)
        }
      )

      # Perform token exchange
      token_set <- tryCatch(
        {
          ts <- call_with_optional_shiny_session(
            swap_code_for_token_set,
            client = oauth_client,
            code = code,
            code_verifier = code_verifier,
            shiny_session = shiny_session
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
                  ts[["id_token"]] %||% NA_character_
                )),
                received_refresh_token = isTRUE(is_valid_string(
                  ts[["refresh_token"]] %||% NA_character_
                )),
                expires_in_synthesized = !(is.numeric(ts[[
                  "expires_in",
                  exact = TRUE
                ]]) &&
                  is.finite(ts[["expires_in"]]))
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
          rethrow_with_context(e)
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
      nonce <- state_store_values[["nonce"]]
      tryCatch(
        with_otel_span(
          "shinyOAuth.callback.validate",
          {
            # validate_oidc_nonce() throws on invalid input; no return value check
            # needed since the function either succeeds or aborts.
            if (oauth_client@provider@use_nonce) {
              validate_oidc_nonce(nonce)
            }
          },
          attributes = otel_client_attributes(
            client = oauth_client,
            shiny_session = shiny_session,
            phase = "callback.nonce_validation"
          )
        ),
        error = function(e) {
          try(
            audit_event(
              "callback_validation_failed",
              context = list(
                provider = oauth_client@provider@name %||% NA_character_,
                issuer = oauth_client@provider@issuer %||% NA_character_,
                client_id_digest = string_digest(oauth_client@client_id),
                state_digest = string_digest(
                  payload[["state"]] %||% NA_character_
                ),
                error_class = paste(class(e), collapse = ", "),
                phase = "nonce_validation"
              ),
              shiny_session = shiny_session
            ),
            silent = TRUE
          )
          rethrow_with_context(e)
        }
      )

      # Verify token set: validates ID token signature + claims (including nonce),
      # scope reconciliation, and token_type. Userinfo is NOT yet present; the
      # subject match check will run after userinfo is fetched below.
      defer_certificate_binding <- isTRUE(introspect) &&
        client_requests_certificate_bound_tokens(oauth_client) &&
        !is_valid_string(
          token_cnf_x5t_s256(
            access_token = token_set[["access_token"]],
            cnf = token_set[["cnf"]] %||% NULL
          )
        )
      token_set <- verify_token_set(
        oauth_client,
        token_set = token_set,
        nonce = nonce,
        is_refresh = FALSE,
        requested_scopes = payload[["scopes"]] %||% NULL,
        shiny_session = shiny_session,
        defer_certificate_binding = defer_certificate_binding
      )
      effective_token_type <- resolve_effective_access_token_type(
        oauth_client,
        token_set = token_set
      )

      token <- OAuthToken(
        access_token = token_set[["access_token"]] %||%
          err_token("Token response missing access_token"),
        token_type = effective_token_type,
        refresh_token = token_set[["refresh_token"]] %||%
          NA_character_,
        expires_at = if (
          is.numeric(token_set[["expires_in"]]) &&
            is.finite(token_set[["expires_in"]])
        ) {
          as.numeric(Sys.time()) +
            as.numeric(
              token_set[["expires_in"]]
            )
        } else {
          resolve_missing_expires_in(phase = "exchange_code")
        },
        id_token = token_set[["id_token"]] %||% NA_character_,
        cnf = resolve_token_cnf(
          cnf = token_set[["cnf"]],
          access_token = token_set[["access_token"]]
        ),
        granted_scopes = token_set[["granted_scopes"]] %||%
          character(0),
        granted_scopes_verified = isTRUE(
          token_set[["granted_scopes_verified"]]
        ),
        id_token_validated = isTRUE(token_set[[".id_token_validated"]])
      )

      intro_res <- NULL
      if (isTRUE(introspect)) {
        intro_res <- call_with_optional_shiny_session(
          introspect_token,
          oauth_client = oauth_client,
          oauth_token = token,
          which = "access",
          async = FALSE,
          shiny_session = shiny_session
        )
        validate_token_cnf_consistency(
          access_token = token@access_token,
          cnf = token_set[["cnf"]],
          introspection_result = intro_res,
          error_context = "token",
          phase = "exchange_code"
        )
        token@cnf <- resolve_token_cnf(
          cnf = token_set[["cnf"]],
          access_token = token@access_token,
          introspection_result = intro_res
        )
        token@token_type <- resolve_effective_access_token_type(
          oauth_client,
          token_set = token_set,
          introspection_result = intro_res,
          phase = "exchange_code"
        )
        validate_token_dpop_binding(
          oauth_client = oauth_client,
          token = token,
          error_context = "token",
          phase = "exchange_code"
        )
        validate_observed_dpop_cnf_required(
          oauth_client = oauth_client,
          token = token,
          introspection_result = intro_res,
          error_context = "token",
          phase = "exchange_code"
        )

        if (isTRUE(defer_certificate_binding)) {
          validate_token_certificate_binding(
            token = token,
            oauth_client = oauth_client,
            error_context = "token",
            phase = "exchange_code"
          )
        }
      }

      # Fetch userinfo -------------------------------------------------------------

      # Fetch userinfo after token validation. When introspection is enabled,
      # backfill cnf first so certificate-bound opaque tokens can satisfy the
      # initial sender-constraint check and the first automatic userinfo call.

      if (isTRUE(oauth_client@provider@userinfo_required)) {
        userinfo <- call_with_optional_shiny_session(
          get_userinfo,
          oauth_client = oauth_client,
          token = token,
          shiny_session = shiny_session
        )
        token_set[["userinfo"]] <- userinfo

        # OIDC Core requires UserInfo subject binding whenever a validated ID
        # token baseline is available. Explicit userinfo_id_token_match = TRUE
        # also fails closed if that baseline is missing.
        enforce_userinfo_id_token_subject_match(
          oauth_client,
          userinfo = userinfo,
          token_set = token_set
        )

        # Validate requested claims in userinfo (OIDC Core Section 5.5)
        validate_essential_claims(oauth_client, userinfo, "userinfo")

        token@userinfo <- userinfo
      }

      # Return ---------------------------------------------------------------------

      # Optional token introspection validation -----------------------------------

      if (isTRUE(introspect)) {
        token <- enforce_token_introspection_policy(
          oauth_client = oauth_client,
          token = token,
          introspection_result = intro_res,
          requested_scopes = payload[["scopes"]] %||%
            effective_client_scopes(oauth_client),
          phase = "exchange_code",
          token_response_cnf = token_set[["cnf"]]
        )
      }

      # Audit: login success with redacted identifiers
      try(
        {
          # Best-effort subject extraction: prefer userinfo via selector, else ID token sub
          # Track source for audit transparency (userinfo is trusted; ID token may not be)
          sub_val <- NA_character_
          sub_source <- NA_character_
          if (!is.null(token@userinfo) && length(token@userinfo)) {
            sub_val <- resolve_userinfo_subject(oauth_client, token@userinfo)
            if (is_valid_string(sub_val)) sub_source <- "userinfo"
          }
          if (!is_valid_string(sub_val)) {
            # Attempt parse id_token payload for sub (without revalidation)
            it <- token@id_token
            if (is_valid_string(it)) {
              pl <- try(parse_jwt_payload(it), silent = TRUE)
              if (!inherits(pl, "try-error")) {
                sub_val <- pl[["sub"]] %||% NA_character_
                if (is_valid_string(sub_val)) {
                  # Mark whether this specific ID token was actually validated
                  id_token_was_validated <- isTRUE(token@id_token_validated)
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
              refresh_token_present = isTRUE(is_valid_string(
                token@refresh_token
              )),
              expires_at = token@expires_at
            ),
            shiny_session = shiny_session
          )
        },
        silent = TRUE
      )

      return(token)
    }
  )
}

#' Resolve the authenticated subject from a userinfo payload
#'
#' Uses the provider's `userinfo_id_selector` when configured, falling back to
#' `userinfo$sub` only when no selector is configured. Used by login auditing
#' and token-introspection subject checks.
#'
#' @param oauth_client [OAuthClient] carrying the provider selector.
#' @param userinfo Userinfo payload list.
#' @return Scalar character subject, or `NA_character_` when unavailable.
#' @keywords internal
#' @noRd
resolve_userinfo_subject <- function(oauth_client, userinfo) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is.list(userinfo) || length(userinfo) == 0L) {
    return(NA_character_)
  }

  selector <- oauth_client@provider@userinfo_id_selector
  if (is.function(selector)) {
    subject <- try(selector(userinfo), silent = TRUE)
    if (
      inherits(subject, "try-error") ||
        is.null(subject) ||
        length(subject) != 1L
    ) {
      return(NA_character_)
    }

    if (!is.character(subject)) {
      subject <- try(as.character(subject), silent = TRUE)
      if (inherits(subject, "try-error") || length(subject) != 1L) {
        return(NA_character_)
      }
    }

    subject <- subject[[1]]
    if (is_valid_string(subject)) {
      return(subject)
    }

    return(NA_character_)
  }

  subject <- userinfo[["sub"]] %||% NA_character_
  if (!is_valid_string(subject)) {
    return(NA_character_)
  }

  as.character(subject)[[1]]
}

#' Enforce the client's token-introspection policy
#'
#' Applies the configured `introspect` and `introspect_elements` requirements
#' to a normalized [introspect_token()] result. Used after initial login and
#' refresh when access-token introspection is required.
#'
#' @param oauth_client [OAuthClient] carrying the introspection policy.
#' @param token [OAuthToken] being validated.
#' @param introspection_result Normalized result list returned by
#'   [introspect_token()].
#' @param phase Optional token-processing phase used in structured token
#'   errors.
#' @param token_response_cnf Optional raw `cnf` claim returned by the token or
#'   refresh response. When supplied, this preserves token-surface provenance
#'   so conflicts with introspection can be rejected before `cnf` values are
#'   collapsed.
#' @param requested_scopes Optional scope baseline to enforce when
#'   `"scope"` is listed in `client@introspect_elements`. Defaults to the
#'   client's effective scopes.
#' @return The updated [OAuthToken], with `cnf` and `token_type` augmented from
#'   the introspection response when available.
#' @keywords internal
#' @noRd
enforce_token_introspection_policy <- function(
  oauth_client,
  token,
  introspection_result,
  requested_scopes = NULL,
  phase = NULL,
  token_response_cnf = NULL
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)
  S7::check_is_S7(token, class = OAuthToken)

  if (!is.list(introspection_result) || length(introspection_result) == 0L) {
    err_token("Invalid token introspection result")
  }

  if (!isTRUE(introspection_result[["supported"]])) {
    err_token(c(
      "x" = "Token introspection required but provider does not support it",
      "i" = "Set `introspect = FALSE` or configure an introspection_url on the provider"
    ))
  }

  if (!isTRUE(introspection_result[["active"]])) {
    err_token(c(
      "x" = "Token introspection indicates the access token is not active",
      "i" = paste0(
        "Introspection status: ",
        introspection_result[["status"]] %||% "unknown"
      )
    ))
  }

  token_cnf_input <- token_response_cnf %||% token@cnf
  validate_token_cnf_consistency(
    access_token = token@access_token,
    cnf = token_cnf_input,
    introspection_result = introspection_result,
    error_context = "token",
    phase = phase
  )
  token@cnf <- resolve_token_cnf(
    cnf = token_cnf_input,
    access_token = token@access_token,
    introspection_result = introspection_result
  )

  raw <- introspection_result[["raw"]] %||% list()
  if (!is.list(raw)) {
    raw <- list()
  }

  introspect_elements <- oauth_client@introspect_elements %||% character(0)
  intro_token_type <- token_type_from_introspection(introspection_result)
  token@token_type <- resolve_effective_access_token_type(
    oauth_client,
    token_set = list(
      token_type = token@token_type,
      access_token = token@access_token,
      cnf = token_cnf_input
    ),
    introspection_result = introspection_result,
    phase = phase
  )

  if ("token_type" %in% introspect_elements) {
    if (!is_valid_string(intro_token_type)) {
      err_token(c(
        "x" = "Token introspection response missing required token_type",
        "i" = paste(
          "Disable this check or ensure your provider returns token_type in",
          "introspection."
        )
      ))
    }
  }

  if ("client_id" %in% introspect_elements) {
    cid <- raw[["client_id"]] %||% NA_character_
    if (!is_valid_string(cid)) {
      err_token(c(
        "x" = "Token introspection response missing required client_id",
        "i" = "Disable this check or ensure your provider returns client_id in introspection"
      ))
    }
    if (
      !identical(as.character(cid)[1], as.character(oauth_client@client_id)[1])
    ) {
      err_token(c(
        "x" = "Token introspection client_id does not match configured client_id",
        "!" = paste0("Got: ", as.character(cid)[1])
      ))
    }
  }

  if ("sub" %in% introspect_elements) {
    intro_sub <- raw[["sub"]] %||% NA_character_
    if (!is_valid_string(intro_sub)) {
      err_token(c(
        "x" = "Token introspection response missing required sub",
        "i" = "Disable this check or ensure your provider returns sub in introspection"
      ))
    }

    expected_sub <- NA_character_
    if (isTRUE(token@id_token_validated) && is_valid_string(token@id_token)) {
      pl <- try(parse_jwt_payload(token@id_token), silent = TRUE)
      if (!inherits(pl, "try-error")) {
        expected_sub <- pl[["sub"]] %||% NA_character_
      }
    }
    if (!is_valid_string(expected_sub)) {
      ui <- token@userinfo %||% list()
      if (is.list(ui)) {
        expected_sub <- resolve_userinfo_subject(oauth_client, ui)
      }
    }

    if (!is_valid_string(expected_sub)) {
      err_token(c(
        "x" = "Cannot validate introspection sub: no subject is available from a validated ID token or userinfo",
        "i" = "Enable ID token validation and/or userinfo, or disable the sub requirement"
      ))
    }

    if (!identical(as.character(intro_sub)[1], as.character(expected_sub)[1])) {
      err_token(c(
        "x" = "Token introspection sub does not match authenticated subject",
        "i" = "This may indicate a provider inconsistency or a token mix-up"
      ))
    }
  }

  if ("scope" %in% introspect_elements) {
    scope_validation_mode <- oauth_client@scope_validation %||% "warn"
    requested_scopes <- normalize_scope_tokens(
      requested_scopes %||% effective_client_scopes(oauth_client)
    )
    intro_scope_raw <- raw[["scope"]] %||% NULL

    if (!is.null(intro_scope_raw)) {
      token@granted_scopes <- normalize_scope_tokens(intro_scope_raw)
      token@granted_scopes_verified <- TRUE
    }

    if (
      !identical(scope_validation_mode, "none") && length(requested_scopes) > 0
    ) {
      if (is.null(intro_scope_raw)) {
        msg <- "Token introspection response missing scope; cannot validate requested scopes"
        if (identical(scope_validation_mode, "strict")) {
          err_token(c(
            "x" = msg,
            "i" = "Set scope_validation = 'warn' or 'none', or disable the scope introspection requirement"
          ))
        } else if (identical(scope_validation_mode, "warn")) {
          warn_pkg(
            "Unable to validate requested scopes from token introspection",
            c(
              "!" = msg,
              "i" = "Set scope_validation = 'none' to suppress this warning"
            ),
            .frequency = "once",
            .frequency_id = "introspection-scope-validation-missing-scope"
          )
        }
      } else {
        intro_scopes <- normalize_scope_tokens(intro_scope_raw)

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
            warn_pkg(
              "Introspected scopes missing requested entries",
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

  token
}


## 2.2 Callback context and issuer guards --------------------------------------

#' Enforce the callback issuer
#'
#' Checks the callback `iss` value against the configured provider issuer when
#' issuer enforcement is enabled. Used by [handle_callback()] and
#' [oauth_module_server()] before any token exchange starts.
#'
#' @param oauth_client [OAuthClient] carrying the enforcement flag and provider
#'   issuer.
#' @param iss Optional `iss` value from the callback query.
#' @return Invisibly returns `iss` on success. Otherwise this function raises a
#'   typed error.
#' @keywords internal
#' @noRd
enforce_callback_issuer <- function(
  oauth_client,
  iss = NULL
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!(is.null(iss) || is_valid_string(iss))) {
    err_input("{.arg iss} must be NULL or a non-empty string.")
  }

  should_enforce_callback_issuer <- isTRUE(
    oauth_client@enforce_callback_issuer
  )
  expected_issuer <- oauth_client@provider@issuer %||% NA_character_
  if (
    isTRUE(should_enforce_callback_issuer) &&
      !is_valid_string(expected_issuer)
  ) {
    provider_name <- oauth_client@provider@name %||% "(unnamed)"
    err_config(
      c(
        "{.arg enforce_callback_issuer} = {.val TRUE} requires the provider to have a configured {.arg issuer}.",
        "x" = paste0(
          "Provider {.val ",
          provider_name,
          "} does not expose a stable issuer identifier."
        ),
        "i" = "Disable {.arg enforce_callback_issuer} or use an issuer-configured OIDC/discovery provider."
      )
    )
  }

  if (isTRUE(should_enforce_callback_issuer) && is.null(iss)) {
    err_invalid_state(
      "Callback missing required iss parameter (RFC 9207)",
      context = list(
        callback_error = "issuer_missing",
        expected_issuer = expected_issuer
      )
    )
  }

  if (
    isTRUE(should_enforce_callback_issuer) &&
      !is.null(iss) &&
      is_valid_string(expected_issuer) &&
      !identical(iss, expected_issuer)
  ) {
    err_invalid_state(
      "Callback iss parameter does not match expected issuer (RFC 9207)",
      context = list(
        callback_error = "issuer_mismatch",
        expected_issuer = expected_issuer,
        callback_issuer = iss
      )
    )
  }

  invisible(iss)
}

# 3 Token exchange and verification --------------------------------------------

## 3.1 Swap code for token set -------------------------------------------------

#' Exchange the authorization code for tokens
#'
#' Performs the first token request after callback validation succeeds. Used by
#' `handle_callback_internal()` once state, browser, and issuer checks pass.
#'
#' @param client [OAuthClient] used for endpoint resolution and client
#'   authentication.
#' @param code Authorization code to exchange.
#' @param code_verifier PKCE verifier, when PKCE is enabled.
#' @param shiny_session Optional Shiny session context.
#' @return A parsed token response list.
#' @keywords internal
#' @noRd
swap_code_for_token_set <- function(
  client,
  code,
  code_verifier,
  shiny_session = NULL
) {
  S7::check_is_S7(client, class = OAuthClient)

  with_otel_span(
    "shinyOAuth.token.exchange",
    {
      params <- list(
        grant_type = "authorization_code",
        code = code,
        redirect_uri = client@redirect_uri,
        code_verifier = code_verifier
      )
      if (length(client@resource) > 0) {
        params[["resource"]] <- client@resource
      }

      if (length(client@provider@extra_token_params) > 0) {
        params <- c(params, client@provider@extra_token_params)
      }

      token_url <- resolve_provider_endpoint_url(
        client@provider,
        "token_endpoint",
        prefer_mtls = client_uses_mtls_endpoint(client)
      )

      req <- httr2::request(token_url)
      prepared <- apply_direct_client_auth(
        req = req,
        params = params,
        client = client,
        context = "token_exchange"
      )
      req <- prepared[["req"]]
      params <- prepared[["params"]]
      req <- req_apply_authorization_server_mtls(req, client)

      # Apply defaults first; disable redirects to prevent leaking secrets
      req <- add_req_defaults(req)
      req <- req_no_redirect(req)

      # Add any extra token headers without using rlang splicing so tests can stub
      extra_headers <- as.list(client@provider@extra_token_headers)
      if (length(extra_headers) > 0) {
        req <- do.call(httr2::req_headers, c(list(req), extra_headers))
      }

      # Drop NULL entries (e.g., code_verifier when PKCE disabled) before adding form body
      params <- compact_list(params)

      # Add form body without using !!! so it works with simple stubs
      req <- req_body_form_encoded(req, params)
      req <- req_refresh_jwt_client_assertion_on_retry(
        req = req,
        params = params,
        client = client,
        context = "token_exchange",
        body_mode = "encoded"
      )
      req <- httr2::req_method(req, "POST")

      resp <- with_otel_span(
        "shinyOAuth.token.exchange.http",
        {
          # Token exchange consumes a single-use authorization code; do not retry.
          # When DPoP is enabled, req_with_dpop_retry() may regenerate the
          # proof once if the authorization server challenges with DPoP-Nonce.
          resp <- req_with_dpop_retry(req, client, idempotent = FALSE)
          otel_record_http_result(resp)
          resp
        },
        attributes = otel_http_attributes(
          method = "POST",
          url = token_url,
          extra = c(
            list(oauth.phase = "token.exchange"),
            otel_mtls_endpoint_alias_attributes(
              provider = client@provider,
              endpoint = "token_endpoint",
              url = token_url
            )
          )
        ),
        options = list(kind = "client"),
        mark_ok = FALSE
      )
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
      if (!is.null(token_set[["expires_in"]])) {
        token_set[["expires_in"]] <- coerce_expires_in(
          token_set[["expires_in"]]
        )
      }

      otel_set_span_attributes(
        attributes = otel_token_response_attributes(
          token_set,
          client = client
        )
      )

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
      if (!is.null(token_set[["expires_in"]])) {
        if (
          !is.numeric(token_set[["expires_in"]]) ||
            length(token_set[["expires_in"]]) != 1L ||
            !is.finite(token_set[["expires_in"]]) ||
            token_set[["expires_in"]] < 0
        ) {
          err_token("Invalid expires_in in token response")
        }

        if (token_set[["expires_in"]] <= 0) {
          warn_about_nonpositive_expires_in(
            token_set[["expires_in"]],
            phase = "exchange_code"
          )
        }
      }

      token_set
    },
    attributes = otel_client_attributes(
      client = client,
      shiny_session = shiny_session,
      phase = "token.exchange",
      extra = list(
        oauth.used_pkce = is_valid_string(code_verifier),
        oauth.client_auth_style = otel_client_auth_style(client),
        oauth.extra_token_params_count = otel_count_items(
          client@provider@extra_token_params
        ),
        oauth.extra_token_headers_count = otel_count_items(
          client@provider@extra_token_headers
        )
      )
    )
  )
}


## 3.2 Verify token set --------------------------------------------------------

#' Validate a token response
#'
#' Checks the token response before it is converted to an [OAuthToken],
#' including token type, scope reconciliation, ID token validation, requested
#' claims, and refresh-specific continuity checks. Used by
#' `handle_callback_internal()` and [refresh_token()].
#'
#' @param client [OAuthClient] and provider policy source.
#' @param token_set Token response list to validate.
#' @param nonce Expected nonce for ID token validation.
#' @param is_refresh Whether `token_set` came from a refresh flow.
#' @param original_id_token Previous ID token used for refresh continuity
#'   checks.
#' @param requested_scopes Scopes originally requested, defaulting to the
#'   effective client scopes.
#' @param prior_granted_scopes Previously stored granted scopes to carry
#'   forward when a refresh response omits `scope`.
#' @param shiny_session Optional Shiny session context.
#' @param defer_certificate_binding Logical. When `TRUE`, postpone strict mTLS
#'   certificate-binding checks until the caller has had a chance to backfill
#'   `cnf` from token introspection.
#' @return The validated `token_set` list.
#' @keywords internal
#' @noRd
verify_token_set <- function(
  client,
  token_set,
  nonce,
  is_refresh = FALSE,
  original_id_token = NULL,
  requested_scopes = NULL,
  prior_granted_scopes = NULL,
  shiny_session = NULL,
  defer_certificate_binding = FALSE
) {
  # Helpers/types --------------------------------------------------------------

  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(token_set) || length(token_set) == 0) {
    err_token("Invalid token set: must be a non-empty list")
  }

  scope_validation_mode <- client@scope_validation %||% "warn"
  requested_scopes <- normalize_scope_tokens(
    requested_scopes %||% effective_client_scopes(client)
  )
  granted_scope_state <- resolve_granted_scope_state(
    token_scope = token_set[["scope"]],
    requested_scopes = requested_scopes,
    is_refresh = is_refresh,
    previous_granted_scopes = prior_granted_scopes
  )
  granted_scopes <- granted_scope_state[["granted_scopes"]] %||%
    character(0)
  granted_scopes_verified <- isTRUE(
    granted_scope_state[["granted_scopes_verified"]]
  )
  scope_is_omitted <- isTRUE(
    granted_scope_state[["scope_is_omitted"]]
  )
  scope_is_empty <- isTRUE(
    granted_scope_state[["scope_is_empty"]]
  )
  requested_scope_string <- otel_scope_string(requested_scopes %||% NULL)
  granted_scope_string <- otel_scope_string(granted_scopes %||% NULL)
  granted_scope_count <- {
    if (!length(granted_scopes)) {
      NULL
    } else {
      as.integer(length(granted_scopes))
    }
  }
  phase <- if (isTRUE(is_refresh)) "refresh_token" else "exchange_code"
  id_token_present <- isTRUE(is_valid_string(token_set[["id_token"]]))
  id_token_required <- !isTRUE(is_refresh) &&
    (isTRUE(client@provider@id_token_required) |
      isTRUE(client@provider@id_token_validation) |
      isTRUE(client@provider@userinfo_id_token_match) |
      isTRUE(client@provider@use_nonce) |
      isTRUE(is_valid_string(nonce)))
  racr <- client@required_acr_values %||% character(0)
  should_enforce_id_token_claims <-
    !identical(client@claims_validation %||% "none", "none") &&
    claims_request_target_has_enforceable_requirements(
      client@claims,
      "id_token"
    )

  with_otel_span(
    "shinyOAuth.token.verify",
    local({
      # Initialize before on.exit so cleanup still runs after early aborts.
      id_token_validated <- FALSE

      # Emit these decision attributes once on span exit so exporters do not
      # receive duplicate keys when final values replace the initial defaults.
      on.exit(
        otel_set_span_attributes(
          attributes = compact_list(list(
            oauth.id_token.validated = isTRUE(id_token_validated),
            oauth.scopes.granted = granted_scope_string,
            oauth.scopes.granted_count = granted_scope_count
          ))
        ),
        add = TRUE
      )

      verify_token_type_allowlist(client, token_set)
      validate_token_dpop_binding(
        oauth_client = client,
        access_token = token_set[["access_token"]],
        cnf = token_set[["cnf"]] %||% NULL,
        error_context = "token",
        phase = phase
      )
      validate_observed_dpop_cnf_required(
        oauth_client = client,
        access_token = token_set[["access_token"]],
        cnf = token_set[["cnf"]] %||% NULL,
        error_context = "token",
        phase = phase
      )
      if (!isTRUE(defer_certificate_binding)) {
        validate_token_certificate_binding(
          access_token = token_set[["access_token"]],
          cnf = token_set[["cnf"]] %||% NULL,
          oauth_client = client,
          error_context = "token",
          phase = phase
        )
      }

      # Scope reconciliation --------------------------------------------------------

      # If requested scopes exist, verify the provider returned them (or a superset).
      # RFC 6749 Section 3.3 allows servers to reduce scopes; behavior is controlled
      # by client@scope_validation: "strict" (error), "warn", or "none" (skip).
      #
      # RFC 6749 Section 5.1 allows the token response to omit scope when the
      # granted scope is identical to the requested scope. RFC 6749 Section 6
      # applies the same rule to refresh responses. We therefore treat an
      # omitted scope as unchanged from the request rather than as an error.
      # Skip explicit scope reconciliation when provider omits scope. Per RFC
      # 6749 Sections 5.1 and 6, omission means unchanged from the requested
      # scope. During refresh we also continue tolerating empty string scope to
      # preserve compatibility with providers that serialize an unchanged scope
      # that way.
      if (
        !identical(scope_validation_mode, "none") &&
          length(requested_scopes) > 0 &&
          !scope_is_omitted &&
          !(isTRUE(is_refresh) && scope_is_empty)
      ) {
        if (scope_is_empty) {
          msg <- "Token response scope is empty; cannot verify requested scopes were granted"
          if (identical(scope_validation_mode, "strict")) {
            err_token(c(
              "x" = msg,
              "i" = "Set scope_validation = 'warn' or 'none' to allow empty scope in response"
            ))
          } else if (identical(scope_validation_mode, "warn")) {
            warn_pkg(
              "Unable to validate requested scopes from token response",
              c(
                "!" = msg,
                "i" = "Set scope_validation = 'none' to suppress this warning"
              ),
              .frequency = "once",
              .frequency_id = "scope-validation-empty-scope"
            )
          }
        } else {
          missing <- setdiff(requested_scopes, granted_scopes)
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
              warn_pkg(
                "Granted scopes missing requested entries",
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

      token_set[["granted_scopes"]] <- granted_scopes
      token_set[["granted_scopes_verified"]] <- granted_scopes_verified

      # ID token -------------------------------------------------------------------

      # Check that it is present if required
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
      if (isTRUE(id_token_required) && !isTRUE(id_token_present)) {
        err_id_token("ID token required but not present")
      }

      # OIDC Core 12.2: During refresh, if a new ID token is returned, its sub
      # claim MUST match the original. We always enforce this sub continuity when
      # a refresh returns an ID token, even if signature/claim validation is
      # disabled (id_token_validation = FALSE).
      expected_sub <- NULL
      original_payload <- NULL
      should_validate_id_token <- isTRUE(id_token_present) &&
        (isTRUE(client@provider@id_token_validation) ||
          isTRUE(client@provider@use_nonce) ||
          isTRUE(is_valid_string(nonce)))

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
        if (!is_valid_string(original_payload[["sub"]])) {
          err_id_token("Original ID token missing sub claim (OIDC 12.2)")
        }
        expected_sub <- original_payload[["sub"]]

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
          if (!is_valid_string(new_payload[["sub"]])) {
            err_id_token("Refreshed ID token missing sub claim (OIDC 12.2)")
          }
          if (!identical(new_payload[["sub"]], expected_sub)) {
            err_id_token(
              "Refresh returned an ID token with sub that does not match the original (OIDC 12.2)"
            )
          }
          compare_refresh_id_token_continuity(new_payload, original_payload)
        }
      }

      # Validate ID token when present and validation is requested.
      # Covers: id_token_validation, use_nonce, or explicit nonce passed.
      if (isTRUE(should_validate_id_token)) {
        # Verifies signature & claims of ID token
        # Will error if invalid
        # OIDC Core Section 3.1.2.1: when max_age was requested in extra_auth_params,
        # pass it to validate_id_token() so auth_time is enforced.
        requested_max_age <- NULL
        if (!isTRUE(is_refresh)) {
          requested_max_age <- inspect_auth_max_age(
            client@provider@extra_auth_params
          )[["value"]]
        }
        id_token_validation_result <- validate_id_token(
          client,
          id_token,
          expected_nonce = nonce,
          expected_sub = expected_sub,
          expected_access_token = token_set[["access_token"]],
          max_age = requested_max_age
        )

        # If validate_id_token() returned explicit metadata that signature
        # verification was skipped (for example via skip_id_sig in test mode),
        # do not mark the token as cryptographically validated.
        id_token_validated <- !identical(
          attr(id_token_validation_result, "signature_verified", exact = TRUE),
          FALSE
        )

        # OIDC Core 12.2: during refresh, verify iss and aud match the original
        # ID token's actual values (not just the provider config). validate_id_token()
        # already checks iss == provider@issuer and client_id %in% aud, but 12.2
        # additionally requires exact match against the original token's claims.
        # Parse the new token payload directly (rather than depending on the return
        # value of validate_id_token) so the check is robust regardless of mocking.
        if (isTRUE(is_refresh) && !is.null(original_payload)) {
          new_payload_for_refresh <- tryCatch(
            parse_jwt_payload(id_token),
            error = function(e) NULL
          )
          if (is.null(new_payload_for_refresh)) {
            err_id_token(
              "Cannot parse refreshed ID token to verify continuity claims (OIDC 12.2)"
            )
          }
          compare_refresh_id_token_continuity(
            new_payload_for_refresh,
            original_payload
          )
        }
      }

      # Validate requested claims in ID token (OIDC Core Section 5.5) ---------------------

      # When claims_validation is enabled and the client requested essential
      # claims or explicit claim values for id_token, verify the decoded ID token
      # payload satisfies those requests. This applies to both initial login and
      # refresh (if a new ID token is returned).
      if (
        isTRUE(id_token_present) &&
          isTRUE(should_enforce_id_token_claims) &&
          !isTRUE(id_token_validated)
      ) {
        err_id_token(
          "Cannot enforce requested ID token claims without ID token validation"
        )
      }
      if (isTRUE(id_token_present) && isTRUE(id_token_validated)) {
        id_payload <- tryCatch(
          parse_jwt_payload(token_set[["id_token"]]),
          error = function(e) NULL
        )
        if (!is.null(id_payload)) {
          validate_essential_claims(client, id_payload, "id_token")
        }
      }

      # Validate acr claim against required_acr_values (OIDC Core Sections 2 and 3.1.2.1) ----

      # When the client specifies required_acr_values, verify the ID token's acr
      # claim is present and matches one of the allowlisted values.  This runs on
      # both initial login and refresh (when a new ID token is returned).
      if (
        length(racr) > 0 &&
          isTRUE(id_token_present) &&
          !isTRUE(id_token_validated)
      ) {
        err_id_token(
          "Cannot enforce required_acr_values without ID token validation"
        )
      }
      if (
        length(racr) > 0 &&
          isTRUE(id_token_present) &&
          isTRUE(id_token_validated)
      ) {
        acr_payload <- tryCatch(
          parse_jwt_payload(token_set[["id_token"]]),
          error = function(e) NULL
        )
        if (is.null(acr_payload)) {
          err_id_token(
            "Cannot parse ID token to verify acr claim"
          )
        }
        acr_value <- acr_payload[["acr"]]
        if (is.null(acr_value) || !is_valid_string(acr_value)) {
          err_id_token(c(
            "x" = "ID token missing required acr claim (OIDC Core Section 2)",
            "i" = paste0(
              "Required one of: ",
              paste(racr, collapse = ", ")
            )
          ))
        }
        if (!acr_value %in% racr) {
          err_id_token(c(
            "x" = paste0(
              "ID token acr claim '",
              acr_value,
              "' is not in the required_acr_values allowlist"
            ),
            "i" = paste0(
              "Allowed: ",
              paste(racr, collapse = ", ")
            )
          ))
        }
      }

      # Validate match between userinfo & ID token ---------------------------------

      # During initial login (is_refresh = FALSE): this check is now performed by
      # handle_callback() AFTER userinfo is fetched, not here. This function is
      # called before userinfo fetch in the new flow, so we skip this check.
      # During refresh, direct callers may provide userinfo alongside the token
      # response. Bind it to any validated ID token baseline in the response,
      # and fail closed when policy explicitly requires that baseline.

      token_set[[".id_token_validated"]] <- id_token_validated

      if (isTRUE(is_refresh)) {
        userinfo_present <- is.list(token_set[["userinfo"]]) &&
          length(token_set[["userinfo"]]) > 0

        if (userinfo_present) {
          enforce_userinfo_id_token_subject_match(
            client,
            userinfo = token_set[["userinfo"]],
            token_set = token_set
          )
        }
      }

      token_set
    }),
    attributes = otel_client_attributes(
      client = client,
      shiny_session = shiny_session,
      phase = if (isTRUE(is_refresh)) "refresh.verify" else "callback.verify",
      extra = c(
        list(
          oauth.received_id_token = id_token_present,
          oauth.received_refresh_token = isTRUE(is_valid_string(token_set[[
            "refresh_token"
          ]])),
          oauth.id_token.required = isTRUE(id_token_required),
          oauth.id_token.present = isTRUE(id_token_present),
          oauth.nonce.required = isTRUE(client@provider@use_nonce) ||
            isTRUE(is_valid_string(nonce)),
          oauth.scope.validation_mode = scope_validation_mode,
          oauth.scopes.requested = requested_scope_string,
          oauth.scopes.requested_count = as.integer(length(requested_scopes)),
          oauth.required_acr_values = otel_required_acr_values(racr),
          oauth.required_acr_values_count = otel_count_items(racr),
          oauth.refresh_flow = isTRUE(is_refresh)
        ),
        otel_sender_constraint_token_attributes(
          client = client,
          token_set = token_set
        )
      ),
    )
  )
}

#' Enforce the provider token type allowlist
#'
#' Validates the returned `token_type` against the provider policy so later code
#' can trust how the access token must be used. Used by `verify_token_set()` as
#' the token response is normalized.
#'
#' @param client [OAuthClient] whose provider defines allowed token types.
#' @param token_set Token response list containing `token_type`.
#' @return Invisibly returns `TRUE` when the token type policy passes.
#'   Otherwise this function raises a token error.
#' @keywords internal
#' @noRd
verify_token_type_allowlist <- function(client, token_set) {
  S7::check_is_S7(client, class = OAuthClient)

  if (!is.list(token_set)) {
    err_token("Invalid token set: must be a list")
  }

  # Token type guardrail -------------------------------------------------------
  # Policy:
  # - token_type is always required on successful token responses.
  # - If provider@allowed_token_types is non-empty, token_type must also be
  #   one of the allowed values (case-insensitive). DPoP-capable clients
  #   extend that non-empty allowlist with DPoP so the provider can return
  #   either token_type without extra configuration.
  allowed_vec <- client@provider@allowed_token_types %||% character(0)
  if (
    length(allowed_vec) > 0 &&
      client_has_dpop(client) &&
      !any(tolower(allowed_vec) == "dpop")
  ) {
    allowed_vec <- c(allowed_vec, "DPoP")
  }

  tt <- token_set[["token_type"]]
  if (!is.null(tt)) {
    if (!is_valid_string(tt)) {
      err_token("Invalid token_type in token response")
    }
    tt <- as.character(tt)
  } else {
    err_token("Token response missing token_type")
  }

  if (length(allowed_vec) > 0) {
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

  if (
    is_valid_string(tt) && is_dpop_token_type(tt) && !client_has_dpop(client)
  ) {
    err_token(c(
      "x" = "Received token_type = DPoP but OAuthClient has no dpop_private_key configured",
      "i" = "Configure dpop_private_key on the OAuthClient to use DPoP-bound tokens."
    ))
  }

  if (isTRUE(client@dpop_require_access_token)) {
    if (!is_valid_string(tt)) {
      err_token(
        "Token response missing token_type but dpop_require_access_token = TRUE"
      )
    }
    if (!is_dpop_token_type(tt)) {
      err_token(c(
        "x" = "Expected token_type = DPoP",
        "i" = "Set dpop_require_access_token = FALSE to allow Bearer access tokens when using DPoP-bound refresh tokens."
      ))
    }
  }

  invisible(TRUE)
}

#' Parse token_type data from an introspection result
#'
#' @param introspection_result Introspection result object or raw payload list.
#' @return Scalar token type string, or `NA_character_` when absent.
#' @keywords internal
#' @noRd
token_type_from_introspection <- function(introspection_result) {
  if (!is.list(introspection_result)) {
    return(NA_character_)
  }

  raw <- introspection_result[["raw"]] %||% introspection_result
  if (is.data.frame(raw)) {
    raw <- as.list(raw)
  }
  if (!is.list(raw)) {
    return(NA_character_)
  }

  token_type <- raw[["token_type"]] %||% NA_character_
  if (!is_valid_string(token_type)) {
    return(NA_character_)
  }

  as.character(token_type)[[1]]
}

#' Resolve the effective access token type
#'
#' Used after token-response policy checks so later surfaces can reconcile an
#' explicit token-response `token_type` with any authoritative introspection
#' metadata.
#'
#' @param oauth_client [OAuthClient] whose DPoP configuration may imply DPoP.
#' @param token_set Token response list containing `token_type`,
#'   `access_token`, and optional `cnf`.
#' @param introspection_result Optional introspection payload whose
#'   `token_type` may backfill or validate the effective token type.
#' @param phase Optional token-processing phase used in structured token
#'   errors.
#' @return Scalar token type string, or `NA_character_` when no effective type
#'   can be derived.
#' @keywords internal
#' @noRd
resolve_effective_access_token_type <- function(
  oauth_client,
  token_set,
  introspection_result = NULL,
  phase = NULL
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is.list(token_set)) {
    err_token("Invalid token set: must be a list")
  }

  intro_token_type <- token_type_from_introspection(introspection_result)
  effective_token_type <- token_set[["token_type"]] %||%
    NA_character_
  if (
    is_valid_string(effective_token_type) &&
      is_valid_string(intro_token_type) &&
      !identical(
        tolower(as.character(effective_token_type)[[1]]),
        tolower(as.character(intro_token_type)[[1]])
      )
  ) {
    err_token(
      c(
        "x" = "Token introspection token_type conflicts with the token response",
        "!" = paste0(
          "Token response: ",
          as.character(effective_token_type)[[1]],
          "; introspection: ",
          as.character(intro_token_type)[[1]]
        ),
        "i" = "Reject tokens whose sender-constraint metadata disagrees across token surfaces."
      ),
      context = compact_list(list(phase = phase))
    )
  }
  if (
    !is_valid_string(effective_token_type) && is_valid_string(intro_token_type)
  ) {
    verify_token_type_allowlist(
      oauth_client,
      token_set = list(token_type = intro_token_type)
    )
    effective_token_type <- intro_token_type
  }

  if (is_valid_string(effective_token_type)) {
    return(as.character(effective_token_type))
  }

  NA_character_
}

# 4 Refresh continuity helpers -------------------------------------------------

#' Internal: compare original and refreshed ID token continuity claims
#'
#' Used by `swap_code_for_token_set()` during refresh handling to enforce OIDC
#' Core section 12.2 continuity checks for `iss`, `aud`, `auth_time`, `nonce`,
#' and `azp` when a provider returns a refreshed ID token.
#'
#' @param new_payload Parsed refreshed ID token payload.
#' @param original_payload Parsed original ID token payload.
#' @return No return value; raises `err_id_token()` on any continuity mismatch.
#' @keywords internal
#' @noRd
compare_refresh_id_token_continuity <- function(
  new_payload,
  original_payload
) {
  original_iss <- original_payload[["iss"]]
  original_aud <- original_payload[["aud"]]
  original_auth_time <- original_payload[["auth_time"]]
  original_nonce <- original_payload[["nonce"]] %||% NULL
  original_azp <- original_payload[["azp"]] %||% NULL

  if (
    is_valid_string(original_iss) &&
      !identical(new_payload[["iss"]] %||% "", original_iss)
  ) {
    err_id_token(
      "Refresh returned an ID token with iss that does not match the original (OIDC 12.2)"
    )
  }
  if (
    !is.null(original_aud) &&
      !identical(
        sort(as.character(new_payload[["aud"]] %||% character())),
        sort(as.character(original_aud))
      )
  ) {
    err_id_token(
      "Refresh returned an ID token with aud that does not match the original (OIDC 12.2)"
    )
  }
  if (!is.null(original_auth_time)) {
    original_auth_time_val <- suppressWarnings(as.numeric(
      original_auth_time
    ))
    if (
      length(original_auth_time) != 1L ||
        !is.numeric(original_auth_time_val) ||
        !is.finite(original_auth_time_val)
    ) {
      err_id_token(
        "Original ID token auth_time claim must be a single finite number to verify refresh continuity (OIDC 12.2)"
      )
    }
    if (is.null(new_payload[["auth_time"]])) {
      err_id_token(
        "Refresh returned an ID token missing auth_time from the original authentication (OIDC 12.2)"
      )
    }

    new_auth_time_val <- suppressWarnings(as.numeric(
      new_payload[["auth_time"]]
    ))
    if (
      length(new_payload[["auth_time"]]) != 1L ||
        !is.numeric(new_auth_time_val) ||
        !is.finite(new_auth_time_val)
    ) {
      err_id_token(
        "Refreshed ID token auth_time claim must be a single finite number (OIDC 12.2)"
      )
    }
    if (!identical(new_auth_time_val, original_auth_time_val)) {
      err_id_token(
        "Refresh returned an ID token with auth_time that does not match the original (OIDC 12.2)"
      )
    }
  }
  if (
    !is.null(new_payload[["nonce"]]) &&
      !identical(new_payload[["nonce"]], original_nonce)
  ) {
    err_id_token(
      "Refresh returned an ID token with nonce that does not match the original (OIDC 12.2)"
    )
  }
  if (
    (!is.null(original_azp) ||
      !is.null(new_payload[["azp"]])) &&
      !identical(
        new_payload[["azp"]] %||% NULL,
        original_azp
      )
  ) {
    err_id_token(
      "Refresh returned an ID token with azp that does not match the original (OIDC 12.2)"
    )
  }
}
