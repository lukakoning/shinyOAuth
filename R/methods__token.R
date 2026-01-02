# This file contains methods to introspect and refresh an OAuthToken

#' @title
#' Introspect an OAuth 2.0 token
#'
#' @description
#' Introspects an access or refresh token using RFC 7662 when the
#' provider exposes an introspection endpoint. Returns a list including at least
#' `supported` (logical) and `active` (logical|NA) and the parsed response (if
#' any) under `raw`.
#'
#' Authentication to the introspection endpoint mirrors the provider's
#' `token_auth_style`:
#'  - "header" (default): HTTP Basic with `client_id`/`client_secret`.
#'  - "body": form fields `client_id` and (when available) `client_secret`.
#'  - "client_secret_jwt" / "private_key_jwt": a signed JWT client assertion
#'    is generated (RFC 7523) and sent via `client_assertion_type` and
#'    `client_assertion`, with `aud` set to the provider's
#'    `introspection_url`.
#'
#' @details
#' Best-effort semantics:
#' - If the provider does not expose an introspection endpoint, the function
#'   returns `supported = FALSE`, `active = NA`, and `status = "introspection_unsupported"`.
#' - If the endpoint responds with an HTTP error (e.g., 404/500) or the body
#'   cannot be parsed or does not include a usable `active` field, the function
#'   does not throw. It returns `supported = TRUE`, `active = NA`, and a
#'   descriptive `status` (for example, `"http_404"`, `"invalid_json"`,
#'   `"missing_active"`). In this context, `NA`
#'   means "unknown" and will not break flows unless your code explicitly
#'   requires a definitive result (i.e., `isTRUE(result$active)`).
#' - Providers vary in how they encode the RFC 7662 `active` field (logical,
#'   numeric, or character variants like "true"/"false", 1/0). These are
#'   normalized to logical `TRUE`/`FALSE` when possible; otherwise `active` is
#'   set to `NA`.
#'
#' @param oauth_client [OAuthClient] object
#' @param oauth_token [OAuthToken] object to introspect
#' @param which Which token to introspect: "access" (default) or "refresh".
#' @param async Logical, default FALSE. If TRUE and promises is available, run
#'   in background and return a promise resolving to the result list
#'
#' @return A list with fields: supported, active, raw, status
#'
#' @example inst/examples/token_methods.R
#'
#' @export
introspect_token <- function(
  oauth_client,
  oauth_token,
  which = c("access", "refresh"),
  async = FALSE
) {
  # Type checks
  S7::check_is_S7(oauth_client, OAuthClient)
  S7::check_is_S7(oauth_token, OAuthToken)
  stopifnot(
    is.logical(async),
    length(async) == 1,
    !is.na(async)
  )

  which <- match.arg(which)

  url <- oauth_client@provider@introspection_url %||% NA_character_
  if (!is_valid_string(url)) {
    return(list(
      supported = FALSE,
      active = NA,
      raw = NULL,
      status = "introspection_unsupported"
    ))
  }

  if (isTRUE(async)) {
    rlang::check_installed(
      c("promises", "future"),
      reason = "to use `async = TRUE` in `introspect_token()`"
    )

    return(promises::future_promise({
      introspect_token(
        oauth_client = oauth_client,
        oauth_token = oauth_token,
        which = which,
        async = FALSE
      )
    }))
  }

  tok_val <- if (which == "access") {
    oauth_token@access_token
  } else {
    oauth_token@refresh_token
  }
  if (!is_valid_string(tok_val)) {
    return(list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = "missing_token"
    ))
  }

  params <- list(token = tok_val)
  # Some providers require a token_type_hint; include if refreshing
  if (which == "refresh") {
    params$token_type_hint <- "refresh_token"
  } else {
    params$token_type_hint <- "access_token"
  }

  req <- httr2::request(url)
  tas <- oauth_client@provider@token_auth_style %||% "header"
  if (identical(tas, "header")) {
    req <- req |>
      httr2::req_auth_basic(oauth_client@client_id, oauth_client@client_secret)
  } else if (identical(tas, "body")) {
    params$client_id <- oauth_client@client_id
    if (is_valid_string(oauth_client@client_secret)) {
      params$client_secret <- oauth_client@client_secret
    }
  } else if (
    identical(tas, "client_secret_jwt") || identical(tas, "private_key_jwt")
  ) {
    params$client_id <- oauth_client@client_id
    params$client_assertion_type <-
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    params$client_assertion <- build_client_assertion(
      oauth_client,
      aud = url
    )
  } else {
    err_config(
      c(
        "x" = "Unsupported token_auth_style for introspection.",
        "i" = paste0(
          "Got: '",
          tas,
          "'. Allowed: 'header', 'body', 'client_secret_jwt', 'private_key_jwt'."
        )
      ),
      context = list(phase = "introspect_token", style = tas)
    )
  }
  req <- add_req_defaults(req)
  req <- do.call(httr2::req_body_form, c(list(req), params))
  req <- httr2::req_error(req, is_error = function(resp) FALSE)
  # Perform request with retry for transient failures
  resp <- req_with_retry(req)

  if (httr2::resp_is_error(resp)) {
    # If the endpoint responds with an HTTP error (e.g., 404), we cannot
    # confirm token validity. Mark active as NA (unknown). The overall
    # all_passed logic requires active == TRUE when requested, so NA will
    # still result in all_passed = FALSE.
    return(list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = paste0("http_", httr2::resp_status(resp))
    ))
  }
  raw <- NULL
  active <- NA
  status <- "ok"
  # Try parse JSON; RFC 7662 requires JSON body with at least { active: boolean }
  body_txt <- httr2::resp_body_string(resp)
  parsed <- try(
    jsonlite::fromJSON(body_txt, simplifyVector = TRUE),
    silent = TRUE
  )

  if (inherits(parsed, "try-error") || !is.list(parsed)) {
    status <- "invalid_json"
    raw <- NULL
  } else {
    raw <- parsed
    # Coerce various encodings of the RFC 7662 `active` field into a single logical
    # TRUE/FALSE. Some providers return strings ("true"/"false") or numbers (1/0).
    coerce_active <- function(x) {
      # logical -> pass through (preserve NA as NA)
      if (is.logical(x)) {
        return(ifelse(length(x) >= 1L, x[[1]], NA))
      }
      # numeric/integer -> 0 = FALSE, non-zero = TRUE
      if (is.numeric(x)) {
        xv <- suppressWarnings(as.numeric(x[[1]]))
        if (length(xv) == 1L && !is.na(xv)) {
          return(xv != 0)
        }
        return(NA)
      }
      # character -> handle common truthy/falsey strings
      if (is.character(x)) {
        v <- tolower(trimws(as.character(x[[1]])))
        if (v %in% c("true", "1", "t", "yes", "y")) {
          return(TRUE)
        }
        if (v %in% c("false", "0", "f", "no", "n")) {
          return(FALSE)
        }
        return(NA)
      }
      NA
    }

    if (is.null(raw$active)) {
      status <- "missing_active"
    } else {
      active <- coerce_active(raw$active)
      if (is.na(active)) {
        status <- "invalid_active"
      }
    }
  }

  # Defensive: ensure we never claim success when the result is unknown.
  if (identical(status, "ok") && is.null(raw)) {
    status <- "invalid_json"
  }
  if (identical(status, "ok") && is.na(active)) {
    status <- "missing_active"
  }

  # If parsing failed or the response didn't include an active field,
  # leave active as NA (unknown). The caller's all_passed logic requires
  # TRUE to pass, so NA will not pass.
  list(
    supported = TRUE,
    active = active,
    raw = raw,
    status = status
  )
}

#' @title
#' Refresh an OAuth 2.0 token
#'
#' @description
#' Refreshes an OAuth session by obtaining a fresh access token using the
#' refresh token. When configured, also re-fetches userinfo and validates any
#' new ID token returned by the provider.
#'
#' Per OIDC Core Section 12.2, providers may omit the ID token from refresh
#' responses. When omitted, the original ID token from the initial login is
#' preserved.
#'
#' If the provider does return a new ID token during refresh, `refresh_token()`
#' requires that an original ID token from the initial login is available so it
#' can enforce subject continuity (OIDC 12.2: `sub` MUST match). If no original
#' ID token is available, refresh fails with an error.
#'
#' When `id_token_validation = TRUE`, any refresh-returned ID token is also
#' fully validated (signature and claims) in addition to the OIDC 12.2 `sub`
#' continuity check.
#'
#' When `userinfo_required = TRUE`, userinfo is re-fetched using the fresh
#' access token. If both a new ID token and fresh userinfo are present and
#' `userinfo_id_token_match = TRUE`, their subjects are verified to match.
#'
#' @param oauth_client [OAuthClient] object
#' @param token [OAuthToken] object containing the refresh token
#' @param async Logical, default FALSE. If TRUE and the `promises` package is
#'   available, the refresh is performed off the main R session using
#'   `promises::future_promise()` and this function returns a promise that
#'   resolves to an updated `OAuthToken`. If `promises` is not available, falls
#'   back to synchronous behavior
#' @param introspect Logical, default FALSE. After a successful refresh, if the
#'   provider exposes an introspection endpoint, perform a best-effort
#'   introspection of the new access token for audit/diagnostics. The result
#'   is not stored on the token object.
#'
#' @return An updated [OAuthToken] object with refreshed credentials.
#'
#'   **What changes:**
#'   - `access_token`: Always updated to the fresh token
#'   - `expires_at`: Computed from `expires_in` when provided; otherwise `Inf`
#'   - `refresh_token`: Updated if the provider rotates it; otherwise preserved
#'   - `id_token`: Updated only if the provider returns one (and it validates);
#'     otherwise the original from login is preserved
#'   - `userinfo`: Refreshed if `userinfo_required = TRUE`; otherwise preserved
#'
#'   **Validation failures cause errors:** If the provider returns a new ID
#'   token that fails validation (wrong issuer, audience, expired, or subject
#'   mismatch with original), or if userinfo subject doesn't match the new ID
#'   token, the refresh fails with an error. In `oauth_module_server()`, this
#'   clears the session and sets `authenticated = FALSE`.
#'
#' @example inst/examples/token_methods.R
#'
#' @export
refresh_token <- function(
  oauth_client,
  token,
  async = FALSE,
  introspect = FALSE
) {
  S7::check_is_S7(oauth_client, OAuthClient)
  S7::check_is_S7(token, OAuthToken)
  stopifnot(
    is.logical(async),
    length(async) == 1,
    !is.na(async),
    is.logical(introspect),
    length(introspect) == 1,
    !is.na(introspect)
  )

  # Optional async execution using promises if requested and available.
  if (isTRUE(async)) {
    rlang::check_installed(
      c("promises", "future"),
      reason = "to use `async = TRUE` in `refresh_token()`"
    )

    return(promises::future_promise({
      refresh_token(
        oauth_client = oauth_client,
        token = token,
        async = FALSE,
        introspect = introspect
      )
    }))
  }
  if (!is_valid_string(token@refresh_token)) {
    err_input("No refresh token available")
  }

  params <- list(
    grant_type = "refresh_token",
    refresh_token = token@refresh_token
  )
  # Allow provider to add custom token params (mirrors login path)
  if (length(oauth_client@provider@extra_token_params) > 0) {
    params <- c(params, oauth_client@provider@extra_token_params)
  }

  req <- httr2::request(oauth_client@provider@token_url)

  tas <- oauth_client@provider@token_auth_style %||% "header"
  if (identical(tas, "header")) {
    req <- req |>
      httr2::req_auth_basic(oauth_client@client_id, oauth_client@client_secret)
  } else if (identical(tas, "body")) {
    params$client_id <- oauth_client@client_id
    if (is_valid_string(oauth_client@client_secret)) {
      params$client_secret <- oauth_client@client_secret
    }
  } else if (
    identical(tas, "client_secret_jwt") || identical(tas, "private_key_jwt")
  ) {
    params$client_id <- oauth_client@client_id
    params$client_assertion_type <-
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    params$client_assertion <- build_client_assertion(
      oauth_client,
      aud = resolve_client_assertion_audience(oauth_client, req)
    )
  }

  req <- add_req_defaults(req)
  # Allow provider to add custom token headers (mirrors login path)
  extra_headers <- as.list(oauth_client@provider@extra_token_headers)
  if (length(extra_headers)) {
    req <- do.call(httr2::req_headers, c(list(req), extra_headers))
  }
  req <- do.call(httr2::req_body_form, c(list(req), params))
  # Perform request with retry for transient failures
  resp <- req_with_retry(req)

  if (httr2::resp_is_error(resp)) {
    err_http(
      c("x" = "Token refresh failed"),
      resp,
      context = list(phase = "refresh_token")
    )
  }

  tok <- parse_token_response(resp)
  # Normalize expires_in when provided as a quoted number (form or JSON)
  if (!is.null(tok$expires_in)) {
    tok$expires_in <- coerce_expires_in(tok$expires_in)
  }

  # Validate expires_in if present (align with swap_code_for_token_set())
  if (!is.null(tok$expires_in)) {
    if (
      !is.numeric(tok$expires_in) ||
        length(tok$expires_in) != 1L ||
        !is.finite(tok$expires_in) ||
        tok$expires_in < 0
    ) {
      err_token(
        "Invalid expires_in in token response",
        context = list(phase = "refresh_token")
      )
    }

    if (tok$expires_in <= 0) {
      warn_about_nonpositive_expires_in(tok$expires_in, phase = "refresh_token")
    }
  }

  # Verify the response contains a new access token
  if (!is_valid_string(tok$access_token)) {
    err_token(
      "Token response missing access_token",
      context = list(phase = "refresh_token")
    )
  }

  # If configured, (re-)fetch userinfo using the fresh access token
  if (isTRUE(oauth_client@provider@userinfo_required)) {
    ui <- get_userinfo(oauth_client, token = tok$access_token)
    tok$userinfo <- ui
  }

  # Verify token set. During refresh (is_refresh = TRUE):
  # - ID token is NOT required (OIDC allows omission per Section 12.2)
  # - If ID token IS present and id_token_validation = TRUE, it's validated
  #   and its sub MUST match the original (OIDC 12.2)
  # - userinfo_id_token_match runs when both userinfo and id_token are present
  token_set <- list(
    access_token = tok$access_token,
    token_type = tok$token_type,
    refresh_token = tok$refresh_token,
    id_token = tok$id_token,
    userinfo = tok$userinfo,
    expires_in = tok$expires_in
  )
  token_set <- verify_token_set(
    oauth_client,
    token_set = token_set,
    nonce = NULL,
    is_refresh = TRUE,
    original_id_token = token@id_token
  )

  # Align expiry handling with login path: expires_in==0 means "expires now".
  expires_at <- if (
    is.numeric(token_set$expires_in) && is.finite(token_set$expires_in)
  ) {
    as.numeric(Sys.time()) + as.numeric(token_set$expires_in)
  } else {
    Inf
  }

  token@access_token <- token_set$access_token
  # Only replace the stored refresh_token when the provider actually rotates it
  # with a non-empty string. Some providers include an empty field to signal
  # "no change"; in that case, keep the existing refresh token.
  if (is_valid_string(token_set$refresh_token)) {
    token@refresh_token <- token_set$refresh_token
  }
  token@expires_at <- expires_at

  # ID token: update only if provider returned a new one (and it passed
  # validation if id_token_validation = TRUE). Otherwise preserve the original
  # from login - this is the common case per OIDC spec.
  if (is_valid_string(token_set$id_token)) {
    token@id_token <- token_set$id_token
  }

  # Userinfo: update if fetched during refresh (userinfo_required = TRUE)
  if (!is.null(token_set$userinfo)) {
    token@userinfo <- token_set$userinfo
  }

  # Optionally introspect the fresh access token (result currently not stored)
  if (isTRUE(introspect)) {
    try(
      introspect_token(oauth_client, token, which = "access", async = FALSE),
      silent = TRUE
    )
  }
  # Emit audit event for refresh
  audit_event(
    "token_refresh",
    context = list(
      provider = oauth_client@provider@name %||% NA_character_,
      issuer = oauth_client@provider@issuer %||% NA_character_,
      client_id_digest = string_digest(oauth_client@client_id),
      had_refresh_token = !is.na(token@refresh_token) &&
        nzchar(token@refresh_token),
      new_expires_at = token@expires_at
    )
  )

  token
}
