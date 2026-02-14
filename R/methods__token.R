# This file contains methods to introspect and refresh an OAuthToken

#' @title
#' Revoke an OAuth 2.0 token
#'
#' @description
#' Attempts to revoke an access or refresh token using RFC 7009 when the
#' provider exposes a revocation endpoint.
#'
#' Authentication mirrors the provider's `token_auth_style` (same as token
#' exchange and introspection).
#'
#' Best-effort semantics:
#' - If the provider does not expose a revocation endpoint, returns
#'   `supported = FALSE`, `revoked = NA`, and `status = "revocation_unsupported"`.
#' - If the selected token value is missing, returns `supported = TRUE`,
#'   `revoked = NA`, and `status = "missing_token"`.
#' - If the endpoint returns a 2xx, returns `supported = TRUE`, `revoked = TRUE`,
#'   and `status = "ok"`.
#' - If the endpoint returns an HTTP error, returns `supported = TRUE`,
#'   `revoked = NA`, and `status = "http_<code>"`.
#'
#' @param oauth_client [OAuthClient] object
#' @param oauth_token [OAuthToken] object containing tokens to revoke
#' @param which Which token to revoke: "refresh" (default) or "access"
#' @param async Logical, default FALSE. If TRUE and the [mirai] package is
#'   available, the operation is performed off the main R session using
#'   `mirai::mirai()` and this function returns a mirai (which implements
#'   `as.promise()`) that resolves to the result list. Requires mirai
#'   daemons to be configured with [mirai::daemons()].
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#'
#' @return A list with fields: supported, revoked, status
#'
#' @export
revoke_token <- function(
  oauth_client,
  oauth_token,
  which = c("refresh", "access"),
  async = FALSE,
  shiny_session = NULL
) {
  S7::check_is_S7(oauth_client, OAuthClient)
  S7::check_is_S7(oauth_token, OAuthToken)
  if (!(is.logical(async) && length(async) == 1 && !is.na(async))) {
    err_input("{.arg async} must be a single non-NA logical.")
  }

  which <- match.arg(which)

  url <- oauth_client@provider@revocation_url %||% NA_character_
  if (!is_valid_string(url)) {
    try(
      audit_event(
        "token_revocation",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          which = which,
          supported = FALSE,
          revoked = NA,
          status = "revocation_unsupported"
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
    return(list(
      supported = FALSE,
      revoked = NA,
      status = "revocation_unsupported"
    ))
  }

  if (isTRUE(async)) {
    # Capture shiny_session for propagation into the async worker
    captured_shiny_session <- shiny_session

    # Capture shinyOAuth.* options for propagation to the async worker.
    # This ensures audit hooks, HTTP settings, and other options are
    # available in the worker process.
    captured_async_options <- capture_async_options()

    # Use namespace-qualified calls to avoid passing function closures to mirai
    # (functions carry their enclosing environments, causing serialization overhead)
    return(async_dispatch(
      expr = quote({
        .ns <- asNamespace("shinyOAuth")
        # Restore shinyOAuth.* options in the async worker
        .ns$with_async_options(captured_async_options, {
          # Set async context so errors include session info with is_async = TRUE
          .ns$with_async_session_context(captured_shiny_session, {
            shinyOAuth::revoke_token(
              oauth_client = oauth_client,
              oauth_token = oauth_token,
              which = which,
              async = FALSE,
              shiny_session = captured_shiny_session
            )
          })
        })
      }),
      args = list(
        captured_async_options = captured_async_options,
        captured_shiny_session = captured_shiny_session,
        oauth_client = oauth_client,
        oauth_token = oauth_token,
        which = which
      )
    ))
  }

  tok_val <- if (which == "access") {
    oauth_token@access_token
  } else {
    oauth_token@refresh_token
  }

  if (!is_valid_string(tok_val)) {
    try(
      audit_event(
        "token_revocation",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          which = which,
          supported = TRUE,
          revoked = NA,
          status = "missing_token"
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
    return(list(
      supported = TRUE,
      revoked = NA,
      status = "missing_token"
    ))
  }

  params <- list(token = tok_val)
  params$token_type_hint <- if (which == "access") {
    "access_token"
  } else {
    "refresh_token"
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
      aud = resolve_client_assertion_audience(oauth_client, req)
    )
  } else {
    err_config(
      c(
        "x" = "Unsupported token_auth_style for revocation.",
        "i" = paste0(
          "Got: '",
          tas,
          "'. Allowed: 'header', 'body', 'client_secret_jwt', 'private_key_jwt'."
        )
      ),
      context = list(phase = "revoke_token", style = tas)
    )
  }

  req <- add_req_defaults(req)
  req <- req_no_redirect(req)
  # Apply any extra token headers (mirrors exchange/refresh paths)
  extra_headers <- as.list(oauth_client@provider@extra_token_headers)
  if (length(extra_headers)) {
    req <- do.call(httr2::req_headers, c(list(req), extra_headers))
  }
  req <- do.call(httr2::req_body_form, c(list(req), params))
  req <- httr2::req_error(req, is_error = function(resp) FALSE)
  resp <- req_with_retry(req)

  # Security: reject redirect responses to prevent credential leakage
  # For revocation, we catch the error and return a structured result
  redirect_err <- try(
    reject_redirect_response(resp, context = "token_revocation"),
    silent = TRUE
  )
  if (inherits(redirect_err, "try-error") || inherits(redirect_err, "error")) {
    status_code <- paste0("http_", httr2::resp_status(resp))
    try(
      audit_event(
        "token_revocation",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          which = which,
          supported = TRUE,
          revoked = NA,
          status = status_code
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
    return(list(
      supported = TRUE,
      revoked = NA,
      status = status_code
    ))
  }

  if (httr2::resp_is_error(resp)) {
    status_code <- paste0("http_", httr2::resp_status(resp))
    try(
      audit_event(
        "token_revocation",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          which = which,
          supported = TRUE,
          revoked = NA,
          status = status_code
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )
    return(list(
      supported = TRUE,
      revoked = NA,
      status = status_code
    ))
  }

  try(
    audit_event(
      "token_revocation",
      context = list(
        provider = oauth_client@provider@name %||% NA_character_,
        issuer = oauth_client@provider@issuer %||% NA_character_,
        client_id_digest = string_digest(oauth_client@client_id),
        which = which,
        supported = TRUE,
        revoked = TRUE,
        status = "ok"
      ),
      shiny_session = shiny_session
    ),
    silent = TRUE
  )

  list(
    supported = TRUE,
    revoked = TRUE,
    status = "ok"
  )
}

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
#'    `client_assertion`, with `aud` resolved via
#'    `resolve_client_assertion_audience()` (so `client_assertion_audience`
#'    overrides are honored).
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
#' @param async Logical, default FALSE. If TRUE and the [mirai] package is
#'   available, the operation is performed off the main R session using
#'   `mirai::mirai()` and this function returns a mirai (which implements
#'   `as.promise()`) that resolves to the result list. Requires mirai
#'   daemons to be configured with [mirai::daemons()].
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
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
  async = FALSE,
  shiny_session = NULL
) {
  # Type checks
  S7::check_is_S7(oauth_client, OAuthClient)
  S7::check_is_S7(oauth_token, OAuthToken)
  if (!(is.logical(async) && length(async) == 1 && !is.na(async))) {
    err_input("{.arg async} must be a single non-NA logical.")
  }

  which <- match.arg(which)

  .audit_introspection <- function(result) {
    # Best-effort audit logging for introspection (do not fail the caller).
    # Avoid including raw introspection payloads as they may contain PII.
    raw <- result$raw %||% NULL
    if (!is.list(raw)) {
      raw <- NULL
    }

    # Include digested identifiers when present in raw payload.
    sub_digest <- NA_character_
    if (!is.null(raw) && is_valid_string(raw$sub %||% NA_character_)) {
      sub_digest <- string_digest(as.character(raw$sub)[1])
    }
    introspected_client_id_digest <- NA_character_
    if (!is.null(raw) && is_valid_string(raw$client_id %||% NA_character_)) {
      introspected_client_id_digest <- string_digest(as.character(
        raw$client_id
      )[1])
    }
    scope_digest <- NA_character_
    if (
      !is.null(raw) &&
        !is.null(raw$scope) &&
        is_valid_string(as.character(raw$scope)[1])
    ) {
      scope_digest <- string_digest(as.character(raw$scope)[1])
    }

    try(
      audit_event(
        "token_introspection",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          which = which,
          supported = isTRUE(result$supported),
          active = if (is.na(result$active)) NA else isTRUE(result$active),
          status = result$status %||% NA_character_,
          sub_digest = sub_digest,
          introspected_client_id_digest = introspected_client_id_digest,
          scope_digest = scope_digest
        ),
        shiny_session = shiny_session
      ),
      silent = TRUE
    )

    invisible(NULL)
  }

  url <- oauth_client@provider@introspection_url %||% NA_character_
  if (!is_valid_string(url)) {
    result <- list(
      supported = FALSE,
      active = NA,
      raw = NULL,
      status = "introspection_unsupported"
    )
    .audit_introspection(result)
    return(result)
  }

  if (isTRUE(async)) {
    # Capture shiny_session for propagation into the async worker
    captured_shiny_session <- shiny_session

    # Capture shinyOAuth.* options for propagation to the async worker.
    # This ensures audit hooks, HTTP settings, and other options are
    # available in the worker process.
    captured_async_options <- capture_async_options()

    # Use namespace-qualified calls to avoid passing function closures to mirai
    # (functions carry their enclosing environments, causing serialization overhead)
    return(async_dispatch(
      expr = quote({
        .ns <- asNamespace("shinyOAuth")
        # Restore shinyOAuth.* options in the async worker
        .ns$with_async_options(captured_async_options, {
          # Set async context so errors include session info with is_async = TRUE
          .ns$with_async_session_context(captured_shiny_session, {
            shinyOAuth::introspect_token(
              oauth_client = oauth_client,
              oauth_token = oauth_token,
              which = which,
              async = FALSE,
              shiny_session = captured_shiny_session
            )
          })
        })
      }),
      args = list(
        captured_async_options = captured_async_options,
        captured_shiny_session = captured_shiny_session,
        oauth_client = oauth_client,
        oauth_token = oauth_token,
        which = which
      )
    ))
  }

  tok_val <- if (which == "access") {
    oauth_token@access_token
  } else {
    oauth_token@refresh_token
  }
  if (!is_valid_string(tok_val)) {
    result <- list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = "missing_token"
    )
    .audit_introspection(result)
    return(result)
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
      aud = resolve_client_assertion_audience(oauth_client, req)
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
  req <- req_no_redirect(req)
  # Apply any extra token headers (mirrors exchange/refresh paths)
  extra_headers <- as.list(oauth_client@provider@extra_token_headers)
  if (length(extra_headers)) {
    req <- do.call(httr2::req_headers, c(list(req), extra_headers))
  }
  req <- do.call(httr2::req_body_form, c(list(req), params))
  req <- httr2::req_error(req, is_error = function(resp) FALSE)
  # Perform request with retry for transient failures
  resp <- req_with_retry(req)

  # Security: reject redirect responses to prevent credential leakage
  # For introspection, catch and return structured result instead of throwing
  redirect_err <- try(
    reject_redirect_response(resp, context = "token_introspection"),
    silent = TRUE
  )
  if (inherits(redirect_err, "try-error") || inherits(redirect_err, "error")) {
    result <- list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = paste0("http_", httr2::resp_status(resp))
    )
    .audit_introspection(result)
    return(result)
  }

  if (httr2::resp_is_error(resp)) {
    # If the endpoint responds with an HTTP error (e.g., 404), we cannot
    # confirm token validity. Mark active as NA (unknown). The overall
    # all_passed logic requires active == TRUE when requested, so NA will
    # still result in all_passed = FALSE.
    result <- list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = paste0("http_", httr2::resp_status(resp))
    )
    .audit_introspection(result)
    return(result)
  }
  raw <- NULL
  active <- NA
  status <- "ok"
  # Guard against oversized introspection responses before parsing
  size_ok <- try(
    check_resp_body_size(resp, context = "introspection"),
    silent = TRUE
  )
  if (inherits(size_ok, "try-error")) {
    result <- list(
      supported = TRUE,
      active = NA,
      raw = NULL,
      status = "body_too_large"
    )
    .audit_introspection(result)
    return(result)
  }
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
  result <- list(
    supported = TRUE,
    active = active,
    raw = raw,
    status = status
  )

  .audit_introspection(result)
  result
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
#' @param async Logical, default FALSE. If TRUE and the [mirai] package is
#'   available, the refresh is performed off the main R session using
#'   `mirai::mirai()` and this function returns a mirai (which implements
#'   `as.promise()`) that resolves to an updated `OAuthToken`. Requires mirai
#'   daemons to be configured with [mirai::daemons()].
#' @param introspect Logical, default FALSE. After a successful refresh, if the
#'   provider exposes an introspection endpoint, perform a best-effort
#'   introspection of the new access token for audit/diagnostics. The result
#'   is not stored on the token object.
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
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
  introspect = FALSE,
  shiny_session = NULL
) {
  S7::check_is_S7(oauth_client, OAuthClient)
  S7::check_is_S7(token, OAuthToken)
  if (!(is.logical(async) && length(async) == 1 && !is.na(async))) {
    err_input("{.arg async} must be a single non-NA logical.")
  }
  if (
    !(is.logical(introspect) && length(introspect) == 1 && !is.na(introspect))
  ) {
    err_input("{.arg introspect} must be a single non-NA logical.")
  }

  # Optional async execution using mirai if requested and available.
  if (isTRUE(async)) {
    # Capture shiny_session for propagation into the async worker
    captured_shiny_session <- shiny_session

    # Capture shinyOAuth.* options for propagation to the async worker.
    # This ensures audit hooks, HTTP settings, and other options are
    # available in the worker process.
    captured_async_options <- capture_async_options()

    # Use namespace-qualified calls to avoid passing function closures to mirai
    # (functions carry their enclosing environments, causing serialization overhead)
    return(async_dispatch(
      expr = quote({
        .ns <- asNamespace("shinyOAuth")
        # Restore shinyOAuth.* options in the async worker
        .ns$with_async_options(captured_async_options, {
          # Set async context so errors include session info with is_async = TRUE
          .ns$with_async_session_context(captured_shiny_session, {
            shinyOAuth::refresh_token(
              oauth_client = oauth_client,
              token = token,
              async = FALSE,
              introspect = introspect,
              shiny_session = captured_shiny_session
            )
          })
        })
      }),
      args = list(
        captured_async_options = captured_async_options,
        captured_shiny_session = captured_shiny_session,
        oauth_client = oauth_client,
        token = token,
        introspect = introspect
      )
    ))
  }
  if (!is_valid_string(token@refresh_token)) {
    err_input("No refresh token available")
  }

  # Snapshot the pre-refresh refresh token so the audit event can report
  # whether the provider rotated it (returned a new one) or preserved it.
  pre_refresh_token <- token@refresh_token

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
  req <- req_no_redirect(req)
  # Allow provider to add custom token headers (mirrors login path)
  extra_headers <- as.list(oauth_client@provider@extra_token_headers)
  if (length(extra_headers)) {
    req <- do.call(httr2::req_headers, c(list(req), extra_headers))
  }
  req <- do.call(httr2::req_body_form, c(list(req), params))
  # Perform request with retry for transient failures
  resp <- req_with_retry(req)

  # Security: reject redirect responses to prevent credential leakage
  reject_redirect_response(resp, context = "token_refresh")

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

  # Validate token_type immediately after refresh, before any userinfo call.
  verify_token_type_allowlist(oauth_client, tok)

  # Verify token set BEFORE fetching userinfo. During refresh (is_refresh = TRUE):
  # - ID token is NOT required (OIDC allows omission per Section 12.2)
  # - If ID token IS present and id_token_validation = TRUE, it's validated
  #   and its sub MUST match the original (OIDC 12.2)
  # - scope: pass through provider's response; if NULL, verify_token_set skips
  #   scope validation per RFC 6749 Section 6 (omitted = unchanged)
  # Userinfo is fetched after this to ensure cryptographic validation occurs
  # before making external calls.
  token_set <- list(
    access_token = tok$access_token,
    token_type = tok$token_type,
    refresh_token = tok$refresh_token,
    id_token = tok$id_token,
    userinfo = NULL,
    expires_in = tok$expires_in,
    scope = tok$scope
  )
  token_set <- verify_token_set(
    oauth_client,
    token_set = token_set,
    nonce = NULL,
    is_refresh = TRUE,
    original_id_token = token@id_token
  )

  # Fetch userinfo AFTER ID token validation. This ordering ensures we only
  # make external calls after cryptographic validation passes.
  if (isTRUE(oauth_client@provider@userinfo_required)) {
    ui <- get_userinfo(oauth_client, token = tok$access_token)
    token_set$userinfo <- ui

    # Verify userinfo subject matches ID token subject (if configured).
    # Unlike initial login, this check requires id_token presence because OIDC
    # Core Section 12.2 allows providers to omit ID token from refresh responses.
    # If no ID token is returned, we skip the match (compliant behavior).
    if (
      isTRUE(oauth_client@provider@userinfo_id_token_match) &&
        is_valid_string(token_set[["id_token"]])
    ) {
      verify_userinfo_id_token_subject_match(
        oauth_client,
        userinfo = ui,
        id_token = token_set[["id_token"]]
      )
    }

    # Validate essential claims in userinfo (OIDC Core §5.5)
    validate_essential_claims(oauth_client, ui, "userinfo")
  }

  # Align expiry handling with login path: expires_in==0 means "expires now".
  expires_at <- if (
    is.numeric(token_set$expires_in) && is.finite(token_set$expires_in)
  ) {
    as.numeric(Sys.time()) + as.numeric(token_set$expires_in)
  } else {
    resolve_missing_expires_in(phase = "refresh_token")
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
    # Propagate whether the new ID token was cryptographically validated.
    token@id_token_validated <- isTRUE(token_set[[".id_token_validated"]])
  }

  # Userinfo: update if fetched during refresh (userinfo_required = TRUE)
  if (!is.null(token_set$userinfo)) {
    token@userinfo <- token_set$userinfo
  }

  # Optionally introspect the fresh access token (result currently not stored)
  if (isTRUE(introspect)) {
    try(
      introspect_token(
        oauth_client,
        token,
        which = "access",
        async = FALSE,
        shiny_session = shiny_session
      ),
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
      refresh_token_rotated = is_valid_string(token_set$refresh_token) &&
        !identical(token_set$refresh_token, pre_refresh_token),
      new_expires_at = token@expires_at
    ),
    shiny_session = shiny_session
  )

  token
}
