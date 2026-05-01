# This file contains the token lifecycle functions that run after login succeeds.
# Use them to revoke tokens, ask a provider whether a token is still active,
# or refresh a session without sending the user through login again.

# 1 Token lifecycle and response policy -----------------------------------

## 1.1 Revocation ---------------------------------------------------------

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
#' @param async Logical, default FALSE. If TRUE and an async backend is
#'   configured, the operation is dispatched through shinyOAuth's async
#'   promise path and this function returns a promise-compatible async result
#'   that resolves to the result list. [mirai] is preferred when daemons are
#'   configured via [mirai::daemons()]; otherwise the current [future] plan is
#'   used. Non-sequential future plans run off the main R session;
#'   `future::sequential()` stays in-process.
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
  async_attr <- isTRUE(tryCatch(shiny_session$is_async, error = function(...) {
    NULL
  })) ||
    isTRUE(get_async_session_context()$is_async) ||
    isTRUE(is_async_worker_context())
  trace_id <- resolve_trace_id()

  with_trace_id(trace_id, {
    if (isTRUE(async)) {
      return(dispatch_token_async(
        function_name = "revoke_token",
        call_args = list(
          oauth_client = oauth_client,
          oauth_token = oauth_token,
          which = which
        ),
        client = oauth_client,
        shiny_session = shiny_session,
        trace_id = trace_id,
        span_name = "shinyOAuth.token.revoke",
        phase = "token.revoke",
        worker_span_name = "shinyOAuth.token.revoke.worker",
        worker_phase = "token.revoke.worker",
        parent_extra = list(
          oauth.token.which = which,
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = 0L,
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        ),
        worker_extra = list(oauth.token.which = which)
      ))
    }

    with_otel_span(
      "shinyOAuth.token.revoke",
      {
        # Attach the final revoke result to the active span before returning it.
        # Used only inside revoke_token() after each success or fallback path.
        # Input: result list. Output: the same result list after span attributes are updated.
        .return_revoke_result <- function(result) {
          revoked <- result$revoked %||% NA
          otel_set_span_attributes(
            attributes = compact_list(list(
              oauth.token.which = which,
              oauth.supported = isTRUE(result$supported),
              oauth.revoked = if (length(revoked) == 1L && !is.na(revoked)) {
                isTRUE(revoked)
              } else {
                NULL
              },
              oauth.status = result$status %||% NULL
            ))
          )
          result
        }

        url <- resolve_provider_endpoint_url(
          oauth_client@provider,
          "revocation_endpoint",
          prefer_mtls = client_uses_mtls_endpoint(
            oauth_client,
            token = oauth_token
          )
        ) %||%
          NA_character_
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
          return(.return_revoke_result(list(
            supported = FALSE,
            revoked = NA,
            status = "revocation_unsupported"
          )))
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
          return(.return_revoke_result(list(
            supported = TRUE,
            revoked = NA,
            status = "missing_token"
          )))
        }

        params <- list(token = tok_val)
        params$token_type_hint <- if (which == "access") {
          "access_token"
        } else {
          "refresh_token"
        }

        req <- httr2::request(url)
        prepared <- apply_direct_client_auth(
          req = req,
          params = params,
          client = oauth_client,
          context = "revoke_token"
        )
        req <- prepared$req
        params <- prepared$params
        req <- req_apply_authorization_server_mtls(
          req,
          oauth_client,
          token = oauth_token
        )

        req <- add_req_defaults(req)
        req <- req_no_redirect(req)
        extra_headers <- as.list(oauth_client@provider@extra_token_headers)
        if (length(extra_headers)) {
          req <- do.call(httr2::req_headers, c(list(req), extra_headers))
        }
        req <- do.call(httr2::req_body_form, c(list(req), params))
        req <- httr2::req_method(req, "POST")
        req <- httr2::req_error(req, is_error = function(resp) FALSE)
        resp <- with_otel_span(
          "shinyOAuth.token.revoke.http",
          {
            resp <- req_with_dpop_retry(req, oauth_client)
            otel_record_http_result(resp)
            resp
          },
          attributes = otel_http_attributes(
            method = "POST",
            url = url,
            extra = list(oauth.phase = "token.revoke")
          ),
          options = list(kind = "client"),
          mark_ok = FALSE
        )

        redirect_err <- try(
          reject_redirect_response(resp, context = "token_revocation"),
          silent = TRUE
        )
        if (
          inherits(redirect_err, "try-error") || inherits(redirect_err, "error")
        ) {
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
          return(.return_revoke_result(list(
            supported = TRUE,
            revoked = NA,
            status = status_code
          )))
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
          return(.return_revoke_result(list(
            supported = TRUE,
            revoked = NA,
            status = status_code
          )))
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

        .return_revoke_result(list(
          supported = TRUE,
          revoked = TRUE,
          status = "ok"
        ))
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        async = async_attr,
        phase = "token.revoke",
        extra = list(
          oauth.token.which = which,
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = 0L,
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        )
      ),
      parent = if (isTRUE(async_attr)) NULL else NA
    )
  })
}

## 1.2 Introspection ------------------------------------------------------

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
#'  - "public": form field `client_id` only; `client_secret` is never sent.
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
#' @param async Logical, default FALSE. If TRUE and an async backend is
#'   configured, the operation is dispatched through shinyOAuth's async
#'   promise path and this function returns a promise-compatible async result
#'   that resolves to the result list. [mirai] is preferred when daemons are
#'   configured via [mirai::daemons()]; otherwise the current [future] plan is
#'   used. Non-sequential future plans run off the main R session;
#'   `future::sequential()` stays in-process.
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
  async_attr <- isTRUE(tryCatch(shiny_session$is_async, error = function(...) {
    NULL
  })) ||
    isTRUE(get_async_session_context()$is_async) ||
    isTRUE(is_async_worker_context())
  trace_id <- resolve_trace_id()

  # Write one redacted audit record for the final introspection result.
  # Used only inside introspect_token() after the provider response has been normalized.
  # Input: result list. Output: invisible NULL.
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

  with_trace_id(trace_id, {
    if (isTRUE(async)) {
      return(dispatch_token_async(
        function_name = "introspect_token",
        call_args = list(
          oauth_client = oauth_client,
          oauth_token = oauth_token,
          which = which
        ),
        client = oauth_client,
        shiny_session = shiny_session,
        trace_id = trace_id,
        span_name = "shinyOAuth.token.introspect",
        phase = "token.introspect",
        worker_span_name = "shinyOAuth.token.introspect.worker",
        worker_phase = "token.introspect.worker",
        parent_extra = list(
          oauth.token.which = which,
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = 0L,
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        ),
        worker_extra = list(oauth.token.which = which)
      ))
    }
    with_otel_span(
      "shinyOAuth.token.introspect",
      {
        # Attach the final introspection result to the active span before returning it.
        # Used only inside introspect_token() after each success or fallback path.
        # Input: result list. Output: the same result list after span attributes are updated.
        .return_introspection_result <- function(result) {
          active <- result$active %||% NA
          otel_set_span_attributes(
            attributes = compact_list(list(
              oauth.token.which = which,
              oauth.supported = isTRUE(result$supported),
              oauth.active = if (length(active) == 1L && !is.na(active)) {
                isTRUE(active)
              } else {
                NULL
              },
              oauth.status = result$status %||% NULL
            ))
          )
          result
        }

        url <- resolve_provider_endpoint_url(
          oauth_client@provider,
          "introspection_endpoint",
          prefer_mtls = client_uses_mtls_endpoint(
            oauth_client,
            token = oauth_token
          )
        ) %||%
          NA_character_
        if (!is_valid_string(url)) {
          result <- list(
            supported = FALSE,
            active = NA,
            raw = NULL,
            status = "introspection_unsupported"
          )
          .audit_introspection(result)
          return(.return_introspection_result(result))
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
          return(.return_introspection_result(result))
        }

        params <- list(token = tok_val)
        if (which == "refresh") {
          params$token_type_hint <- "refresh_token"
        } else {
          params$token_type_hint <- "access_token"
        }

        req <- httr2::request(url)
        prepared <- apply_direct_client_auth(
          req = req,
          params = params,
          client = oauth_client,
          context = "introspect_token"
        )
        req <- prepared$req
        params <- prepared$params
        req <- req_apply_authorization_server_mtls(
          req,
          oauth_client,
          token = oauth_token
        )
        req <- add_req_defaults(req)
        req <- req_no_redirect(req)
        extra_headers <- as.list(oauth_client@provider@extra_token_headers)
        if (length(extra_headers)) {
          req <- do.call(httr2::req_headers, c(list(req), extra_headers))
        }
        req <- do.call(httr2::req_body_form, c(list(req), params))
        req <- httr2::req_method(req, "POST")
        req <- httr2::req_error(req, is_error = function(resp) FALSE)
        resp <- with_otel_span(
          "shinyOAuth.token.introspect.http",
          {
            resp <- req_with_dpop_retry(req, oauth_client)
            otel_record_http_result(resp)
            resp
          },
          attributes = otel_http_attributes(
            method = "POST",
            url = url,
            extra = list(oauth.phase = "token.introspect")
          ),
          options = list(kind = "client"),
          mark_ok = FALSE
        )

        redirect_err <- try(
          reject_redirect_response(resp, context = "token_introspection"),
          silent = TRUE
        )
        if (
          inherits(redirect_err, "try-error") || inherits(redirect_err, "error")
        ) {
          result <- list(
            supported = TRUE,
            active = NA,
            raw = NULL,
            status = paste0("http_", httr2::resp_status(resp))
          )
          .audit_introspection(result)
          return(.return_introspection_result(result))
        }

        if (httr2::resp_is_error(resp)) {
          result <- list(
            supported = TRUE,
            active = NA,
            raw = NULL,
            status = paste0("http_", httr2::resp_status(resp))
          )
          .audit_introspection(result)
          return(.return_introspection_result(result))
        }
        raw <- NULL
        active <- NA
        status <- "ok"
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
          return(.return_introspection_result(result))
        }

        body_txt <- httr2::resp_body_string(resp)
        parsed <- try(
          {
            reject_duplicate_json_object_members(
              body_txt,
              "Introspection response JSON"
            )
            jsonlite::fromJSON(body_txt, simplifyVector = TRUE)
          },
          silent = TRUE
        )

        if (inherits(parsed, "try-error") || !is.list(parsed)) {
          status <- "invalid_json"
          raw <- NULL
        } else {
          raw <- parsed
          # Normalize the provider's `active` field into TRUE/FALSE/NA.
          # Used only inside introspect_token() because providers encode this field in different ways.
          # Input: raw `active` value. Output: logical TRUE/FALSE or NA when it cannot be trusted.
          coerce_active <- function(x) {
            if (is.logical(x)) {
              return(ifelse(length(x) >= 1L, x[[1]], NA))
            }
            if (is.numeric(x)) {
              xv <- suppressWarnings(as.numeric(x[[1]]))
              if (length(xv) == 1L && !is.na(xv)) {
                return(xv != 0)
              }
              return(NA)
            }
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

        if (identical(status, "ok") && is.null(raw)) {
          status <- "invalid_json"
        }
        if (identical(status, "ok") && is.na(active)) {
          status <- "missing_active"
        }

        result <- list(
          supported = TRUE,
          active = active,
          raw = raw,
          status = status
        )

        .audit_introspection(result)
        .return_introspection_result(result)
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        async = async_attr,
        phase = "token.introspect",
        extra = list(
          oauth.token.which = which,
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = 0L,
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        )
      ),
      parent = if (isTRUE(async_attr)) NULL else NA
    )
  })
}

## 1.3 Refresh ------------------------------------------------------------

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
#' access token. If `userinfo_id_token_match = TRUE`, refreshed userinfo is
#' checked against the refresh ID token when one is returned, otherwise against
#' the preserved original ID token from the initial login. If no trustworthy ID
#' token baseline is available, refresh fails instead of updating userinfo.
#'
#' @param oauth_client [OAuthClient] object
#' @param token [OAuthToken] object containing the refresh token
#' @param async Logical, default FALSE. If TRUE and an async backend is
#'   configured, the refresh is dispatched through shinyOAuth's async promise
#'   path and this function returns a promise-compatible async result that
#'   resolves to an updated `OAuthToken`. [mirai] is preferred when daemons are
#'   configured via [mirai::daemons()]; otherwise the current [future] plan is
#'   used. Non-sequential future plans run off the main R session;
#'   `future::sequential()` stays in-process.
#' @param introspect Logical, default FALSE. After a successful refresh, if the
#'   provider exposes an introspection endpoint, perform a best-effort
#'   introspection of the new access token for audit/diagnostics. The raw
#'   introspection result is not stored separately, but a successful
#'   introspection response may backfill `token@cnf`.
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events. Used when
#'   calling from async workers that lack access to the reactive domain.
#'
#' @return An updated [OAuthToken] object with refreshed credentials.
#'
#'   **What changes:**
#'   - `access_token`: Always updated to the fresh token
#'   - `expires_at`: Computed from `expires_in` when provided; otherwise a
#'     finite fallback expiry from `resolve_missing_expires_in()`
#'   - `refresh_token`: Updated if the provider rotates it; otherwise preserved
#'   - `id_token`: Updated only if the provider returns one (and it validates);
#'     otherwise the original from login is preserved
#'   - `userinfo`: Refreshed if `userinfo_required = TRUE`; otherwise preserved
#'   - `cnf`: Updated from the token response when present, and may be
#'     backfilled from refresh-time introspection when enabled
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

  async_attr <- isTRUE(tryCatch(shiny_session$is_async, error = function(...) {
    NULL
  })) ||
    isTRUE(get_async_session_context()$is_async) ||
    isTRUE(is_async_worker_context())
  trace_id <- resolve_trace_id()

  # Optional async execution using mirai if requested and available.
  with_trace_id(trace_id, {
    if (isTRUE(async)) {
      return(dispatch_token_async(
        function_name = "refresh_token",
        call_args = list(
          oauth_client = oauth_client,
          token = token,
          introspect = introspect
        ),
        client = oauth_client,
        shiny_session = shiny_session,
        trace_id = trace_id,
        span_name = "shinyOAuth.refresh",
        phase = "refresh",
        worker_span_name = "shinyOAuth.refresh.worker",
        worker_phase = "refresh.worker",
        parent_extra = list(
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = otel_count_items(
            oauth_client@provider@extra_token_params
          ),
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        )
      ))
    }
    with_otel_span(
      "shinyOAuth.refresh",
      {
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
        if (length(oauth_client@resource) > 0) {
          params$resource <- oauth_client@resource
        }
        # Allow provider to add custom token params (mirrors login path)
        if (length(oauth_client@provider@extra_token_params) > 0) {
          params <- c(params, oauth_client@provider@extra_token_params)
        }

        token_url <- resolve_provider_endpoint_url(
          oauth_client@provider,
          "token_endpoint",
          prefer_mtls = client_uses_mtls_endpoint(
            oauth_client,
            token = token
          )
        )

        req <- httr2::request(token_url)
        prepared <- apply_direct_client_auth(
          req = req,
          params = params,
          client = oauth_client,
          context = "refresh_token"
        )
        req <- prepared$req
        params <- prepared$params
        req <- req_apply_authorization_server_mtls(
          req,
          oauth_client,
          token = token
        )

        req <- add_req_defaults(req)
        req <- req_no_redirect(req)
        # Allow provider to add custom token headers (mirrors login path)
        extra_headers <- as.list(oauth_client@provider@extra_token_headers)
        if (length(extra_headers)) {
          req <- do.call(httr2::req_headers, c(list(req), extra_headers))
        }
        req <- req_body_form_encoded(req, compact_list(params))
        req <- httr2::req_method(req, "POST")
        resp <- with_otel_span(
          "shinyOAuth.token.exchange.http",
          {
            # Refresh may consume a rotatable refresh token; do not retry.
            resp <- req_with_dpop_retry(req, oauth_client, idempotent = FALSE)
            otel_record_http_result(resp)
            resp
          },
          attributes = otel_http_attributes(
            method = "POST",
            url = token_url,
            extra = list(oauth.phase = "refresh")
          ),
          options = list(kind = "client"),
          mark_ok = FALSE
        )

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

        otel_set_span_attributes(
          attributes = otel_token_response_attributes(tok)
        )

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
            warn_about_nonpositive_expires_in(
              tok$expires_in,
              phase = "refresh_token"
            )
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

        token_set <- list(
          access_token = tok$access_token,
          token_type = tok$token_type,
          refresh_token = tok$refresh_token,
          id_token = tok$id_token,
          cnf = tok$cnf,
          userinfo = NULL,
          expires_in = tok$expires_in,
          scope = tok$scope
        )
        token_set <- verify_token_set(
          oauth_client,
          token_set = token_set,
          nonce = NULL,
          is_refresh = TRUE,
          original_id_token = token@id_token,
          shiny_session = shiny_session
        )

        if (isTRUE(oauth_client@provider@userinfo_required)) {
          userinfo_token <- OAuthToken(
            access_token = token_set$access_token,
            token_type = token_set$token_type %||% NA_character_,
            userinfo = list(),
            cnf = resolve_token_cnf(
              cnf = token_set$cnf,
              access_token = token_set$access_token
            )
          )
          ui <- call_with_optional_shiny_session(
            get_userinfo,
            oauth_client = oauth_client,
            token = userinfo_token,
            shiny_session = shiny_session
          )

          if (isTRUE(oauth_client@provider@userinfo_id_token_match)) {
            baseline_id_token <- token_set[["id_token"]]
            if (!is_valid_string(baseline_id_token)) {
              baseline_id_token <- token@id_token
            }

            if (!is_valid_string(baseline_id_token)) {
              err_userinfo(c(
                "x" = "Cannot verify refreshed userinfo subject",
                "i" = paste(
                  "userinfo_id_token_match = TRUE requires a new or preserved",
                  "ID token during refresh"
                )
              ))
            }

            verify_userinfo_id_token_subject_match(
              oauth_client,
              userinfo = ui,
              id_token = baseline_id_token
            )
          }

          validate_essential_claims(oauth_client, ui, "userinfo")
          token_set$userinfo <- ui
        }

        expires_at <- if (
          is.numeric(token_set$expires_in) && is.finite(token_set$expires_in)
        ) {
          as.numeric(Sys.time()) + as.numeric(token_set$expires_in)
        } else {
          resolve_missing_expires_in(phase = "refresh_token")
        }

        token@access_token <- token_set$access_token
        if (is_valid_string(token_set$refresh_token)) {
          token@refresh_token <- token_set$refresh_token
        }
        if (is_valid_string(token_set$token_type)) {
          token@token_type <- token_set$token_type
        }
        token@expires_at <- expires_at

        if (is_valid_string(token_set$id_token)) {
          token@id_token <- token_set$id_token
          token@id_token_validated <- isTRUE(token_set[[".id_token_validated"]])
        }
        token@cnf <- resolve_token_cnf(
          cnf = token_set$cnf,
          access_token = token_set$access_token
        )

        if (!is.null(token_set$userinfo)) {
          token@userinfo <- token_set$userinfo
        }

        if (isTRUE(introspect)) {
          intro_res <- try(
            introspect_token(
              oauth_client,
              token,
              which = "access",
              async = FALSE,
              shiny_session = shiny_session
            ),
            silent = TRUE
          )
          if (!inherits(intro_res, "try-error")) {
            token@cnf <- resolve_token_cnf(
              cnf = token@cnf,
              access_token = token@access_token,
              introspection_result = intro_res
            )
          }
        }

        audit_event(
          "token_refresh",
          context = list(
            provider = oauth_client@provider@name %||% NA_character_,
            issuer = oauth_client@provider@issuer %||% NA_character_,
            client_id_digest = string_digest(oauth_client@client_id),
            refresh_token_rotated = is_valid_string(token_set$refresh_token) &&
              !identical(token_set$refresh_token, pre_refresh_token),
            new_expires_at = token@expires_at,
            expires_in_synthesized = !(is.numeric(token_set$expires_in) &&
              is.finite(token_set$expires_in))
          ),
          shiny_session = shiny_session
        )

        token
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        async = async_attr,
        phase = "refresh",
        extra = list(
          oauth.client_auth_style = otel_client_auth_style(oauth_client),
          oauth.extra_token_params_count = otel_count_items(
            oauth_client@provider@extra_token_params
          ),
          oauth.extra_token_headers_count = otel_count_items(
            oauth_client@provider@extra_token_headers
          )
        )
      ),
      parent = if (isTRUE(async_attr)) NULL else NA
    )
  })
}

# 2 Async execution helpers -----------------------------------------------

## 2.1 Shared token-method async wrapper ----------------------------------

# Dispatch one token method through the shared async wrapper.
# Used by revoke_token(), introspect_token(), and refresh_token() so trace,
# option, session, and OTEL propagation stay in one place. Input: function
# name plus call args, client/session context, trace id, and span metadata.
# Output: a promise resolving to the underlying method result.
dispatch_token_async <- function(
  function_name,
  call_args,
  client,
  shiny_session,
  trace_id,
  span_name,
  phase,
  worker_span_name,
  worker_phase,
  parent_extra = list(),
  worker_extra = list()
) {
  captured_shiny_session <- shiny_session
  captured_trace_id <- trace_id
  parent_shiny_session <- normalize_shiny_session_context(shiny_session)

  # Capture shinyOAuth.* options for propagation to the async worker.
  # This ensures audit hooks, HTTP settings, and other options are
  # available in the worker process.
  captured_async_options <- capture_async_options()
  otel_parent <- otel_start_async_parent(
    span_name,
    attributes = otel_client_attributes(
      client = client,
      shiny_session = parent_shiny_session,
      async = TRUE,
      phase = phase,
      extra = parent_extra
    )
  )

  # Use namespace-qualified lookup inside the worker to avoid serializing
  # function closures and to keep the worker running the installed package.
  promise <- tryCatch(
    async_dispatch(
      expr = quote({
        .ns <- asNamespace("shinyOAuth")
        .fn <- get(function_name, envir = .ns, inherits = FALSE)
        .ns$with_trace_id(captured_trace_id, {
          .ns$with_async_options(captured_async_options, {
            .ns$with_async_session_context(captured_shiny_session, {
              do.call(
                .fn,
                c(
                  call_args,
                  list(
                    async = FALSE,
                    shiny_session = captured_shiny_session
                  )
                )
              )
            })
          })
        })
      }),
      args = list(
        function_name = function_name,
        call_args = call_args,
        captured_trace_id = captured_trace_id,
        captured_async_options = captured_async_options,
        captured_shiny_session = captured_shiny_session
      ),
      otel_context = list(
        headers = otel_parent$headers,
        worker_span_name = worker_span_name,
        shiny_session = captured_shiny_session,
        attributes = otel_client_attributes(
          client = client,
          shiny_session = shiny_session,
          async = TRUE,
          phase = worker_phase,
          extra = worker_extra
        )
      )
    ),
    error = function(e) {
      otel_end_async_parent(otel_parent, status = "error", error = e)
      stop(e)
    }
  )

  promise |>
    promises::then(function(value) {
      otel_end_async_parent(otel_parent, status = "ok")
      replay_async_conditions(value)
    }) |>
    promises::catch(function(err) {
      otel_end_async_parent(otel_parent, status = "error", error = err)
      stop(err)
    })
}
