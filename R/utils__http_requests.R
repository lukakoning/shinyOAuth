# This file contains the shared HTTP request helpers used before talking to
# providers and downstream APIs
# Used for applying the package's defaults for redirects, timeouts, body-size
# limits, and retries

# 1 HTTP request helpers -------------------------------------------------------

## 1.1 Redirects, defaults, and retries ----------------------------------------

#' Internal: Disable HTTP redirect following
#'
#' Prevents httr2 from automatically following redirect responses (3xx) for
#' sensitive provider-facing requests such as token exchange, refresh,
#' introspection, revocation, UserInfo, OIDC discovery, and JWKS fetches.
#' Used by all outbound provider-facing requests because redirects can:
#'
#' - Leaking authorization codes, tokens, client secrets, PKCE verifiers, or
#'   other credentials to malicious or misconfigured redirect targets.
#' - Bypassing host validation (is_ok_host) since initial URL is validated but
#'   the redirected URL would not be.
#' - HTTPS downgrade attacks (HTTPS -> HTTP redirects would expose secrets).
#'
#' When a 3xx response is received, the request will return the redirect
#' response itself rather than following it, allowing callers to fail with a
#' clear error rather than silently leaking secrets.
#'
#' Behavior can be overridden via `options(shinyOAuth.allow_redirect = TRUE)`,
#' but this should only be enabled when a deployment deliberately accepts the
#' redirect-following risk for these sensitive endpoints.
#'
#' @param req httr2 request object.
#' @return Request object with redirect following disabled, or the original
#'   input when no change is needed.
#' @keywords internal
#' @noRd
req_no_redirect <- function(req) {
  if (!inherits(req, "httr2_request")) {
    return(req)
  }
  # Allow redirects only if explicitly enabled.
  if (allow_redirect()) {
    return(req)
  }
  httr2::req_options(req, followlocation = FALSE)
}

#' Internal: Check if response is a redirect and reject it
#'
#' Security check to ensure 3xx redirect responses are treated as errors for
#' sensitive endpoints. Since `req_no_redirect()` prevents following redirects,
#' a 3xx response indicates the endpoint tried to redirect us (misconfig,
#' attack, or proxy behavior). We should fail rather than parse an empty/wrong
#' response body. Used immediately after sensitive outbound requests complete.
#'
#' Skipped when `allow_redirect()` returns TRUE.
#'
#' @param resp httr2 response object
#' @param context Character string describing the operation for error messages
#'
#' @return TRUE if the response is NOT a redirect; throws an error if it is
#'
#' @keywords internal
#' @noRd
reject_redirect_response <- function(resp, context = "request") {
  # Skip rejection if redirects are explicitly allowed.
  if (allow_redirect()) {
    return(TRUE)
  }
  if (!inherits(resp, "httr2_response")) {
    return(TRUE)
  }
  status <- try(httr2::resp_status(resp), silent = TRUE)
  if (inherits(status, "try-error") || is.na(status)) {
    return(TRUE)
  }
  # 3xx status codes are redirects

  if (status >= 300 && status < 400) {
    location <- try(httr2::resp_header(resp, "location"), silent = TRUE)
    if (inherits(location, "try-error")) {
      location <- NA_character_
    }
    err_http(
      c(
        "x" = paste0(
          "Unexpected redirect response during ",
          context,
          " (status ",
          status,
          ")"
        ),
        "!" = "Redirects are disabled for security; endpoint may be misconfigured",
        "i" = if (!is.na(location)) {
          paste0("Would have redirected to: ", location)
        } else {
          NULL
        }
      ),
      resp,
      context = list(phase = context, redirect_blocked = TRUE)
    )
  }
  TRUE
}

#' Internal: HTTP defaults (timeout and User-Agent)
#'
#' Applies a modest timeout and a descriptive User-Agent to an httr2 request.
#' Timeout and UA are configurable via options:
#'   - options(shinyOAuth.timeout = 5) seconds
#'   - options(shinyOAuth.user_agent = "shinyOAuth/<version> (+R/<version>)")
#' Used by request builders before any network call is performed.
#'
#' @param req httr2 request object.
#' @return Request object with timeout, user-agent, and body-size defaults
#'   applied.
#' @keywords internal
#' @noRd
add_req_defaults <- function(req) {
  # If a test double/fake is passed, do nothing
  if (!inherits(req, "httr2_request")) {
    return(req)
  }
  # Resolve timeout (seconds)
  t <- suppressWarnings(as.numeric(getOption("shinyOAuth.timeout", 5)))
  if (!is.finite(t) || is.na(t) || t <= 0) {
    t <- 10
  }

  # Resolve UA
  ua <- getOption("shinyOAuth.user_agent", NULL)
  if (is.null(ua)) {
    # Try to derive package version, fall back to dev
    ver <- tryCatch(
      as.character(utils::packageVersion("shinyOAuth")),
      error = function(...) NA_character_
    )
    if (is.na(ver)) {
      d <- tryCatch(
        utils::packageDescription("shinyOAuth"),
        error = function(...) NULL
      )
      ver <- if (!is.null(d$Version)) d$Version else "dev"
    }
    ua <- sprintf(
      "shinyOAuth/%s R/%s httr2/%s",
      ver,
      getRversion(),
      as.character(utils::packageVersion("httr2"))
    )
  }
  # Max response body size (bytes). Curl aborts the transfer when the server
  # advertises Content-Length exceeding this value, preventing large allocations
  # from malicious or compromised endpoints. Default 1 MiB. Chunked responses
  # without Content-Length are caught post-download by check_resp_body_size().
  max_bytes <- resolve_max_body_bytes()

  req |>
    httr2::req_timeout(t) |>
    httr2::req_user_agent(ua) |>
    httr2::req_options(maxfilesize = max_bytes)
}

## 1.2 Client-auth request shaping ---------------------------------------------

#' Apply direct client authentication to a request
#'
#' Shapes request credentials according to the provider's configured token auth
#' style. Used by token, refresh, introspection, and revocation requests.
#'
#' @param req httr2 request object.
#' @param params Named request-parameter list.
#' @param client OAuth client carrying auth configuration.
#' @param context Phase label used by downstream helpers.
#' @return A list with updated `req` and `params` entries.
#' @keywords internal
#' @noRd
apply_direct_client_auth <- function(req, params, client, context) {
  tas <- normalize_token_auth_style(
    client@provider@token_auth_style %||% "header"
  )

  if (identical(tas, "header")) {
    req <- req |>
      httr2::req_auth_basic(client@client_id, client@client_secret)
  } else if (identical(tas, "body")) {
    params$client_id <- params$client_id %||% client@client_id
    # client_secret_post can omit client_secret for PKCE/public-like flows,
    # but it still sends the secret when one is configured.
    if (is_valid_string(client@client_secret)) {
      params$client_secret <- client@client_secret
    }
  } else if (identical(tas, "public")) {
    params$client_id <- params$client_id %||% client@client_id
  } else if (tas %in% MTLS_TOKEN_AUTH_STYLES) {
    params$client_id <- params$client_id %||% client@client_id
  } else if (
    identical(tas, "client_secret_jwt") || identical(tas, "private_key_jwt")
  ) {
    params$client_id <- params$client_id %||% client@client_id
    params$client_assertion_type <-
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    params$client_assertion <- build_client_assertion(
      client,
      aud = resolve_client_assertion_audience(client, req)
    )
  } else {
    err_config(
      c(
        paste0("Unsupported token_auth_style for ", context, "."),
        "i" = paste0(
          "Got: '",
          tas,
          "'. Allowed: 'header', 'body', 'public', 'tls_client_auth', 'self_signed_tls_client_auth', 'client_secret_jwt', 'private_key_jwt'."
        )
      ),
      context = list(phase = context, style = tas)
    )
  }

  list(req = req, params = params)
}

#' Attach per-attempt JWT client-assertion rebuilding to a request
#'
#' OpenID Connect JWT client assertions are single-use credentials. When a
#' request may be retried, the form body must be rebuilt with a fresh
#' `client_assertion` (and therefore a fresh `jti`) for each attempt.
#'
#' @param req httr2 request object with the original body already attached.
#' @param params Named request-parameter list used to build that body.
#' @param client OAuth client carrying auth configuration.
#' @param context Phase label used when rebuilding direct client auth.
#' @param body_mode Either `"encoded"` for `req_body_form_encoded()` or
#'   `"form"` for `httr2::req_body_form()`.
#' @return Updated request. Non-JWT client-auth styles are returned unchanged.
#' @keywords internal
#' @noRd
req_refresh_jwt_client_assertion_on_retry <- function(
  req,
  params,
  client,
  context,
  body_mode = c("encoded", "form")
) {
  if (!inherits(req, "httr2_request")) {
    return(req)
  }

  S7::check_is_S7(client, class = OAuthClient)

  tas <- normalize_token_auth_style(
    client@provider@token_auth_style %||% "header"
  )
  if (
    !(identical(tas, "client_secret_jwt") || identical(tas, "private_key_jwt"))
  ) {
    return(req)
  }

  body_mode <- match.arg(body_mode)
  base_params <- compact_list(params)

  req$shinyOAuth_prepare_attempt <- function(attempt_req, attempt) {
    prepared <- apply_direct_client_auth(
      req = attempt_req,
      params = base_params,
      client = client,
      context = context
    )
    attempt_req <- prepared$req
    attempt_params <- compact_list(prepared$params)

    if (identical(body_mode, "encoded")) {
      return(req_body_form_encoded(attempt_req, attempt_params))
    }

    do.call(httr2::req_body_form, c(list(attempt_req), attempt_params))
  }

  req
}

#' Internal: resolve max body bytes from option
#'
#' Used by request defaults and response-size guards.
#'
#' @return Integer, validated max body bytes (default 1 MiB).
#' @keywords internal
#' @noRd
resolve_max_body_bytes <- function() {
  max_bytes <- suppressWarnings(
    as.numeric(getOption("shinyOAuth.max_body_bytes", 1048576L))
  )
  if (!is.finite(max_bytes) || is.na(max_bytes) || max_bytes < 1024) {
    max_bytes <- 1048576L
  }
  as.integer(max_bytes)
}

#' Internal: check response body size before parsing
#'
#' Defense-in-depth guard that prevents expensive parsing (JSON, JWT) of
#' oversized response bodies. Works for both Content-Length and chunked
#' transfer encoding because it checks the actual downloaded body length. Used
#' before token, discovery, JWKS, and UserInfo bodies are parsed.
#'
#' @param resp httr2 response object.
#' @param context Character label for error messages (e.g., "token", "userinfo").
#' @param max_bytes Maximum allowed body size in bytes; defaults to
#'   `getOption("shinyOAuth.max_body_bytes", 1048576L)`.
#'
#' @return Invisibly TRUE when body is within limits; raises
#'   `shinyOAuth_parse_error` otherwise.
#'
#' @keywords internal
#' @noRd
check_resp_body_size <- function(
  resp,
  context = "response",
  max_bytes = resolve_max_body_bytes()
) {
  if (!inherits(resp, "httr2_response")) {
    return(invisible(TRUE))
  }
  body_len <- length(resp$body)
  if (body_len > max_bytes) {
    err_parse(
      c(
        "x" = paste0(
          "Response body too large during ",
          context,
          " (",
          body_len,
          " bytes; limit ",
          max_bytes,
          ")"
        ),
        "i" = "Adjust via `options(shinyOAuth.max_body_bytes = <bytes>)` if the provider legitimately returns large payloads"
      ),
      context = list(
        phase = context,
        body_bytes = body_len,
        max_bytes = max_bytes
      )
    )
  }
  invisible(TRUE)
}

#' Internal: Perform an httr2 request with retries
#'
#' Retries on network errors and transient HTTP statuses (default: 408, 429,
#' and 5xx). Honors Retry-After header when present (numeric seconds or
#' HTTP-date) and otherwise uses exponential backoff with jitter. Used by all
#' outbound provider-facing HTTP calls.
#'
#' Note: This helper currently implements backoff via `Sys.sleep()` on the main
#' R thread. In Shiny, calling this from the server will block the event loop
#' during the sleep intervals. To avoid blocking, consider running flows with
#' `async = TRUE` in `oauth_module_server()` (which can execute network calls
#' away from the main process when backed by [mirai] or a non-sequential
#' [future] plan), or reduce retries/timeouts using the options below.
#'
#' @param req An httr2 request object.
#' @param idempotent Logical. When `FALSE`, the request is assumed to consume
#'   single-use credentials (e.g., authorization codes, rotatable refresh
#'   tokens) and will **not** be retried. This prevents the retry loop from
#'   replaying a POST that the server already committed, which would cause
#'   `invalid_grant` errors or trigger refresh-token replay detection.
#'   Default `TRUE` (retries enabled).
#'   Callers may attach an internal `shinyOAuth_prepare_attempt` request field
#'   to rebuild one-shot headers before each perform attempt.
#'
#' Config via options:
#'  - shinyOAuth.retry_max_tries (default 3)
#'  - shinyOAuth.retry_backoff_base (seconds, default 0.5)
#'  - shinyOAuth.retry_backoff_cap (seconds, default 5)
#'  - shinyOAuth.retry_status (integer vector; default c(408, 429, 500:599))
#'
#' @return httr2 response object. Transport failures raise a typed transport
#'   error instead of returning.
#' @keywords internal
#' @noRd
req_with_retry <- function(req, idempotent = TRUE) {
  # Fast-path: if not an httr2 request, just try to perform it
  if (!inherits(req, "httr2_request")) {
    return(httr2::req_perform(req))
  }

  # Note: httr2 throws on HTTP error statuses (4xx/5xx) by default
  # We disable that behavior so we can distinguish transport errors (network
  # failures, timeouts) from HTTP errors (server returned a response with
  # error status). This lets us retry only on transient HTTP statuses while
  # immediately returning non-retryable error responses to the caller.
  req <- httr2::req_error(req, is_error = \(resp) FALSE)

  prepare_attempt <- req$shinyOAuth_prepare_attempt %||% NULL

  prepare_attempt_req <- function(attempt) {
    attempt_req <- req
    if (is.function(prepare_attempt)) {
      attempt_req <- prepare_attempt(req, attempt)
    }
    if (inherits(attempt_req, "httr2_request")) {
      attempt_req$shinyOAuth_prepare_attempt <- NULL
    }
    attempt_req
  }

  # Non-idempotent requests (token exchange, refresh) must not be retried
  # because the server may have already consumed the single-use credential.
  # A retry would replay an invalidated code/token, causing invalid_grant
  # or triggering refresh-token replay detection (full session revocation).
  if (!isTRUE(idempotent)) {
    attempt_req <- prepare_attempt_req(1L)
    resp <- try(httr2::req_perform(attempt_req), silent = TRUE)
    if (inherits(resp, "try-error")) {
      parent <- attr(resp, "condition")
      if (is.null(parent)) {
        parent <- simpleError(as.character(resp))
      }
      err_transport(
        "Transport error performing HTTP request",
        context = compact_list(list(
          method = tryCatch(
            toupper(as.character(attempt_req$method)),
            error = function(...) NA_character_
          ),
          url = tryCatch(
            as.character(attempt_req$url),
            error = function(...) NA_character_
          )
        )),
        parent = parent
      )
    }
    return(resp)
  }

  max_tries <- suppressWarnings(as.integer(getOption(
    "shinyOAuth.retry_max_tries",
    3L
  )))
  if (!is.finite(max_tries) || is.na(max_tries) || max_tries < 1L) {
    max_tries <- 3L
  }
  base <- suppressWarnings(as.numeric(getOption(
    "shinyOAuth.retry_backoff_base",
    0.5
  )))
  if (!is.finite(base) || is.na(base) || base <= 0) {
    base <- 0.5
  }
  cap <- suppressWarnings(as.numeric(getOption(
    "shinyOAuth.retry_backoff_cap",
    5
  )))
  if (!is.finite(cap) || is.na(cap) || cap <= 0) {
    cap <- 5
  }
  retry_status <- getOption("shinyOAuth.retry_status", c(408L, 429L, 500:599))
  retry_status <- unique(as.integer(retry_status))
  # Drop malformed entries to avoid NA propagation in %in% checks
  retry_status <- retry_status[!is.na(retry_status)]
  # If everything was invalid, restore safe defaults to preserve guardrails
  if (length(retry_status) == 0L) {
    retry_status <- c(408L, 429L, 500:599)
  }

  last_err <- NULL
  for (i in seq_len(max_tries)) {
    attempt_req <- prepare_attempt_req(i)
    # Try perform; catch transport errors
    resp <- try(httr2::req_perform(attempt_req), silent = TRUE)
    # Transport error -> retry
    if (inherits(resp, "try-error")) {
      last_err <- resp
      # Backoff on transport errors (no Retry-After available)
      if (i < max_tries) {
        Sys.sleep(retry_backoff_delay(i, base = base, cap = cap))
      }
    } else if (inherits(resp, "httr2_response")) {
      status <- try(httr2::resp_status(resp), silent = TRUE)
      status <- if (!inherits(status, "try-error")) {
        as.integer(status)
      } else {
        NA_integer_
      }
      if (!is.na(status) && !(status %in% retry_status)) {
        # Non-retryable or success -> return immediately
        return(resp)
      }
      # Transient -> maybe delay and retry
      last_err <- structure(
        list(response = resp),
        class = "shinyOAuth_transient_response"
      )
      # Respect Retry-After when present
      wait <- parse_retry_after_header(resp)
      if (is.na(wait)) {
        wait <- retry_backoff_delay(i, base = base, cap = cap)
      }
      # Avoid excessive sleep in tests; cap at 10s for sanity
      wait <- max(0, min(wait, 10))
      if (i < max_tries && wait > 0) Sys.sleep(wait)
    } else {
      # Unexpected return; break
      return(resp)
    }
  }

  # Out of tries: if we have a response, return it for caller to handle
  if (inherits(last_err, "shinyOAuth_transient_response")) {
    return(last_err$response)
  }
  # Otherwise, rethrow transport error as a simple error for caller logic
  parent <- attr(last_err, "condition")
  if (is.null(parent) && inherits(last_err, "try-error")) {
    parent <- simpleError(as.character(last_err))
  }
  # Provide a consistent, package-specific transport error
  err_transport(
    "Transport error performing HTTP request",
    context = compact_list(list(
      method = tryCatch(
        toupper(as.character(req$method)),
        error = function(...) NA_character_
      ),
      url = tryCatch(as.character(req$url), error = function(...) NA_character_)
    )),
    parent = parent
  )
}

## 1.3 Retry timing helpers ----------------------------------------------------

#' Internal: parse one Retry-After response header
#'
#' Used by `req_with_retry()` so transient HTTP responses can respect server-
#' supplied retry delays before falling back to client-side backoff. Extracted
#' from `req_with_retry()` so retry-delay parsing stays testable on its own.
#'
#' @param resp httr2 response object.
#' @return Retry delay in seconds, or `NA_real_` when parsing fails.
#' @keywords internal
#' @noRd
parse_retry_after_header <- function(resp) {
  ra <- try(httr2::resp_header(resp, "retry-after"), silent = TRUE)
  if (inherits(ra, "try-error") || !is_valid_string(ra)) {
    return(NA_real_)
  }
  ra <- trimws(as.character(ra))
  if (grepl("^\\d+$", ra)) {
    val <- suppressWarnings(as.numeric(ra))
    return(ifelse(is.finite(val) && !is.na(val) && val >= 0, val, NA_real_))
  }

  dt <- try(
    as.POSIXct(
      ra,
      tz = "GMT",
      tryFormats = c(
        "%a, %d %b %Y %H:%M:%S %Z",
        "%A, %d-%b-%y %H:%M:%S %Z",
        "%a %b %d %H:%M:%S %Y"
      )
    ),
    silent = TRUE
  )
  if (!inherits(dt, "try-error") && !is.na(dt)) {
    delta <- as.numeric(dt - Sys.time())
    return(ifelse(delta > 0, delta, NA_real_))
  }
  NA_real_
}

#' Internal: compute one retry backoff delay with jitter
#'
#' Used by `req_with_retry()` when no usable `Retry-After` header is present,
#' or when transport errors need client-side exponential backoff.
#'
#' @param attempt 1-based retry attempt number.
#' @param base Base backoff interval in seconds.
#' @param cap Maximum backoff interval in seconds.
#' @return Randomized backoff delay in seconds.
#' @keywords internal
#' @noRd
retry_backoff_delay <- function(attempt, base, cap) {
  max_wait <- min(cap, base * (2^(attempt - 1)))
  stats::runif(1, min = 0, max = max_wait)
}
