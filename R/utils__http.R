#' Internal: HTTP defaults (timeout and User-Agent)
#'
#' Applies a modest timeout and a descriptive User-Agent to an httr2 request.
#' Timeout and UA are configurable via options:
#'   - options(shinyOAuth.timeout = 5) seconds
#'   - options(shinyOAuth.user_agent = "shinyOAuth/<version> (+R/<version>)")
#'
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
  req |>
    httr2::req_timeout(t) |>
    httr2::req_user_agent(ua)
}

#' Internal: Perform an httr2 request with retries
#'
#' Retries on network errors and transient HTTP statuses (default: 408, 429,
#' and 5xx). Honors Retry-After header when present (numeric seconds or
#' HTTP-date) and otherwise uses exponential backoff with jitter.
#'
#' Note: This helper currently implements backoff via `Sys.sleep()` on the main
#' R thread. In Shiny, calling this from the server will block the event loop
#' during the sleep intervals. To avoid blocking, consider running flows with
#' `async = TRUE` in `oauth_module_server()` (which executes network calls in a
#' background future), or reduce retries/timeouts using the options below.
#'
#' Config via options:
#'  - shinyOAuth.retry_max_tries (default 3)
#'  - shinyOAuth.retry_backoff_base (seconds, default 0.5)
#'  - shinyOAuth.retry_backoff_cap (seconds, default 5)
#'  - shinyOAuth.retry_status (integer vector; default c(408, 429, 500:599))
#'
#' @keywords internal
#' @noRd
req_with_retry <- function(req) {
  # Fast-path: if not an httr2 request, just try to perform it
  if (!inherits(req, "httr2_request")) {
    return(httr2::req_perform(req))
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

  parse_retry_after <- function(resp) {
    ra <- try(httr2::resp_header(resp, "retry-after"), silent = TRUE)
    if (inherits(ra, "try-error") || is.null(ra) || !nzchar(ra)) {
      return(NA_real_)
    }
    ra <- trimws(as.character(ra))
    # Numeric seconds
    if (grepl("^\\d+$", ra)) {
      val <- suppressWarnings(as.numeric(ra))
      return(ifelse(is.finite(val) && !is.na(val) && val >= 0, val, NA_real_))
    }
    # HTTP-date
    dt <- try(
      as.POSIXct(
        ra,
        tz = "GMT",
        tryFormats = c(
          "%a, %d %b %Y %H:%M:%S %Z", # IMF-fixdate
          "%A, %d-%b-%y %H:%M:%S %Z", # rfc850
          "%a %b %d %H:%M:%S %Y" # asctime
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

  backoff_delay <- function(attempt) {
    # Exponential backoff with full jitter (0..min(cap, base*2^(attempt-1)))
    max_wait <- min(cap, base * (2^(attempt - 1)))
    stats::runif(1, min = 0, max = max_wait)
  }

  last_err <- NULL
  for (i in seq_len(max_tries)) {
    # Try perform; catch transport errors
    resp <- try(httr2::req_perform(req), silent = TRUE)
    # Transport error -> retry
    if (inherits(resp, "try-error")) {
      last_err <- resp
      # Backoff on transport errors (no Retry-After available)
      if (i < max_tries) {
        Sys.sleep(backoff_delay(i))
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
      wait <- parse_retry_after(resp)
      if (is.na(wait)) {
        wait <- backoff_delay(i)
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

#' Parse token HTTP response by Content-Type
#'
#' @description
#' Internal helper to parse OAuth token endpoint responses. Supports JSON
#' (application/json) and form-encoded (application/x-www-form-urlencoded).
#'
#' @param resp httr2 response
#'
#' @return Named list with token fields
#'
#' @keywords internal
#' @noRd
parse_token_response <- function(resp) {
  ct <- tolower(httr2::resp_header(resp, "content-type") %||% "")
  body <- httr2::resp_body_string(resp)

  # Some providers include charset, e.g., application/json; charset=utf-8
  if (grepl("application/json", ct, fixed = TRUE)) {
    out <- try(
      httr2::resp_body_json(resp, simplifyVector = TRUE),
      silent = TRUE
    )
    if (inherits(out, "try-error")) {
      # Fallback: attempt to parse string via jsonlite
      out <- try(jsonlite::fromJSON(body, simplifyVector = TRUE), silent = TRUE)
      if (inherits(out, "try-error")) {
        err_parse(c("x" = "Failed to parse JSON token response"))
      }
    }
    # Ensure list
    if (is.data.frame(out)) {
      out <- as.list(out)
    }
    return(out)
  }

  # GitHub historically returns form-encoded unless header Accept: application/json
  # Handle application/x-www-form-urlencoded or unknown types by form parsing
  if (
    grepl("application/x-www-form-urlencoded", ct, fixed = TRUE) ||
      ct == "" ||
      grepl("text/plain", ct, fixed = TRUE)
  ) {
    # httr2::url_query_parse handles form-encoded strings
    return(httr2::url_query_parse(body))
  }

  # Last resort: try JSON then form
  out <- try(jsonlite::fromJSON(body, simplifyVector = TRUE), silent = TRUE)
  if (!inherits(out, "try-error")) {
    if (is.data.frame(out)) {
      out <- as.list(out)
    }
    return(out)
  }
  httr2::url_query_parse(body)
}

# Internal: derive a compact, JSON-serializable HTTP summary from a request
build_http_summary <- function(req) {
  if (is.null(req)) {
    return(NULL)
  }

  # Core request line/meta
  method <- .scalar_chr(tryCatch(req$REQUEST_METHOD, error = function(...) {
    NULL
  }))
  path <- .scalar_chr(tryCatch(req$PATH_INFO, error = function(...) NULL))
  query_string <- .scalar_chr(tryCatch(req$QUERY_STRING, error = function(...) {
    NULL
  }))
  host <- .scalar_chr(tryCatch(req$HTTP_HOST, error = function(...) NULL))
  scheme <- .scalar_chr(tryCatch(
    req$HTTP_X_FORWARDED_PROTO,
    error = function(...) NULL
  ))
  if (is.na(scheme) || !nzchar(scheme)) {
    # Try rook scheme when not behind proxy
    scheme <- .scalar_chr(tryCatch(
      req[["rook.url_scheme"]],
      error = function(...) NULL
    ))
  }
  # Remote address preference: X-Forwarded-For (first IP) else REMOTE_ADDR
  ra <- .scalar_chr(tryCatch(req$REMOTE_ADDR, error = function(...) NULL))
  xff <- .scalar_chr(tryCatch(req$HTTP_X_FORWARDED_FOR, error = function(...) {
    NULL
  }))
  if (!is.na(xff) && nzchar(xff)) {
    # If multiple comma-separated IPs, take the first hop
    ra <- strsplit(xff, ",", fixed = TRUE)[[1]]
    ra <- .scalar_chr(if (length(ra)) trimws(ra[[1]]) else NULL)
  }

  # Collect HTTP_* into headers list (JSON-friendly scalars)
  nms <- names(req)
  hdr_idx <- if (!is.null(nms)) grepl("^HTTP_", nms) else rep(FALSE, 0)
  hdrs <- list()
  if (length(hdr_idx) && any(hdr_idx)) {
    for (nm in nms[hdr_idx]) {
      key <- tolower(sub("^HTTP_", "", nm))
      val <- .scalar_chr(tryCatch(req[[nm]], error = function(...) NULL))
      hdrs[[key]] <- if (!is.na(val) && nzchar(val)) val else NULL
    }
    # Remove NULLs to keep JSON clean
    hdrs <- Filter(Negate(is.null), hdrs)
  }

  list(
    method = if (!is.na(method) && nzchar(method)) method else NULL,
    path = if (!is.na(path) && nzchar(path)) path else NULL,
    query_string = if (!is.na(query_string) && nzchar(query_string)) {
      query_string
    } else {
      NULL
    },
    host = if (!is.na(host) && nzchar(host)) host else NULL,
    scheme = if (!is.na(scheme) && nzchar(scheme)) scheme else NULL,
    remote_addr = if (!is.na(ra) && nzchar(ra)) ra else NULL,
    headers = if (length(hdrs)) hdrs else NULL
  )
}
