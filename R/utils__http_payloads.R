# This file contains helpers that parse and build HTTP payload bodies used by
# token and related endpoint requests.
# Use them when form-encoded or JSON payloads need strict parsing rules, input
# validation, or support for repeated parameter names.

# 1 HTTP payload helpers ---------------------------------------------------

## 1.1 Parse and encode request or response bodies ------------------------

#' Parse token HTTP response by Content-Type
#'
#' @description
#' Internal helper to parse OAuth token endpoint responses. Supports JSON
#' (application/json) and form-encoded (application/x-www-form-urlencoded).
#' Errors on unsupported content types to avoid silently parsing garbage
#' (e.g., HTML error pages from misconfigured proxies).
#'
#' @param resp httr2 response
#'
#' @return Named list with token fields
#'
#' @keywords internal
#' @noRd
parse_token_response <- function(resp) {
  check_resp_body_size(resp, context = "token")
  ct <- tolower(httr2::resp_header(resp, "content-type") %||% "")
  body <- httr2::resp_body_string(resp)

  # Some providers include charset, e.g., application/json; charset=utf-8
  if (grepl("application/json", ct, fixed = TRUE)) {
    reject_duplicate_json_object_members(body, "Token response JSON")
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
  # Handle application/x-www-form-urlencoded explicitly
  if (grepl("application/x-www-form-urlencoded", ct, fixed = TRUE)) {
    # httr2::url_query_parse handles form-encoded strings
    reject_duplicate_form_encoded_members(body, "Token response body")
    return(httr2::url_query_parse(body))
  }

  # Empty content-type or text/plain: legacy providers may omit or mis-set headers.

  # Try JSON first (many providers respond with JSON but wrong content-type),
  # then fall back to form parsing.
  if (ct == "" || grepl("text/plain", ct, fixed = TRUE)) {
    # Try JSON first
    reject_duplicate_json_object_members(body, "Token response JSON")
    out <- try(jsonlite::fromJSON(body, simplifyVector = TRUE), silent = TRUE)
    if (!inherits(out, "try-error")) {
      if (is.data.frame(out)) {
        out <- as.list(out)
      }
      return(out)
    }
    # Fall back to form parsing
    reject_duplicate_form_encoded_members(body, "Token response body")
    return(httr2::url_query_parse(body))
  }

  # Unsupported content type - fail explicitly rather than guessing

  # This catches text/html (proxy error pages), XML, or other unexpected types
  err_parse(
    c(
      "x" = "Unsupported content type in token response",
      "i" = paste0("Content-Type: ", ct),
      "i" = "Expected application/json or application/x-www-form-urlencoded"
    ),
    context = list(content_type = ct)
  )
}

# Reject duplicate parameter names in a form-encoded string.
# Used when parsing token responses. Input: form body text plus label. Output:
# invisible NULL or a parse error.
reject_duplicate_form_encoded_members <- function(form_text, label) {
  if (is.null(form_text) || !nzchar(form_text)) {
    return(invisible(NULL))
  }

  parts <- strsplit(form_text, "&", fixed = TRUE)[[1]]
  parts <- parts[nzchar(parts)]
  if (!length(parts)) {
    return(invisible(NULL))
  }

  seen <- character(0)
  for (part in parts) {
    key <- sub("=.*$", "", part)
    key <- utils::URLdecode(key)
    if (key %in% seen) {
      err_parse(paste0(label, " contains duplicate parameter name: ", key))
    }
    seen <- c(seen, key)
  }

  invisible(NULL)
}

# Percent-encode named form/query parameters while preserving repeated keys.
# Used by form-body helpers that cannot rely on httr2's simpler scalar path.
# Input: named parameter list. Output: encoded body string.
# Internal: percent-encode form/query params while preserving repeated keys
encode_www_form_params <- function(params) {
  if (!is.list(params) || length(params) == 0) {
    return("")
  }

  nms <- names(params)
  if (is.null(nms)) {
    err_config("Form/query parameters must be supplied as a named list")
  }

  parts <- unlist(
    lapply(seq_along(params), function(i) {
      nm <- nms[[i]]
      val <- params[[i]]

      if (!is_valid_string(nm)) {
        err_config("Form/query parameters must be supplied as a named list")
      }
      if (is.null(val) || length(val) == 0L) {
        return(character())
      }
      if (is.list(val) && !inherits(val, "AsIs")) {
        err_config(c(
          "x" = "Form/query parameter values must be atomic vectors",
          "i" = paste0(
            "Parameter ",
            sQuote(nm),
            " used an unsupported list value."
          )
        ))
      }

      val_chr <- as.character(val)
      val_chr <- val_chr[!is.na(val_chr)]
      if (length(val_chr) == 0L) {
        return(character())
      }

      nm_enc <- utils::URLencode(nm, reserved = TRUE)
      paste0(nm_enc, "=", utils::URLencode(val_chr, reserved = TRUE))
    }),
    use.names = FALSE
  )

  paste(parts, collapse = "&")
}

# Add a form-encoded body to a request while keeping repeated keys intact.
# Used by token and related request builders. Input: httr2 request plus named
# params list. Output: updated request.
# Internal: add a form body while preserving repeated keys for vector values
req_body_form_encoded <- function(req, params) {
  params <- compact_list(params)
  if (!length(params)) {
    return(req)
  }

  use_raw <- anyDuplicated(names(params)) > 0L ||
    any(vapply(
      params,
      function(val) {
        if (is.null(val)) {
          return(FALSE)
        }
        if (is.list(val) && !inherits(val, "AsIs")) {
          return(TRUE)
        }

        val_chr <- as.character(val)
        val_chr <- val_chr[!is.na(val_chr)]
        length(val_chr) != 1L
      },
      logical(1)
    ))

  if (!use_raw) {
    return(do.call(httr2::req_body_form, c(list(req), params)))
  }

  body <- encode_www_form_params(params)
  httr2::req_body_raw(
    req,
    body = charToRaw(enc2utf8(body)),
    type = "application/x-www-form-urlencoded"
  )
}
