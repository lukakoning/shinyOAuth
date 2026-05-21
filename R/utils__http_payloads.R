# This file contains helpers that parse and build HTTP payload bodies used by
# token and related endpoint requests
# Used for handling form-encoded and JSON payloads with strict parsing and
# validation rules

# 1 Token response parsing -----------------------------------------------------

# 1.1 Parse token responses ----------------------------------------------------

#' Parse token HTTP response by Content-Type
#'
#' @description
#' Internal helper to parse OAuth token endpoint responses. Supports JSON
#' (`application/json`) and form-encoded
#' (`application/x-www-form-urlencoded`) bodies. Empty content types and
#' `text/plain` are handled as a legacy compatibility path: JSON is attempted
#' first, then form parsing is used. Other content types fail explicitly so
#' HTML proxy errors or unrelated payloads are not parsed as tokens.
#'
#' @param resp httr2 response object returned by a token-like endpoint.
#'
#' @return Parsed token response. JSON responses preserve JSON scalar/list
#'   types, with data frames converted to lists. Form-encoded responses return
#'   a named character list such as `access_token`, `token_type`, `scope`,
#'   `expires_in`, `refresh_token`, and provider-specific fields.
#'
#' @keywords internal
#' @noRd
parse_token_response <- function(resp) {
  check_resp_body_size(resp, context = "token")

  content_type <- tolower(httr2::resp_header(resp, "content-type") %||% "")
  body <- httr2::resp_body_string(resp)

  # Some providers include charset, e.g. application/json; charset=utf-8.
  if (grepl("application/json", content_type, fixed = TRUE)) {
    return(parse_token_response_json(body, resp = resp))
  }

  # GitHub historically returns form-encoded unless Accept requests JSON.
  if (grepl("application/x-www-form-urlencoded", content_type, fixed = TRUE)) {
    return(parse_token_response_form(body))
  }

  # Legacy providers may omit the content type or send JSON as text/plain.
  if (
    identical(content_type, "") ||
      grepl("text/plain", content_type, fixed = TRUE)
  ) {
    return(parse_lenient_token_response(body))
  }

  err_parse(
    c(
      "x" = "Unsupported content type in token response",
      "i" = paste0("Content-Type: ", content_type),
      "i" = "Expected application/json or application/x-www-form-urlencoded"
    ),
    context = list(content_type = content_type)
  )
}


# 1.2 Response body parsers ----------------------------------------------------

#' Parse a token response as strict JSON
#'
#' Used by `parse_token_response()` when the response advertises JSON. Duplicate
#' top-level JSON members are rejected before parsing so ambiguous token fields
#' cannot be smuggled through provider or parser differences.
#'
#' @param body Raw response body as a string.
#' @param resp Optional httr2 response. When supplied, httr2's JSON parser is
#'   attempted before falling back to `jsonlite::fromJSON()`.
#' @return Parsed JSON value, normalized by `normalize_token_response_json()`.
#' @keywords internal
#' @noRd
parse_token_response_json <- function(body, resp = NULL) {
  parsed <- try_parse_token_response_json(body, resp = resp)
  if (!isTRUE(parsed$ok)) {
    err_parse(c("x" = "Failed to parse JSON token response"))
  }
  if (!isTRUE(parsed$is_object)) {
    err_parse("Token response JSON must be a JSON object")
  }

  parsed$value
}

#' Try to parse a token response as JSON
#'
#' Used by strict JSON parsing and by the legacy content-type fallback. Parse
#' failures are returned as data rather than raised so callers can decide
#' whether to fall back to form parsing.
#'
#' @param body Raw response body as a string.
#' @param resp Optional httr2 response for httr2-native parsing.
#' @return A list with `ok`, a scalar logical, and `value`, the parsed JSON
#'   value when `ok` is `TRUE` or `NULL` when JSON parsing failed, plus
#'   `is_object` indicating whether the payload used a top-level JSON object.
#' @keywords internal
#' @noRd
try_parse_token_response_json <- function(body, resp = NULL) {
  reject_duplicate_json_object_members(body, "Token response JSON")
  is_object <- json_text_is_object(body)

  out <- if (inherits(resp, "httr2_response")) {
    try(httr2::resp_body_json(resp, simplifyVector = TRUE), silent = TRUE)
  } else {
    try(jsonlite::fromJSON(body, simplifyVector = TRUE), silent = TRUE)
  }

  if (inherits(out, "try-error")) {
    out <- try(jsonlite::fromJSON(body, simplifyVector = TRUE), silent = TRUE)
  }
  if (inherits(out, "try-error")) {
    return(list(ok = FALSE, value = NULL, is_object = is_object))
  }

  list(
    ok = TRUE,
    value = if (isTRUE(is_object)) {
      normalize_token_response_json(out)
    } else {
      out
    },
    is_object = is_object
  )
}

#' Normalize parsed token JSON to the package's expected shape
#'
#' Used after token JSON is parsed. `jsonlite` can return a data frame for
#' object-like responses with vector fields; token callers expect list-style
#' field access, so data frames are converted to lists.
#'
#' @param value Parsed JSON value.
#' @return `value`, with data frames converted to lists.
#' @keywords internal
#' @noRd
normalize_token_response_json <- function(value) {
  if (is.data.frame(value)) {
    return(as.list(value))
  }

  value
}

#' Parse a token response as form-encoded data
#'
#' Used by `parse_token_response()` for explicit form-encoded responses and as
#' the fallback for legacy responses that were not valid JSON.
#'
#' @param body Raw response body as a string.
#' @return Named character list parsed from the form body.
#' @keywords internal
#' @noRd
parse_token_response_form <- function(body) {
  reject_duplicate_form_encoded_members(body, "Token response body")
  httr2::url_query_parse(body)
}

#' Parse a legacy token response with weak or missing Content-Type
#'
#' Used by `parse_token_response()` for empty content types and `text/plain`.
#' JSON is preferred because many providers send JSON with the wrong header;
#' form parsing is retained for older OAuth providers.
#'
#' @param body Raw response body as a string.
#' @return Parsed token response as JSON data or a named character list.
#' @keywords internal
#' @noRd
parse_lenient_token_response <- function(body) {
  parsed_json <- try_parse_token_response_json(body)
  if (isTRUE(parsed_json$ok)) {
    if (!isTRUE(parsed_json$is_object)) {
      err_parse("Token response JSON must be a JSON object")
    }
    return(parsed_json$value)
  }

  parse_token_response_form(body)
}

#' Reject duplicate form-encoded parameter names
#'
#' Used before form-encoded token responses are parsed. Duplicate token fields
#' are rejected so callers do not have to infer which value a parser kept.
#'
#' @param form_text Form-encoded body text.
#' @param label Human-readable label used in parse errors.
#' @return Invisibly returns `NULL` on success. Otherwise this function raises a
#'   parse error.
#' @keywords internal
#' @noRd
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
    separator <- regexpr("=", part, fixed = TRUE)[[1]]
    if (separator < 0) {
      raw_key <- part
      raw_value <- ""
    } else {
      raw_key <- substr(part, 1L, separator - 1L)
      raw_value <- substr(part, separator + 1L, nchar(part, type = "chars"))
    }

    key <- decode_form_member(raw_key, label, "parameter name")
    decode_form_member(raw_value, label, "parameter value")
    if (key %in% seen) {
      err_parse(paste0(label, " contains duplicate parameter name: ", key))
    }
    seen <- c(seen, key)
  }

  invisible(NULL)
}

decode_form_member <- function(value, label, member) {
  if (grepl("(?i)%00|%(?![0-9a-f]{2})", value, perl = TRUE)) {
    err_parse(paste0(
      label,
      " contains malformed percent-encoded ",
      member
    ))
  }
  tryCatch(
    utils::URLdecode(value),
    warning = function(e) {
      err_parse(paste0(
        label,
        " contains malformed percent-encoded ",
        member
      ))
    },
    error = function(e) {
      err_parse(paste0(
        label,
        " contains malformed percent-encoded ",
        member
      ))
    }
  )
}


# 2 Form request bodies --------------------------------------------------------

# 2.1 Add form bodies to requests ----------------------------------------------

#' Add a form-encoded body to a request
#'
#' Preserves repeated keys instead of collapsing vector values onto one scalar
#' path. Used by token and related endpoint request builders.
#'
#' @param req httr2 request object.
#' @param params Named parameter list.
#' @return Updated request. When `params` is empty after `NULL` and scalar `NA`
#'   entries are removed, returns `req` unchanged.
#' @keywords internal
#' @noRd
req_body_form_encoded <- function(req, params) {
  params <- compact_list(params)
  if (!length(params)) {
    return(req)
  }

  if (!form_params_need_raw_body(params)) {
    return(do.call(httr2::req_body_form, c(list(req), params)))
  }

  body <- encode_www_form_params(params)
  httr2::req_body_raw(
    req,
    body = charToRaw(enc2utf8(body)),
    type = "application/x-www-form-urlencoded"
  )
}

#' Decide whether form parameters need raw-body encoding
#'
#' Used by `req_body_form_encoded()` to choose between httr2's standard form
#' builder and the package encoder that preserves repeated keys and vector
#' values.
#'
#' @param params Named parameter list after `compact_list()`.
#' @return `TRUE` when raw form encoding is needed; otherwise `FALSE`.
#' @keywords internal
#' @noRd
form_params_need_raw_body <- function(params) {
  anyDuplicated(names(params)) > 0L ||
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
}


# 2.2 Encode form parameters ---------------------------------------------------

#' Percent-encode form or query parameters
#'
#' Preserves repeated keys for vector values. Used by request-body and URL
#' builders that need stable repeated-parameter handling.
#'
#' @param params Named parameter list.
#' @return Encoded body string such as `"a=1&scope=read&scope=write"`.
#' @keywords internal
#' @noRd
encode_www_form_params <- function(params) {
  if (!is.list(params) || length(params) == 0L) {
    return("")
  }

  param_names <- names(params)
  if (is.null(param_names)) {
    err_config("Form/query parameters must be supplied as a named list")
  }

  parts <- unlist(
    Map(encode_www_form_param, param_names, params),
    use.names = FALSE
  )

  paste(parts, collapse = "&")
}

#' Percent-encode one form or query parameter
#'
#' Used by `encode_www_form_params()` for each named parameter. Atomic vectors
#' are encoded as repeated parameter names, while `NULL`, empty, and `NA` values
#' are omitted.
#'
#' @param name Parameter name.
#' @param value Parameter value.
#' @return Character vector containing zero or more `"name=value"` pairs.
#' @keywords internal
#' @noRd
encode_www_form_param <- function(name, value) {
  if (!is_valid_string(name)) {
    err_config("Form/query parameters must be supplied as a named list")
  }
  if (is.null(value) || length(value) == 0L) {
    return(character())
  }
  if (is.list(value) && !inherits(value, "AsIs")) {
    err_config(c(
      "x" = "Form/query parameter values must be atomic vectors",
      "i" = paste0(
        "Parameter ",
        sQuote(name),
        " used an unsupported list value."
      )
    ))
  }

  value <- as.character(value)
  value <- value[!is.na(value)]
  if (length(value) == 0L) {
    return(character())
  }

  name <- utils::URLencode(name, reserved = TRUE)
  paste0(name, "=", utils::URLencode(value, reserved = TRUE))
}
