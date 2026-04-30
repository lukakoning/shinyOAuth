#' Internal: check if a string is an absolute URI
#'
#' @keywords internal
#' @noRd
is_absolute_uri <- function(x) {
  if (!is_valid_string(x)) {
    return(FALSE)
  }

  x <- trimws(x)
  if (!grepl("^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:]]+$", x, perl = TRUE)) {
    return(FALSE)
  }

  parsed <- try(httr2::url_parse(x), silent = TRUE)
  if (!inherits(parsed, "try-error")) {
    return(is_valid_string(parsed$scheme %||% NA_character_))
  }

  TRUE
}

#' Internal: sanitize provider callback error_uri values
#'
#' Provider-supplied `error_uri` values are untrusted navigation inputs. Only
#' absolute HTTPS URLs are surfaced; anything else is dropped.
#'
#' @keywords internal
#' @noRd
sanitize_callback_error_uri <- function(x) {
  if (!is_valid_string(x)) {
    return(NULL)
  }

  x <- trimws(x)
  parsed <- try(httr2::url_parse(x), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(NULL)
  }

  scheme <- tolower(parsed$scheme %||% "")
  host <- trimws(parsed$hostname %||% "")

  if (!identical(scheme, "https") || !nzchar(host)) {
    return(NULL)
  }

  x
}

#' Internal: validate RFC 8707 resource indicators
#'
#' @keywords internal
#' @noRd
resource_indicator_problem <- function(resource) {
  if (!is.character(resource)) {
    return("resource must be a character vector")
  }
  if (anyNA(resource)) {
    return("resource must not contain NA")
  }
  if (!all(nzchar(trimws(resource)))) {
    return("resource must not contain empty strings")
  }
  if (!all(vapply(resource, is_absolute_uri, logical(1)))) {
    return("resource must contain only absolute URI values")
  }

  NULL
}

#' Internal: append query params to a URL while preserving repeated keys
#'
#' @keywords internal
#' @noRd
url_append_query_params <- function(url, params) {
  if (!is_valid_string(url)) {
    return(url)
  }

  params <- compact_list(params)
  query <- encode_www_form_params(params)
  if (!is_valid_string(query)) {
    return(url)
  }

  match <- regexec("^([^#]*)(#.*)?$", url, perl = TRUE)
  parts <- regmatches(url, match)[[1]]
  if (length(parts) == 0L) {
    return(url)
  }

  base <- parts[[2]]
  fragment <- if (length(parts) >= 3L && !is.na(parts[[3]])) {
    parts[[3]]
  } else {
    ""
  }

  sep <- if (grepl("[?&]$", base, perl = TRUE)) {
    ""
  } else if (grepl("?", base, fixed = TRUE)) {
    "&"
  } else {
    "?"
  }

  paste0(base, sep, query, fragment)
}

#' Internal: normalize URL path without touching query/fragment
#'
#' Collapses multiple consecutive slashes in the path component of a URL while
#' preserving the query string and fragment verbatim (no re-encoding).
#'
#' @keywords internal
#' @noRd
normalize_url <- function(u) {
  if (is.null(u) || is.na(u) || !nzchar(u)) {
    return(u)
  }

  # RFC 3986 components: scheme://authority path ?query #fragment
  m <- regexec(
    "^((?:[^:/?#]+:)?//[^/?#]*)([^?#]*)(\\?[^#]*)?(#.*)?$",
    u,
    perl = TRUE
  )

  parts <- regmatches(u, m)[[1]]
  if (length(parts) == 0) {
    return(u)
  }

  authority <- parts[2]
  path <- parts[3]
  query <- if (!is.na(parts[4])) parts[4] else ""
  fragment <- if (!is.na(parts[5])) parts[5] else ""
  path <- gsub("//+", "/", path)

  paste0(authority, path, query, fragment)
}

#' Internal: Right trim single trailing slash from URL
#'
#' @keywords internal
#' @noRd
rtrim_slash <- function(x) sub("/$", "", x)

#' Internal: Parse URL and extract normalized scheme and host
#'
#' Returns a list with lowercased scheme and hostname. Errors with err_config
#' when the URL can't be parsed or has no hostname.
#'
#' @keywords internal
#' @noRd
parse_url_components <- function(url, label = "url") {
  parsed <- try(httr2::url_parse(url), silent = TRUE)

  if (inherits(parsed, "try-error")) {
    err_config(c(
      "x" = sprintf("Could not parse %s", label),
      "!" = sprintf("Value: '%s'", url)
    ))
  }

  scheme <- tolower((parsed$scheme %||% ""))
  host <- tolower(trimws(parsed$hostname %||% ""))
  host <- sub("^\\[([^\\]]+)\\](?::.*)?$", "\\1", host, perl = TRUE)
  host <- sub("\\.$", "", host)

  if (!nzchar(host)) {
    err_config(c(
      "x" = sprintf("%s does not include a hostname", label),
      "!" = sprintf("Value: '%s'", url)
    ))
  }

  list(scheme = scheme, host = host)
}

#' Internal: Parse URL and return normalized host only
#'
#' @keywords internal
#' @noRd
parse_url_host <- function(url, label = "url") {
  h <- parse_url_components(url, label)$host
  sub("^\\[([^\\]]+)\\]$", "\\1", h)
}
