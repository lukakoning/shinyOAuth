# This file contains URL builders, normalizers, validation helpers, and host
# policy checks used across the package
# Used for building authorization URLs, parsing untrusted URLs, normalizing
# issuer and endpoint values, and enforcing allowed-host and HTTPS rules

# 1 URL entry points -----------------------------------------------------------

## 1.1 Check host policy -------------------------------------------------------

#' @title
#' Check if URL(s) are HTTPS and/or in allowed hosts lists
#'
#' @description
#' Returns `TRUE` if every input URL passes shinyOAuth's scheme and host
#' policy. In practice, each URL must be either:
#' - a syntactically valid HTTPS URL, and (if set) whose host matches `allowed_hosts`, or
#' - an HTTP URL whose host matches `allowed_non_https_hosts` (e.g. localhost, 127.0.0.1, ::1),
#'   and (if set) also matches `allowed_hosts`.
#'
#' If the input omits the scheme (e.g., "localhost:8080/cb"), this function
#' will first attempt to validate it as HTTP (useful for loopback development),
#' and if that fails, as HTTPS. This mirrors how helpers normalize inputs for
#' convenience while still enforcing the same host and scheme policies.
#'
#' `allowed_hosts` is the allowlist of hosts or domains that are permitted,
#' while `allowed_non_https_hosts` defines which hosts are allowed to use HTTP
#' instead of HTTPS. If `allowed_hosts` is `NULL` or length 0, all hosts are
#' allowed subject to the scheme rules above.
#'
#' Since `allowed_hosts` supports globs, a value like "*" matches any host
#' and therefore effectively disables endpoint host restrictions. Only use a catch-all
#' pattern when you truly intend to allow any host. In most deployments you should pin
#' to your expected domain(s), e.g. `c(".example.com")` or a specific host name.
#'
#' Wildcards: `allowed_hosts` and `allowed_non_https_hosts` support globs:
#' `*` = any chars, `?` = one char. A leading `.example.com` matches the
#' domain itself and any subdomain.
#'
#' Any non-URLs, NAs, or empty strings cause a FALSE result.
#'
#' @details
#' This function is used internally to validate redirect URIs in OAuth clients,
#' but can also be used directly to test whether URLs would be accepted.
#' Internally, the defaults come from the options
#' `shinyOAuth.allowed_non_https_hosts` and `shinyOAuth.allowed_hosts`.
#'
#' @param url Single URL or vector of URLs (character; length 1 or more)
#' @param allowed_non_https_hosts Character vector of hostnames that are allowed
#' to use HTTP instead of HTTPS. Defaults to localhost equivalents. Supports globs
#' @param allowed_hosts Optional allowlist of hosts/domains; if supplied (length > 0),
#' only these hosts are permitted. Supports globs
#'
#' @return Logical indicator (TRUE if all URLs pass all checks; FALSE otherwise)
#'
#' @example inst/examples/is_ok_host.R
#'
#' @export
is_ok_host <- function(
  url,
  allowed_non_https_hosts = getOption(
    "shinyOAuth.allowed_non_https_hosts",
    # Note: host extraction removes square brackets for IPv6; include both forms for robustness
    default = c("localhost", "127.0.0.1", "::1", "[::1]")
  ),
  allowed_hosts = getOption("shinyOAuth.allowed_hosts", default = NULL)
) {
  # Handle NULL/empty input early; return FALSE for those
  if (is.null(url) || length(url) == 0) {
    return(FALSE)
  }

  # Check all URLs; return TRUE only if all pass
  all(vapply(
    url,
    is_ok_host_one,
    logical(1),
    allowed_non_https_hosts = allowed_non_https_hosts,
    allowed_hosts = allowed_hosts
  ))
}

## 1.2 Build request URLs ------------------------------------------------------

#' Internal: append query params to a URL while preserving repeated keys
#'
#' Used by authorization and outbound request builders.
#'
#' @param url URL string.
#' @param params Named parameter list.
#' @return Updated URL string.
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

## 1.3 Normalize and validate issuer or endpoint URLs --------------------------

#' Internal: Resolve issuer from discovery with issuer matching policy
#'
#' Requires the discovery issuer to be present and well-formed.
#'
#' Matching is controlled by `issuer_match`:
#' - "url": require an exact match against the issuer URL prefix used for
#'   discovery (after removing one trailing slash, if present)
#' - "host": require scheme+host match only (explicit opt-out)
#' - "none": do not validate issuer consistency
#' Used after OIDC discovery fetches issuer metadata.
#'
#' @param issuer_input Issuer URL provided by the caller.
#' @param issuer_discovered Issuer URL returned by discovery metadata.
#' @param issuer_match Issuer-matching policy.
#' @return Discovered issuer string.
#' @keywords internal
#' @noRd
validate_discovery_issuer <- function(
  issuer_input,
  issuer_discovered,
  issuer_match = c("url", "host", "none")
) {
  issuer_match <- match.arg(issuer_match)

  if (
    !is.character(issuer_discovered) ||
      length(issuer_discovered) != 1L ||
      is.na(issuer_discovered) ||
      !nzchar(issuer_discovered)
  ) {
    err_parse(c(
      "x" = "Discovery missing required issuer metadata",
      "i" = "The discovery document must include issuer as a single non-empty string"
    ))
  }

  iss <- issuer_discovered

  if (identical(issuer_match, "none")) {
    return(iss)
  }

  if (identical(issuer_match, "host")) {
    p_in <- parse_url_components(issuer_input, "issuer")
    p_dc <- parse_url_components(issuer_discovered, "discovery issuer")

    if (
      !identical(p_in$scheme, p_dc$scheme) || !identical(p_in$host, p_dc$host)
    ) {
      err_config(
        c(
          "x" = "OIDC discovery issuer mismatch",
          "!" = sprintf(
            "Input '%s://%s' vs discovery '%s://%s'",
            p_in$scheme,
            p_in$host,
            p_dc$scheme,
            p_dc$host
          )
        )
      )
    }

    return(iss)
  }

  expected_issuer <- rtrim_slash(issuer_input)

  if (!identical(expected_issuer, issuer_discovered)) {
    err_config(
      c(
        "x" = "OIDC discovery issuer mismatch",
        "!" = sprintf(
          "Input '%s' vs discovery '%s'",
          expected_issuer,
          issuer_discovered
        ),
        "i" = "Set issuer_match = 'host' to compare only scheme+host (not recommended)"
      )
    )
  }

  iss
}

#' Internal: validate absolute URL against allowed hosts
#'
#' Validates that one endpoint is an absolute URL and that its scheme and host
#' satisfy the current host policy. Used by discovery and provider endpoint
#' validation so endpoint failures raise one consistent configuration error.
#'
#' @param u Endpoint URL to validate.
#' @param allowed_hosts_vec Allowed host vector.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   configuration error.
#' @keywords internal
#' @noRd
validate_endpoint <- function(u, allowed_hosts_vec) {
  is_scalar_string <- is.character(u) && length(u) == 1

  # Allow NA/empty to pass silently (callers may treat missing endpoints as optional)
  if (is_scalar_string && (is.na(u) || !nzchar(u))) {
    return(invisible(TRUE))
  }

  if (!(is_scalar_string && !is.na(u) && nzchar(u))) {
    err_config(
      c(
        "x" = "Endpoint must be an absolute URL",
        "i" = paste0(
          "Got invalid URL: ",
          paste(as.character(u), collapse = ", ")
        )
      ),
      context = list(endpoint = u)
    )
  }

  p <- try(httr2::url_parse(u), silent = TRUE)

  if (inherits(p, "try-error")) {
    err_config(
      c(
        "x" = "Endpoint must be an absolute URL",
        "i" = paste0(
          "Got invalid URL: ",
          as.character(u)
        )
      ),
      context = list(endpoint = u)
    )
  }

  # absolute URL required
  if (
    is.null(p$scheme) ||
      !nzchar(p$scheme) ||
      is.null(p$hostname) ||
      !nzchar(p$hostname)
  ) {
    err_config(
      c(
        "x" = "Endpoint must be an absolute URL",
        "i" = paste0(
          "Got invalid URL: ",
          as.character(u)
        )
      ),
      context = list(endpoint = u)
    )
  }

  # Delegate scheme + host policy to is_ok_host using computed allowed_hosts.
  # This permits HTTP only for hosts in shinyOAuth.allowed_non_https_hosts,
  # while still pinning endpoints to the issuer host (or allowlist).
  if (!is_ok_host(u, allowed_hosts = allowed_hosts_vec)) {
    chost <- tolower(trimws(p$hostname))
    chost <- sub("\\.$", "", chost)
    err_config(
      c(
        "x" = "Endpoint host or scheme not allowed (see `?is_ok_host`)",
        "i" = paste0(
          "Got endpoint: ",
          as.character(u)
        ),
        "i" = paste0(
          "Allowed hosts: ",
          paste(allowed_hosts_vec, collapse = ", ")
        )
      ),
      context = list(
        endpoint = u,
        endpoint_host = chost,
        allowed_hosts = allowed_hosts_vec
      )
    )
  }

  invisible(TRUE)
}

# 2 URL parsing helpers --------------------------------------------------------

## 2.1 Recognize and inspect URLs ----------------------------------------------

#' Internal: check if a string is an absolute URI
#'
#' Used by callback and provider URL sanitizers.
#'
#' @param x String to test.
#' @return `TRUE` when `x` looks like an absolute URI; otherwise `FALSE`.
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

#' Internal: check whether a URI includes a fragment component
#'
#' Used by endpoint, issuer, and resource-indicator validation.
#'
#' @param x URI string to inspect.
#' @return `TRUE` when `x` includes a fragment delimiter; otherwise `FALSE`.
#' @keywords internal
#' @noRd
has_uri_fragment <- function(x) {
  if (!is_valid_string(x)) {
    return(FALSE)
  }

  grepl("#", trimws(x), fixed = TRUE)
}

#' Internal: sanitize provider callback error_uri values
#'
#' Provider-supplied `error_uri` values are untrusted navigation inputs. Only
#' absolute HTTPS URLs are surfaced; anything else is dropped. Used when the
#' module surfaces provider error callbacks.
#'
#' @param x Provider-supplied `error_uri` value.
#' @return Sanitized HTTPS URL string, or `NULL` when the value should be
#'   dropped.
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
#' Used before authorization and token requests include `resource` values.
#'
#' @param resource Resource-indicator value or vector.
#' @return `NULL` when `resource` is valid, otherwise a length-1 error message
#'   string describing the first problem.
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
  if (any(vapply(resource, has_uri_fragment, logical(1)))) {
    return("resource must not include a fragment component")
  }

  NULL
}

#' Internal: normalize URL path without touching query/fragment
#'
#' Collapses multiple consecutive slashes in the path component of a URL while
#' preserving the query string and fragment verbatim (no re-encoding). Used by
#' URL normalization and host-policy helpers.
#'
#' @param u URL string to normalize.
#' @return URL string with repeated path slashes collapsed.
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
#' Used by issuer and discovery URL builders.
#'
#' @param x URL string.
#' @return URL string with one trailing slash removed when present.
#' @keywords internal
#' @noRd
rtrim_slash <- function(x) sub("/$", "", x)

#' Internal: normalize hostnames to a stable ASCII comparison form
#'
#' Converts Unicode DNS labels to their A-label form so host comparisons work
#' consistently across locales and input forms. IP literals and wildcard-bearing
#' labels are left unchanged apart from lowercasing.
#'
#' @param host Host string or host pattern.
#' @param allow_glob Whether `*` and `?` wildcards are allowed within labels.
#' @return Normalized host string.
#' @keywords internal
#' @noRd
host_normalize_idna <- function(host, allow_glob = FALSE) {
  if (is.null(host) || is.na(host)) {
    return(host)
  }

  host <- trimws(as.character(host))
  if (!nzchar(host)) {
    return(host)
  }

  host <- sub("\\.$", "", host)
  lead_dot <- startsWith(host, ".")
  core <- if (lead_dot) substr(host, 2, nchar(host)) else host
  if (!nzchar(core)) {
    return(if (lead_dot) "." else core)
  }

  if (grepl(":", core, fixed = TRUE) || grepl("^[0-9.]+$", core)) {
    return(tolower(host))
  }

  labels <- strsplit(core, ".", fixed = TRUE)[[1]]
  labels <- vapply(
    labels,
    function(label) {
      if (!nzchar(label)) {
        return(label)
      }

      if (isTRUE(allow_glob) && grepl("[*?]", label)) {
        return(tolower(label))
      }

      label_utf8 <- enc2utf8(label)
      if (all(utf8ToInt(label_utf8) < 128L)) {
        return(tolower(label_utf8))
      }

      tryCatch(
        tolower(urltools::puny_encode(label_utf8)),
        error = function(...) tolower(label_utf8)
      )
    },
    character(1),
    USE.NAMES = FALSE
  )

  out <- paste(labels, collapse = ".")
  if (lead_dot) {
    out <- paste0(".", out)
  }

  out
}

#' Internal: Parse URL and extract normalized scheme and host
#'
#' Returns a list with lowercased scheme and hostname. Errors with err_config
#' when the URL can't be parsed or has no hostname. Used by host-policy and
#' issuer/JWKS validation helpers.
#'
#' @param url URL string to parse.
#' @param label Human-readable label used in error messages.
#' @return List with normalized `scheme` and `host` entries.
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
  host <- host_normalize_idna(host)

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
#' Used where only the hostname is needed for allowlist or issuer checks.
#'
#' @param url URL string to parse.
#' @param label Human-readable label used in error messages.
#' @return Normalized host string.
#' @keywords internal
#' @noRd
parse_url_host <- function(url, label = "url") {
  h <- parse_url_components(url, label)$host
  sub("^\\[([^\\]]+)\\]$", "\\1", h)
}

# 3 URL host policy helpers ----------------------------------------------------

## 3.1 Per-URL host validation -------------------------------------------------

#' Internal: validate one URL against host and scheme policy
#'
#' Used by [is_ok_host()] so vector inputs can be checked one URL at a time with
#' the same scheme normalization and allowlist semantics.
#'
#' @param x URL string to validate.
#' @param allowed_non_https_hosts Hosts allowed to use `http` instead of
#'   `https`.
#' @param allowed_hosts Optional host allowlist.
#' @return `TRUE` when the URL passes all host-policy checks.
#' @keywords internal
#' @noRd
is_ok_host_one <- function(x, allowed_non_https_hosts, allowed_hosts) {
  if (is.null(x) || is.na(x)) {
    return(FALSE)
  }
  x <- trimws(as.character(x))
  if (!nzchar(x)) {
    return(FALSE)
  }

  if (!grepl("^[A-Za-z][A-Za-z0-9+.-]*://", x)) {
    plausible <- (grepl("^\\[", x) ||
      grepl("localhost", x, ignore.case = TRUE) ||
      grepl("^[0-9]{1,3}(\\.[0-9]{1,3}){3}", x) ||
      grepl("::", x, fixed = TRUE) ||
      grepl("\\.", x) ||
      grepl(":[0-9]{1,5}", x)) &&
      !grepl("\\s", x)

    if (!plausible) {
      return(FALSE)
    }

    http_try <- paste0("http://", x)
    if (is_ok_host_one(http_try, allowed_non_https_hosts, allowed_hosts)) {
      return(TRUE)
    }

    https_try <- paste0("https://", x)
    return(is_ok_host_one(https_try, allowed_non_https_hosts, allowed_hosts))
  }

  parsed <- try(httr2::url_parse(x), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    return(FALSE)
  }

  scheme <- tolower(parsed$scheme %||% "")
  host <- tolower(trimws(parsed$hostname %||% ""))

  if (!nzchar(host)) {
    mm <- regexec("^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]+)", x, perl = TRUE)
    parts <- regmatches(x, mm)[[1]]
    if (length(parts) >= 2) {
      auth <- parts[2]
      if (grepl("^\\[", auth)) {
        host <- sub("^\\[([^\\]]+)\\].*$", "\\1", auth, perl = TRUE)
      } else {
        host <- sub(":.*$", "", auth, perl = TRUE)
      }
      host <- tolower(host)
    }
  }

  host <- sub("^\\[([^\\]]+)\\](?::.*)?$", "\\1", host, perl = TRUE)
  host <- host_normalize_idna(host)
  if (!nzchar(host)) {
    return(FALSE)
  }

  if (!host_matches_any(host, allowed_hosts)) {
    if (
      !is.null(allowed_hosts) &&
        length(allowed_hosts) > 0 &&
        grepl(":", host, fixed = TRUE)
    ) {
      ah <- tolower(vapply(
        allowed_hosts,
        host_normalize_pattern,
        character(1)
      ))
      if (!(host %in% ah || paste0("[", host, "]") %in% ah)) {
        return(FALSE)
      }
    } else {
      return(FALSE)
    }
  }

  if (scheme == "https") {
    return(TRUE)
  }

  if (scheme == "http") {
    if (
      is.null(allowed_non_https_hosts) || length(allowed_non_https_hosts) == 0
    ) {
      return(FALSE)
    }

    if (identical(tolower(host), "::1")) {
      allowed_http_hosts <- tolower(trimws(as.character(
        allowed_non_https_hosts
      )))
      if (any(allowed_http_hosts %in% c("::1", "[::1]"))) {
        return(TRUE)
      }
    }

    if (host_matches_any(host, allowed_non_https_hosts)) {
      return(TRUE)
    }
    return(FALSE)
  }

  FALSE
}

## 3.2 Host-pattern normalization and matching ---------------------------------

#' Internal: normalize a host pattern to a bare hostname
#'
#' Strips scheme and userinfo, drops path and (for non-IPv6) port
#' Preserves leading dot semantics (e.g., .example.com)
#' Handles bracketed IPv6 forms `[::1]`. Used by host allowlist helpers.
#'
#' @param pat Host-pattern string to normalize.
#' @return Bare normalized hostname or host pattern.
#' @keywords internal
#' @noRd
host_normalize_pattern <- function(pat) {
  if (is.null(pat) || is.na(pat)) {
    return(pat)
  }
  p <- trimws(as.character(pat))
  if (!nzchar(p)) {
    return(p)
  }

  # Preserve leading dot for subdomain semantics (e.g., .example.com)
  lead_dot <- startsWith(p, ".")

  # Remove scheme if present
  p <- sub("^[A-Za-z][A-Za-z0-9+.-]*://", "", p, perl = TRUE)

  # Strip userinfo
  p <- sub("^[^@]*@", "", p, perl = TRUE)

  # Cut at first '/' (drop any path)
  p <- sub("/.*$", "", p, perl = TRUE)

  # Extract host (IPv6 in [ ] or normal); drop port for non-IPv6 literals
  if (grepl("^\\[", p)) {
    # [IPv6] -> IPv6
    p <- sub("^\\[([^\\]]+)\\].*$", "\\1", p, perl = TRUE)
  } else {
    # Count colons to detect bracketless IPv6 literals; don't strip by ':' if IPv6
    m <- gregexpr(":", p, perl = TRUE)[[1]]
    ncol <- if (identical(m, -1L)) 0L else length(m)
    if (ncol >= 2) {
      # Looks like bracketless IPv6 literal: keep as-is (do not drop :port)
      p <- p
    } else {
      # Normal hostname or host:port -> drop :port if present
      p <- sub(":.*$", "", p, perl = TRUE)
    }
  }

  # Reapply leading dot if it was present originally and retained meaning
  if (lead_dot && !startsWith(p, ".")) {
    p <- paste0(".", p)
  }

  host_normalize_idna(p, allow_glob = TRUE)
}

#' Internal: convert a glob host pattern to a case-insensitive regex
#'
#' Supports '*' and '?' and leading-dot semantics (domain itself or any subdomain)
#' Used by host allowlist matching.
#'
#' @param pat Host pattern.
#' @return Regex string, or `NULL` for invalid patterns.
#' @keywords internal
#' @noRd
host_glob_to_regex <- function(pat) {
  # Be robust to NA/null/blank inputs
  if (is.null(pat) || is.na(pat)) {
    return(NULL)
  }
  pat <- trimws(tolower(pat))
  if (!isTRUE(nzchar(pat))) {
    return(NULL)
  }

  if (startsWith(pat, ".")) {
    core <- substr(pat, 2, nchar(pat))
    # Escape regex metacharacters EXCEPT * and ? which are glob wildcards
    core_esc <- gsub(
      "([.\\^$|()\\[\\]{}+\\\\])",
      "\\\\\\1",
      core,
      perl = TRUE
    )
    # Convert glob wildcards to regex equivalents
    core_esc <- gsub("*", ".*", core_esc, fixed = TRUE)
    core_esc <- gsub("?", ".", core_esc, fixed = TRUE)
    return(paste0("^(?:", core_esc, "|(?:[^.]+\\.)+", core_esc, ")$"))
  }

  # Escape regex metacharacters EXCEPT * and ? which are glob wildcards
  esc <- gsub("([.\\^$|()\\[\\]{}+\\\\])", "\\\\\\1", pat, perl = TRUE)
  # Convert glob wildcards to regex equivalents
  esc <- gsub("*", ".*", esc, fixed = TRUE)
  esc <- gsub("?", ".", esc, fixed = TRUE)
  paste0("^", esc, "$")
}

#' Check whether a host matches an allowlist
#'
#' When `patterns` is `NULL` or empty, this returns `TRUE`. Patterns may include
#' globs and leading-dot semantics. IPv6 bracket equivalence is handled. Used by
#' [is_ok_host()] and related validators.
#'
#' @param host Host string to test.
#' @param patterns Allowlist patterns.
#' @return `TRUE` when `host` matches at least one allowlist pattern; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
host_matches_any <- function(host, patterns) {
  if (is.null(patterns) || length(patterns) == 0) {
    return(TRUE)
  }
  # Remember original length to detect degenerate post-filter empties
  orig_len <- length(patterns)
  # Be forgiving if callers accidentally include scheme/port; normalize to hostname
  patterns <- vapply(patterns, host_normalize_pattern, character(1))
  # Drop NA/blank entries early to avoid regex generation surprises
  patterns <- patterns[!is.na(patterns) & nzchar(patterns)]
  patterns <- vapply(
    patterns,
    host_normalize_idna,
    character(1),
    allow_glob = TRUE
  )
  # If the caller provided entries but nothing remained after normalization,
  # deny by default rather than silently allowing any host
  if (orig_len > 0 && length(patterns) == 0) {
    return(FALSE)
  }
  host_lc <- host_normalize_idna(host)
  # Direct equality: also consider bracketed/unbracketed IPv6 equivalence
  if (host_lc %in% patterns) {
    return(TRUE)
  }
  host_br <- if (grepl(":", host_lc, fixed = TRUE) && !grepl("^\\[", host_lc)) {
    paste0("[", host_lc, "]")
  } else {
    host_lc
  }
  if (host_br %in% patterns) {
    return(TRUE)
  }
  rxs <- Filter(Negate(is.null), lapply(patterns, host_glob_to_regex))
  # If patterns were supplied but yielded no usable regexes, deny rather than allow-all
  if (orig_len > 0 && length(rxs) == 0) {
    return(FALSE)
  }
  any(vapply(
    rxs,
    function(rx) grepl(rx, tolower(host), perl = TRUE),
    logical(1)
  ))
}
