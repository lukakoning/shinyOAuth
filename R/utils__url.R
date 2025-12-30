#' @title
#' Check if URL(s) are HTTPS and/or in allowed hosts lists
#'
#' @description
#' Returns TRUE if every input URL is either:
#' - a syntactically valid HTTPS URL, and (if set) whose host matches `allowed_hosts`, or
#' - an HTTP URL whose host matches `allowed_non_https_hosts` (e.g. localhost, 127.0.0.1, ::1),
#'   and (if set) also matches `allowed_hosts`.
#'
#' If the input omits the scheme (e.g., "localhost:8080/cb"), this function
#' will first attempt to validate it as HTTP (useful for loopback development),
#' and if that fails, as HTTPS. This mirrors how helpers normalize inputs for
#' convenience while still enforcing the same host and scheme policies.
#'
#' `allowed_hosts` is thus an allowlist of hosts/domains that are permitted, while
#' `allowed_non_https_hosts` defines which hosts are allowed to use HTTP instead of HTTPS.
#' If `allowed_hosts` is NULL or length 0, all hosts are allowed (subject to scheme rules),
#' but HTTPS is still required unless the host is in `allowed_non_https_hosts`.
#'
#' Since `allowed_hosts` supports globs, a value like "*" matches any host
#' and therefore effectively disables endpoint host restrictions. Only use a catch‑all
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
#' but can be used elsewhere to test if URLs would be allowed. Internally, it will always
#' determine the default values for `allowed_non_https_hosts` and `allowed_hosts`
#' from the options `shinyOAuth.allowed_non_https_hosts` and
#' `shinyOAuth.allowed_hosts`, respectively.
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

  # Helper: check if a host is in the HTTP exemptions list (with glob support)
  host_in_http_exempt <- function(host, patterns) {
    if (is.null(patterns) || length(patterns) == 0) {
      return(FALSE)
    }

    # Fast-path: IPv6 loopback literal
    if (identical(tolower(host), "::1")) {
      lp <- tolower(trimws(as.character(patterns)))
      if (any(lp %in% c("::1", "[::1]"))) return(TRUE)
    }

    # Reuse common host matching semantics (globs, IPv6 bracket forms)
    host_matches_any(host, patterns)
  }

  # Wrapper for checking a single URL
  check_one <- function(x) {
    if (is.null(x) || is.na(x)) {
      return(FALSE)
    }
    x <- trimws(as.character(x))
    if (!nzchar(x)) {
      return(FALSE)
    }

    # If scheme is missing, attempt http then https normalization for plausible inputs
    # (loopback names, IPv4, bracketed IPv6, has a dot, or explicit :port).
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
      if (check_one(http_try)) {
        return(TRUE)
      }

      https_try <- paste0("https://", x)
      return(check_one(https_try))
    }

    # Robust parse via httr2 for scheme + hostname (handles IPv6 brackets)
    parsed <- try(httr2::url_parse(x), silent = TRUE)
    if (inherits(parsed, "try-error")) {
      return(FALSE)
    }

    scheme <- tolower(parsed$scheme %||% "")
    host <- tolower(trimws(parsed$hostname %||% ""))

    if (!nzchar(host)) {
      # Fallback: extract authority and host manually (handles bracketed IPv6)
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

    # Normalize bracketed IPv6 hostnames to bare form for matching (allow optional :port)
    host <- sub("^\\[([^\\]]+)\\](?::.*)?$", "\\1", host, perl = TRUE)
    host <- sub("\\.$", "", host)
    if (!nzchar(host)) {
      return(FALSE)
    }

    # Enforce allowed_hosts allowlist if provided
    if (!host_matches_any(host, allowed_hosts)) {
      # Defensive fallback: direct equality for IPv6 literals against normalized patterns
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
      # Apply matching semantics (globs, Unicode, IPv6 bracketless/bracketed) to HTTP exemptions
      if (host_in_http_exempt(host, allowed_non_https_hosts)) {
        return(TRUE)
      }
      return(FALSE)
    }

    FALSE
  }

  # Check all URLs; return TRUE only if all pass
  all(vapply(url, check_one, logical(1)))
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

#' Internal: normalize a host pattern to a bare hostname
#'
#' Strips scheme and userinfo, drops path and (for non-IPv6) port
#' Preserves leading dot semantics (e.g., .example.com)
#' Handles bracketed IPv6 forms `[::1]`
#'
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
    # [IPv6] → IPv6
    p <- sub("^\\[([^\\]]+)\\].*$", "\\1", p, perl = TRUE)
  } else {
    # Count colons to detect bracketless IPv6 literals; don't strip by ':' if IPv6
    m <- gregexpr(":", p, perl = TRUE)[[1]]
    ncol <- if (identical(m, -1L)) 0L else length(m)
    if (ncol >= 2) {
      # Looks like bracketless IPv6 literal: keep as-is (do not drop :port)
      p <- p
    } else {
      # Normal hostname or host:port → drop :port if present
      p <- sub(":.*$", "", p, perl = TRUE)
    }
  }

  # Reapply leading dot if it was present originally and retained meaning
  if (lead_dot && !startsWith(p, ".")) {
    p <- paste0(".", p)
  }
  p
}

#' Internal: convert a glob host pattern to a case-insensitive regex
#'
#' Supports '*' and '?' and leading-dot semantics (domain itself or any subdomain)
#'
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
    core_esc <- gsub(
      "([.\\^$|()\\[\\]{}+?\\\\])",
      "\\\\\\1",
      core,
      perl = TRUE
    )
    return(paste0("^(?:", core_esc, "|(?:[^.]+\\.)+", core_esc, ")$"))
  }

  esc <- gsub("([.\\^$|()\\[\\]{}+?\\\\])", "\\\\\\1", pat, perl = TRUE)
  esc <- gsub("\\*", ".*", esc, perl = TRUE)
  esc <- gsub("\\?", ".", esc, perl = TRUE)
  paste0("^", esc, "$")
}

#' Internal: does a host match any pattern from an allowlist?
#'
#' When `patterns` is NULL/empty, returns TRUE (no restriction). Patterns may
#' include globs and leading-dot semantics. IPv6 bracket equivalence is handled.
#'
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
  patterns <- tolower(patterns)
  # If the caller provided entries but nothing remained after normalization,
  # deny by default rather than silently allowing any host
  if (orig_len > 0 && length(patterns) == 0) {
    return(FALSE)
  }
  host_lc <- tolower(host)
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

normalize_issuer_url <- function(url, label = "issuer") {
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

  port <- parsed$port %||% ""
  port <- as.character(port)
  port <- if (nzchar(port)) paste0(":", port) else ""

  path <- parsed$path %||% ""
  path <- as.character(path)
  path <- if (!nzchar(path) || identical(path, "/")) {
    ""
  } else {
    path <- sub("/+$", "", path)
    if (!startsWith(path, "/")) paste0("/", path) else path
  }

  query <- parsed$query %||% ""
  query <- as.character(query)
  query <- if (nzchar(query)) paste0("?", query) else ""

  fragment <- parsed$fragment %||% ""
  fragment <- as.character(fragment)
  fragment <- if (nzchar(fragment)) paste0("#", fragment) else ""

  paste0(scheme, "://", host, port, path, query, fragment)
}

#' Internal: Resolve issuer from discovery with issuer matching policy
#'
#' Prefers the discovery issuer when provided.
#'
#' Matching is controlled by `issuer_match`:
#' - "url": require full issuer URL match after trailing-slash normalization
#' - "host": require scheme+host match only (explicit opt-out)
#' - "none": do not validate issuer consistency
#'
#' @keywords internal
#' @noRd
validate_discovery_issuer <- function(
  issuer_input,
  issuer_discovered,
  issuer_match = c("url", "host", "none")
) {
  issuer_match <- match.arg(issuer_match)

  # Prefer discovered when available; otherwise fall back to input
  iss <- issuer_discovered %||% issuer_input

  # Nothing to check if discovery didn't supply an issuer
  if (!is_valid_string(issuer_discovered)) {
    return(iss)
  }

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

  in_norm <- normalize_issuer_url(issuer_input, "issuer")
  dc_norm <- normalize_issuer_url(issuer_discovered, "discovery issuer")

  if (!identical(in_norm, dc_norm)) {
    err_config(
      c(
        "x" = "OIDC discovery issuer mismatch",
        "!" = sprintf("Input '%s' vs discovery '%s'", in_norm, dc_norm),
        "i" = "Set issuer_match = 'host' to compare only scheme+host (not recommended)"
      )
    )
  }

  iss
}

#' Internal: validate absolute URL against allowed hosts
#'
#' Ensures the provided URL is absolute (has scheme and hostname) and that it
#' satisfies the host/scheme policy enforced by `is_ok_host()` with the given
#' allowlist. Intended to centralize endpoint checks used by discovery.
#'
#' On failure, raises a configuration error with consistent messaging.
#'
#' @keywords internal
#' @noRd
validate_endpoint <- function(u, allowed_hosts_vec) {
  # Allow NA/empty to pass silently (callers may treat missing endpoints as optional)
  if (is.na(u) || !nzchar(u)) {
    return(invisible(TRUE))
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
