# This file contains the host and allowlist helpers that decide whether URLs
# are acceptable for OAuth redirects, endpoints, and callbacks.
# Use them when a URL must satisfy the package's HTTPS and allowed-host policy,
# including wildcard and loopback rules.

# 1 URL host policy helpers -----------------------------------------------

## 1.1 Host allowlist matching --------------------------------------------

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

# Convert one glob-style host pattern into a regex.
# Used by host allowlist matching. Input: host pattern. Output: regex string or
# NULL.
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

#' Internal: does a host match any pattern from an allowlist?
#'
#' When `patterns` is NULL/empty, returns TRUE (no restriction). Patterns may
#' include globs and leading-dot semantics. IPv6 bracket equivalence is handled.
#'
#' @keywords internal
#' @noRd
# Check whether one host matches any entry in an allowlist.
# Used by is_ok_host() and related validators. Input: host string and patterns.
# Output: TRUE or FALSE.
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
