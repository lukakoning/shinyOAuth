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
#' Requires the discovery issuer to be present and well-formed.
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
