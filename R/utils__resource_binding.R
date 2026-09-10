# Connection requests apply this policy before attaching credentials. It is
# deliberately stricter than the generic host helper and cannot be relaxed by
# process-wide URL or redirect options. RFC 3986 sections 3, 5 and 6 inform the
# comparison; ambiguous path encodings are rejected instead of guessed.
resource_binding_error <- function() {
  err_input(
    "Resource destination is outside its approved base or has ambiguous URL syntax"
  )
}

resource_binding_path <- function(path) {
  if (!nzchar(path)) {
    return("/")
  }
  if (grepl("[\\\\;]|//|%(?![0-9A-Fa-f]{2})", path, perl = TRUE)) {
    resource_binding_error()
  }
  escapes <- gregexpr("%[0-9A-Fa-f]{2}", path, perl = TRUE)
  encoded <- regmatches(path, escapes)[[1L]]
  if (length(encoded)) {
    decoded <- vapply(
      encoded,
      function(x) {
        byte <- strtoi(substring(x, 2L), 16L)
        if (byte >= 128L) {
          return(toupper(x))
        }
        char <- rawToChar(as.raw(byte))
        if (!grepl("^[A-Za-z0-9._~-]$", char)) {
          resource_binding_error()
        }
        char
      },
      ""
    )
    regmatches(path, escapes) <- list(decoded)
  }
  if (!validUTF8(utils::URLdecode(path))) {
    resource_binding_error()
  }
  segments <- strsplit(path, "/", fixed = TRUE)[[1L]]
  if (any(segments %in% c(".", ".."))) {
    resource_binding_error()
  }
  path
}

resource_binding_components <- function(
  url,
  base = FALSE,
  canonicalize = TRUE
) {
  if (
    !is_valid_string(url) ||
      nchar(url, type = "bytes") > 8192L ||
      !grepl("^https?://", url, ignore.case = TRUE) ||
      grepl("[[:space:][:cntrl:]\\\\#]|%(?![0-9A-Fa-f]{2})", url, perl = TRUE)
  ) {
    resource_binding_error()
  }
  # Validate the original path before httr2/curl can remove dot segments or
  # decode escaped delimiters. Compare and send this same canonical path.
  raw_path <- sub(
    "^https?://[^/?#]*",
    "",
    sub("[?#].*$", "", url),
    ignore.case = TRUE
  )
  path <- resource_binding_path(raw_path)
  parsed <- tryCatch(httr2::url_parse(url), error = function(...) {
    resource_binding_error()
  })
  scheme <- tolower(parsed$scheme %||% "")
  host <- tolower(parsed$hostname %||% "")
  if (
    !nzchar(host) ||
      !is.null(parsed$username) ||
      !is.null(parsed$password) ||
      grepl("[@%*?]", host) ||
      endsWith(host, ".") ||
      (base && grepl("?", url, fixed = TRUE))
  ) {
    resource_binding_error()
  }
  # Pin the permitted HTTP exception; global permissive options cannot add hosts.
  if (
    !is_ok_host(
      url,
      allowed_non_https_hosts = c("localhost", "127.0.0.1", "::1", "[::1]")
    )
  ) {
    resource_binding_error()
  }
  port <- parsed$port %||% if (scheme == "https") "443" else "80"
  port <- suppressWarnings(as.integer(port))
  if (length(port) != 1L || is.na(port) || port < 1L || port > 65535L) {
    resource_binding_error()
  }
  if (base && path != "/") {
    path <- sub("/$", "", path)
  }
  parsed$scheme <- scheme
  parsed$hostname <- host
  parsed$port <- if (port == if (scheme == "https") 443L else 80L) {
    NULL
  } else {
    port
  }
  parsed$path <- path
  list(
    scheme = scheme,
    host = host,
    port = port,
    path = path,
    # Discovery validates identifiers without rewriting them. Avoiding a URL
    # rebuild also accommodates curl backends that cannot rebuild IPv6 hosts.
    url = if (canonicalize) httr2::url_build(parsed) else url
  )
}

normalize_resource_bases <- function(resource_bases) {
  if (
    !is.character(resource_bases) ||
      !length(resource_bases) ||
      length(resource_bases) > 64L ||
      anyNA(resource_bases) ||
      is.null(names(resource_bases)) ||
      anyNA(names(resource_bases)) ||
      !all(grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", names(resource_bases))) ||
      anyDuplicated(names(resource_bases))
  ) {
    err_config(
      "resource_bases must be a non-empty character vector with unique resource IDs"
    )
  }
  result <- vapply(
    resource_bases,
    function(base) resource_binding_components(base, base = TRUE)$url,
    ""
  )
  if (anyDuplicated(result)) {
    err_config("Resource IDs must designate distinct approved bases")
  }
  result
}

resolve_bound_resource <- function(base, reference = "") {
  approved <- resource_binding_components(base, base = TRUE)
  if (
    !is.character(reference) ||
      length(reference) != 1L ||
      is.na(reference) ||
      nchar(reference, type = "bytes") > 8192L ||
      startsWith(reference, "//")
  ) {
    resource_binding_error()
  }
  if (grepl("^[A-Za-z][A-Za-z0-9+.-]*:", reference)) {
    candidate <- reference
  } else if (startsWith(reference, "/")) {
    root <- httr2::url_parse(approved$url)
    root$path <- "/"
    candidate <- paste0(sub("/$", "", httr2::url_build(root)), reference)
  } else {
    candidate <- paste0(sub("/$", "", approved$url), "/", reference)
  }
  resolved <- resource_binding_components(candidate)
  if (
    !identical(
      approved[c("scheme", "host", "port")],
      resolved[c("scheme", "host", "port")]
    ) ||
      !(approved$path == "/" ||
        resolved$path == approved$path ||
        startsWith(resolved$path, paste0(approved$path, "/")))
  ) {
    resource_binding_error()
  }
  resolved$url
}
