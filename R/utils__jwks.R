#' Internal: Fetch JWKS for issuer (cachem-only)
#'
#' Attempts to download the OpenID Connect discovery document to locate the
#' JWKS URI, then fetches and caches the key set.
#'
#' Caching details:
#' - Cache entries are keyed by a stable hex sha256 of the issuer URL, combined
#'   with a hex sha256 of the current pinning configuration (sorted pins and
#'   `pin_mode`). This prevents reusing a JWKS cached under a different pinning
#'   policy.
#' - For additional safety, cached entries are re-validated against the current
#'   `pins`/`pin_mode` before being returned. If validation fails, the cache
#'   entry is evicted and a fresh JWKS is fetched.
#'
#' @param issuer Issuer base URL (must include scheme)
#' @param jwks_cache A cachem cache used for caching (keys by hashed issuer)
#' @param force_refresh Force re-fetching JWKS and overwrite cache
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'  to pin against
#' @param pin_mode Either "any" (at least one key matches a pin) or "all"
#'  (every RSA/EC/OKP key must match a pin)
#'
#' @return The JWKS as a list
#'
#' @keywords internal
#' @noRd
fetch_jwks <- function(
  issuer,
  jwks_cache,
  force_refresh = FALSE,
  pins = NULL,
  pin_mode = c("any", "all"),
  provider = NULL
) {
  # Duck-type the cache interface instead of enforcing cachem inheritance
  has_get <- !is.null(jwks_cache$get) && is.function(jwks_cache$get)
  has_set <- !is.null(jwks_cache$set) && is.function(jwks_cache$set)
  if (!isTRUE(has_get && has_set)) {
    err_config(c(
      "x" = "Invalid jwks_cache backend",
      "!" = "Must provide `$get(key, missing = NULL)` and `$set(key, value)`",
      "i" = "Optional `$remove(key)` is respected if present"
    ))
  }
  pin_mode <- match.arg(pin_mode)
  now <- as.numeric(Sys.time())
  # Compute a cache key that incorporates issuer + current pinning configuration
  cache_key <- jwks_cache_key(issuer, pins = pins, pin_mode = pin_mode)

  entry <- jwks_cache$get(cache_key, missing = NULL)

  # Rely entirely on cachem's own eviction policy (max_age). If an entry is
  # present, treat it as fresh; if it has been evicted/expired, $get() will
  # return NULL and we'll refetch. We still record fetched_at for diagnostics.
  if (!force_refresh && !is.null(entry) && !is.null(entry$jwks)) {
    # Defense-in-depth: re-validate cached JWKS under current pinning policy
    ok <- try(
      validate_jwks(entry$jwks, pins = pins, pin_mode = pin_mode),
      silent = TRUE
    )
    if (!inherits(ok, "try-error")) {
      return(entry$jwks)
    } else {
      # Evict incompatible/invalid cached entry and continue to refetch
      if (!is.null(jwks_cache$remove) && is.function(jwks_cache$remove)) {
        jwks_cache$remove(cache_key)
      } else {
        # Fallback: overwrite below after refetch
      }
    }
  }

  disco_url <- paste0(rtrim_slash(issuer), "/.well-known/openid-configuration")
  resp <- httr2::request(disco_url) |>
    add_req_defaults() |>
    req_with_retry()
  if (httr2::resp_is_error(resp)) {
    err_http(
      c("x" = "Failed to fetch OIDC discovery document"),
      resp,
      context = list(issuer = issuer)
    )
  }
  disc <- httr2::resp_body_json(resp, simplifyVector = TRUE)
  jwks_uri <- disc$jwks_uri %||%
    {
      err_parse(c("x" = "Discovery document missing jwks_uri"))
    }
  if (!is_ok_host(jwks_uri)) {
    err_config(c(
      "x" = "jwks_uri is not in an allowed host",
      "!" = paste0("Value: ", jwks_uri),
      "i" = "See `?is_ok_host` to configure allowed hosts"
    ))
  }
  validate_jwks_host_matches_issuer(issuer, jwks_uri, provider = provider)

  jresp <- httr2::request(jwks_uri) |>
    add_req_defaults() |>
    req_with_retry()
  if (httr2::resp_is_error(jresp)) {
    err_http(
      c("x" = "Failed to fetch JWKS"),
      jresp,
      context = list(jwks_uri = jwks_uri)
    )
  }
  jwks <- httr2::resp_body_json(jresp, simplifyVector = TRUE)
  # Validate structure and (optionally) pin before caching
  validate_jwks(jwks, pins = pins, pin_mode = pin_mode)
  new_entry <- list(jwks = jwks, fetched_at = now)
  jwks_cache$set(cache_key, new_entry)
  jwks
}

#' Internal: Rate-limit forced JWKS refresh attempts
#'
#' This is used as a defense-in-depth measure against attackers sending tokens
#' with random `kid` values to trigger repeated forced JWKS refreshes.
#'
#' Implementation notes:
#' - The rate-limit state is stored in the existing `jwks_cache` backend so it
#'   can be shared when users provide a shared cache (e.g., Redis) and so tests
#'   naturally isolate by using fresh caches.
#' - The key is derived from `jwks_cache_key()` (issuer + pinning policy).
#'
#' @keywords internal
#' @noRd
jwks_force_refresh_allowed <- function(
  issuer,
  jwks_cache,
  pins = NULL,
  pin_mode = c("any", "all"),
  min_interval = 30,
  now = as.numeric(Sys.time())
) {
  pin_mode <- match.arg(pin_mode)
  stopifnot(
    is.numeric(min_interval),
    length(min_interval) == 1L,
    !is.na(min_interval),
    min_interval >= 0
  )

  # Derive a stable, cache-safe key for the throttle entry
  base_key <- jwks_cache_key(issuer, pins = pins, pin_mode = pin_mode)
  throttle_key <- paste0(base_key, "xfr")

  last <- jwks_cache$get(throttle_key, missing = NULL)
  if (is.numeric(last) && length(last) == 1L && !is.na(last)) {
    if ((now - last) < min_interval) {
      return(FALSE)
    }
  }

  # Record the attempt time before any network work happens.
  jwks_cache$set(throttle_key, now)
  TRUE
}

#' Internal: Select candidate JWKs for signature verification
#'
#' Filters keys that declare use != "sig" while retaining keys that omit `use`.
#' Optionally restricts to a specific `kid` and orders candidates to prefer
#' keys whose JWK `alg` matches the JWT header algorithm when provided.
#'
#' @param jwks_or_keys A JWKS list (with $keys) or a normalized list of JWKs
#' @param header_alg Optional JWT header alg (character)
#' @param kid Optional key id to restrict candidates to
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'   to restrict candidate keys to. Only keys with matching thumbprints are
#'   returned.
#'
#' @return A list of JWKs, filtered and ordered by preference
#'
#' @keywords internal
#' @noRd
select_candidate_jwks <- function(
  jwks_or_keys,
  header_alg = NULL,
  kid = NULL,
  pins = NULL
) {
  # Normalize input to a list of key objects
  keys <- jwks_or_keys
  if (is.list(jwks_or_keys) && !is.null(jwks_or_keys$keys)) {
    keys <- jwks_or_keys$keys
  }
  if (is.data.frame(keys)) {
    keys <- unname(lapply(seq_len(nrow(keys)), function(i) {
      as.list(keys[i, , drop = FALSE])
    }))
  } else if (is.list(keys)) {
    nm <- names(keys)
    if (
      !is.null(nm) && any(nm %in% c("kty", "kid", "n", "e", "crv", "x", "y"))
    ) {
      keys <- list(keys)
    }
  } else {
    err_parse("JWKS keys malformed")
  }

  if (!is.list(keys)) {
    keys <- list()
  }

  # Keep keys where use is missing or explicitly 'sig'
  keep_use <- vapply(
    keys,
    function(k) {
      u <- try(k$use, silent = TRUE)
      if (inherits(u, "try-error") || is.null(u)) {
        return(TRUE)
      }
      is.character(u) && length(u) == 1L && identical(tolower(u), "sig")
    },
    logical(1)
  )
  keys <- keys[keep_use]

  # Honor key_ops: keep keys where key_ops is missing or includes "verify"
  # (RFC 7517 Section 4.3: key_ops restricts permitted operations)
  keep_ops <- vapply(
    keys,
    function(k) {
      ops <- try(k$key_ops, silent = TRUE)
      if (inherits(ops, "try-error") || is.null(ops)) {
        return(TRUE)
      }
      if (!is.character(ops) || length(ops) == 0L) {
        return(TRUE)
      }
      # For signature verification, the key must support "verify"
      tolower("verify") %in% tolower(ops)
    },
    logical(1)
  )
  keys <- keys[keep_ops]

  # If a kid is provided, restrict to matching keys
  if (!is.null(kid)) {
    keys <- Filter(
      function(k) {
        kk <- k$kid %||% NA_character_
        is.character(kk) && length(kk) == 1L && !is.na(kk) && identical(kk, kid)
      },
      keys
    )
  }

  # Order by preference: JWK alg matching header_alg comes first
  if (
    length(keys) > 1L &&
      is.character(header_alg) &&
      length(header_alg) == 1L &&
      nzchar(header_alg)
  ) {
    ha <- toupper(header_alg)
    ord_score <- vapply(
      keys,
      function(k) {
        ka <- try(k$alg, silent = TRUE)
        if (inherits(ka, "try-error") || is.null(ka)) {
          return(1L)
        }
        if (!is.character(ka) || length(ka) != 1L || !nzchar(ka)) {
          return(1L)
        }
        if (identical(toupper(ka), ha)) 0L else 1L
      },
      integer(1)
    )
    idx <- order(ord_score)
    keys <- keys[idx]
  }

  # Filter by pins: only return keys whose thumbprint is in the pin list.
  # This ensures signature verification uses only pinned keys, not merely
  # that the JWKS passes a presence check.
  if (!is.null(pins) && length(pins) > 0 && length(keys) > 0) {
    pins <- unique(as.character(pins))
    keys <- Filter(
      function(k) {
        tp <- try(compute_jwk_thumbprint(k), silent = TRUE)
        if (inherits(tp, "try-error")) {
          return(FALSE)
        }
        tp %in% pins
      },
      keys
    )
  }

  keys
}

#' Internal: Compute cache key for JWKS entries
#'
#' Uses hex SHA-256 of issuer URL concatenated with hex SHA-256 of the
#' pinning configuration (sorted unique pins + pin_mode). The resulting key is
#' lowercase alphanumeric only, suitable for cachem backends that restrict key
#' characters.
#'
#' @keywords internal
#' @noRd
jwks_cache_key <- function(issuer, pins = NULL, pin_mode = c("any", "all")) {
  pin_mode <- match.arg(pin_mode)
  # Normalize pins: NULL and length-0 both treated as empty
  pins_norm <- character(0)
  if (!is.null(pins) && length(pins) > 0) {
    pins_norm <- sort(unique(as.character(pins)))
  }
  # issuer hash
  ih_raw <- openssl::sha256(charToRaw(as.character(issuer)))
  ih <- paste0(sprintf("%02x", as.integer(ih_raw)), collapse = "")
  # config hash: "<mode>|<pin1>,<pin2>,..."
  cfg_str <- paste0(pin_mode, "|", paste(pins_norm, collapse = ","))
  ch_raw <- openssl::sha256(charToRaw(cfg_str))
  ch <- paste0(sprintf("%02x", as.integer(ch_raw)), collapse = "")
  # Use an alphanumeric delimiter to satisfy cache key constraints while keeping clarity
  paste0(ih, "x", ch)
}

#' Internal: Convert JWK (RSA, EC, or OKP) to an openssl public key
#'
#' @keywords internal
#' @noRd
jwk_to_pubkey <- function(jwk) {
  kty <- jwk$kty %||% err_parse("JWK missing kty")
  if (!kty %in% c("RSA", "EC", "OKP")) {
    err_parse(paste0("Unsupported JWK kty: ", kty))
  }
  # jose::read_jwk takes a JSON string or file path
  jwk_json <- jsonlite::toJSON(jwk, auto_unbox = TRUE, null = "null")
  key <- try(jose::read_jwk(jwk_json), silent = TRUE)
  if (inherits(key, "try-error")) {
    err_parse("Failed to parse JWK")
  }
  key
}

#' Internal: Compute RFC 7638 JWK thumbprint (SHA-256, base64url, no padding)
#'
#' Supports RSA, EC, and OKP public keys. The canonical JSON serialization uses
#' the minimal member set in lexicographic key order:
#' - RSA: {"e":"...","kty":"RSA","n":"..."}
#' - EC:  {"crv":"...","kty":"EC","x":"...","y":"..."}
#' - OKP: {"crv":"...","kty":"OKP","x":"..."}
#'
#' @keywords internal
#' @noRd
compute_jwk_thumbprint <- function(jwk) {
  if (!is.list(jwk)) {
    err_parse("JWK must be a list")
  }
  kty <- jwk$kty %||% err_parse("JWK missing kty")
  if (kty == "RSA") {
    e <- jwk$e %||% err_parse("RSA JWK missing e")
    n <- jwk$n %||% err_parse("RSA JWK missing n")
    if (!is.character(e) || !is.character(n)) {
      err_parse("RSA JWK e/n must be character")
    }
    canon <- list(e = e, kty = "RSA", n = n)
    # Order keys explicitly as required by RFC 7638 (lexicographic)
    canon <- canon[c("e", "kty", "n")]
  } else if (kty == "EC") {
    crv <- jwk$crv %||% err_parse("EC JWK missing crv")
    x <- jwk$x %||% err_parse("EC JWK missing x")
    y <- jwk$y %||% err_parse("EC JWK missing y")
    if (!is.character(crv) || !is.character(x) || !is.character(y)) {
      err_parse("EC JWK crv/x/y must be character")
    }
    canon <- list(crv = crv, kty = "EC", x = x, y = y)
    canon <- canon[c("crv", "kty", "x", "y")]
  } else if (kty == "OKP") {
    crv <- jwk$crv %||% err_parse("OKP JWK missing crv")
    x <- jwk$x %||% err_parse("OKP JWK missing x")
    if (!is.character(crv) || !is.character(x)) {
      err_parse("OKP JWK crv/x must be character")
    }
    canon <- list(crv = crv, kty = "OKP", x = x)
    canon <- canon[c("crv", "kty", "x")]
  } else {
    err_parse("Unsupported JWK kty for thumbprint")
  }
  json <- jsonlite::toJSON(canon, auto_unbox = TRUE, null = "null", digits = NA)
  # Ensure minified JSON (no whitespace); jsonlite pretty=FALSE by default
  json_raw <- charToRaw(as.character(json))
  digest <- openssl::sha256(json_raw)
  base64url_encode(digest)
}

#' Internal: Validate JWKS structure and optionally enforce pinning
#'
#' @param jwks Parsed JWKS (list)
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'   to pin against.
#' @param pin_mode Either "any" (at least one key matches a pin) or "all"
#'   (every RSA/EC/OKP key must match a pin).
#'
#' @keywords internal
#' @noRd
validate_jwks <- function(jwks, pins = NULL, pin_mode = c("any", "all")) {
  pin_mode <- match.arg(pin_mode)
  if (!is.list(jwks)) {
    err_parse("Invalid JWKS structure")
  }
  ks <- jwks$keys
  if (is.null(ks)) {
    err_parse("JWKS missing keys array")
  }
  if (is.data.frame(ks)) {
    ks <- unname(lapply(seq_len(nrow(ks)), function(i) {
      as.list(ks[i, , drop = FALSE])
    }))
  } else if (is.list(ks)) {
    nm <- names(ks)
    if (
      !is.null(nm) && any(nm %in% c("kty", "n", "e", "crv", "x", "y", "kid"))
    ) {
      ks <- list(ks)
    }
  } else {
    err_parse("JWKS keys malformed")
  }
  if (!is.list(ks)) {
    err_parse("JWKS keys must be a list")
  }
  if (length(ks) > 100) {
    err_parse("JWKS contains excessive keys")
  }

  # Validate each key minimally and ensure no private params leaked
  supported_seen <- 0L
  private_params <- c("d", "p", "q", "dp", "dq", "qi", "oth")
  thumbprints <- character()
  for (i in seq_along(ks)) {
    k <- ks[[i]]
    if (!is.list(k)) {
      err_parse("JWK entry must be an object")
    }
    kty <- k$kty %||% err_parse("JWK missing kty")
    kid <- k$kid %||% NA_character_
    if (!is.na(kid)) {
      if (!is.character(kid) || length(kid) != 1 || nchar(kid) > 128) {
        err_parse("JWK kid invalid")
      }
    }
    # No private key parameters in a JWKS
    if (any(names(k) %in% private_params)) {
      err_parse("JWKS contains private key material")
    }
    if (kty %in% c("RSA", "EC", "OKP")) {
      supported_seen <- supported_seen + 1L
      # Minimal member presence
      if (kty == "RSA") {
        if (!is.character(k$n) || !is.character(k$e)) {
          err_parse("RSA JWK missing n/e")
        }
      } else if (kty == "EC") {
        if (!is.character(k$crv) || !is.character(k$x) || !is.character(k$y)) {
          err_parse("EC JWK missing crv/x/y")
        }
      } else if (kty == "OKP") {
        if (!is.character(k$crv) || !is.character(k$x)) {
          err_parse("OKP JWK missing crv/x")
        }
      }
      # Compute thumbprint for pinning
      tp <- try(compute_jwk_thumbprint(k), silent = TRUE)
      if (!inherits(tp, "try-error")) {
        thumbprints <- c(thumbprints, tp)
      }
    }
  }
  if (supported_seen == 0L) {
    err_parse("JWKS contains no supported public keys (RSA/EC/OKP)")
  }

  # Enforce pinning if configured
  if (!is.null(pins) && length(pins) > 0) {
    pins <- unique(as.character(pins))
    if (pin_mode == "any") {
      if (!any(thumbprints %in% pins)) {
        err_parse("JWKS pinning failed: no key matches a configured pin")
      }
    } else if (pin_mode == "all") {
      # All supported keys must be pinned
      missed <- setdiff(thumbprints, pins)
      if (length(missed) > 0) {
        err_parse("JWKS pinning failed: unpinned key(s) present")
      }
    }
  }
  invisible(TRUE)
}

#' Internal: ensure JWKS host aligns with issuer
#'
#' Validates the discovery `jwks_uri` hostname according to the provider's
#' JWKS policy. When `provider@jwks_host_allow_only` is set, the `jwks_uri` host must equal
#' that value exactly. Otherwise, when `provider@jwks_host_issuer_match` is TRUE, the
#' `jwks_uri` host must match the issuer host or one of its subdomains. If both
#' settings are absent/disabled, no host relation is enforced. Prefer
#' configuring `jwks_host_allow_only` for providers that serve JWKS from a
#' different host rather than disabling issuer-match entirely.
#'
#' @keywords internal
#' @noRd
validate_jwks_host_matches_issuer <- function(
  issuer,
  jwks_uri,
  provider = NULL
) {
  issuer_host <- parse_url_host(issuer, "issuer")
  jwks_host <- parse_url_host(jwks_uri, "jwks_uri")

  # Default relaxed behavior unless provider opts in
  check_host <- FALSE
  pinned_host <- NA_character_
  if (!is.null(provider)) {
    # Best-effort access without hard S7 dependency here
    check_host <- isTRUE(try(provider@jwks_host_issuer_match, silent = TRUE))
    pinned_host <- try(provider@jwks_host_allow_only, silent = TRUE)
    if (inherits(pinned_host, "try-error")) pinned_host <- NA_character_
  }

  # If a pinned host is configured, enforce exact match to it
  if (
    is.character(pinned_host) &&
      length(pinned_host) == 1 &&
      !is.na(pinned_host) &&
      nzchar(pinned_host)
  ) {
    ph <- tolower(trimws(pinned_host))
    # Allow specifying either a bare host ("www.googleapis.com") or a full URL
    # ("https://www.googleapis.com"). Normalize to host-only for comparison.
    if (grepl("://", ph, fixed = TRUE)) {
      # Best-effort: extract host from URL; on failure, keep original string
      ph <- try(
        parse_url_host(ph, label = "jwks_host_allow_only"),
        silent = TRUE
      )
      if (inherits(ph, "try-error")) {
        ph <- tolower(trimws(pinned_host))
      }
    }
    ph <- sub("\\.$", "", ph)
    if (!identical(jwks_host, ph)) {
      err_config(c(
        "x" = "jwks_uri host must equal configured jwks_host_allow_only",
        "!" = sprintf("Got '%s' but expected '%s'", jwks_host, ph),
        "i" = "Set `provider@jwks_host_allow_only` to the exact host, or clear it to use issuer-based checks"
      ))
    }
    return(invisible(TRUE))
  }

  # If strict check requested, require same host or subdomain of issuer
  if (isTRUE(check_host)) {
    host_matches <- identical(jwks_host, issuer_host)
    if (!host_matches && nzchar(issuer_host)) {
      host_matches <- endsWith(jwks_host, paste0(".", issuer_host))
    }
    if (!host_matches) {
      err_config(c(
        "x" = "jwks_uri host does not match issuer",
        "!" = sprintf(
          "jwks_uri host '%s' vs issuer '%s'",
          jwks_host,
          issuer_host
        ),
        "i" = paste0(
          "Set `provider@jwks_host_allow_only` to the exact host, or ",
          "set `provider@jwks_host_issuer_match = FALSE` (not recommended)"
        )
      ))
    }
  }
  invisible(TRUE)
}
