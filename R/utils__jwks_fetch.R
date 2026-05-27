# This file contains the helpers that fetch, cache, and policy-check JWKS data
# from a provider
# A JWKS is a provider's published set of public keys used to verify
# signatures
# Used for downloading those keys, caching them, and checking issuer, host,
# and pinning policy before they are trusted

# 1 JWKS fetch and cache helpers -----------------------------------------------

## 1.1 Discovery, caching, and host policy -------------------------------------

#' Internal: resolve the effective discovery issuer-match policy
#'
#' Reads `provider@issuer_match` when a provider is available and otherwise
#' falls back to the package default of `"url"`. Used by JWKS discovery and
#' cache-policy helpers.
#'
#' @param provider Optional [OAuthProvider] used to resolve the issuer-match
#'   policy.
#'
#' @return One of `"url"`, `"host"`, or `"none"`.
#'
#' @keywords internal
#' @noRd
provider_issuer_match <- function(provider = NULL) {
  issuer_match <- "url"
  if (!is.null(provider)) {
    provider_value <- try(provider@issuer_match, silent = TRUE)
    if (
      !inherits(provider_value, "try-error") && is_valid_string(provider_value)
    ) {
      issuer_match <- provider_value
    }
  }

  match.arg(issuer_match, choices = c("url", "host", "none"))
}

#' Internal: resolve the effective explicit provider JWKS URI
#'
#' Reads `provider@jwks_uri` when a provider is available and otherwise returns
#' `NA_character_`. Used by JWKS fetch and cache-key helpers so explicit JWKS
#' overrides stay aligned with runtime network behavior.
#'
#' @param provider Optional [OAuthProvider] used to resolve the explicit JWKS
#'   URI.
#'
#' @return A length-1 character string or `NA_character_`.
#'
#' @keywords internal
#' @noRd
provider_jwks_uri <- function(provider = NULL) {
  if (is.null(provider)) {
    return(NA_character_)
  }

  provider_value <- try(provider@jwks_uri, silent = TRUE)
  if (
    !inherits(provider_value, "try-error") &&
      is_valid_string(provider_value)
  ) {
    return(provider_value)
  }

  NA_character_
}

#' Internal: fetch authorization server metadata for JWKS discovery
#'
#' Tries the RFC 8414 authorization-server metadata location first and then
#' OpenID Connect-compatible well-known locations so generic OAuth/JARM issuers
#' and legacy OIDC deployments can both surface `jwks_uri`.
#'
#' @param issuer Issuer base URL (must include scheme).
#'
#' @return Named list containing parsed metadata and the successful metadata URL.
#'
#' @keywords internal
#' @noRd
fetch_authorization_server_metadata <- function(issuer) {
  build_metadata_url <- function(suffix, legacy_append = FALSE) {
    normalized_issuer <- rtrim_slash(issuer)
    parsed <- httr2::url_parse(normalized_issuer)
    host <- parsed[["hostname"]] %||% err_parse("Invalid issuer host")
    if (grepl(":", host, fixed = TRUE) && !grepl("^\\[", host)) {
      host <- paste0("[", host, "]")
    }

    authority <- paste0(parsed[["scheme"]], "://", host)
    port <- parsed[["port"]] %||% ""
    if (nzchar(port)) {
      authority <- paste0(authority, ":", port)
    }

    path <- parsed[["path"]] %||% ""
    if (identical(path, "/")) {
      path <- ""
    }

    if (isTRUE(legacy_append) || !nzchar(path)) {
      return(normalize_url(paste0(
        normalized_issuer,
        "/.well-known/",
        suffix
      )))
    }

    normalize_url(paste0(authority, "/.well-known/", suffix, path))
  }

  targets <- list(
    list(
      source = "oauth_authorization_server",
      url = build_metadata_url("oauth-authorization-server")
    ),
    list(
      source = "openid_configuration",
      url = build_metadata_url("openid-configuration")
    ),
    list(
      source = "openid_configuration_legacy",
      url = build_metadata_url("openid-configuration", legacy_append = TRUE)
    )
  )
  target_urls <- vapply(targets, function(target) target[["url"]], character(1))
  targets <- targets[!duplicated(target_urls)]

  attempted_urls <- character(0)
  last_response <- NULL
  last_error_message <- NULL
  for (target in targets) {
    attempted_urls <- c(attempted_urls, target[["url"]])

    resp <- try(
      httr2::request(target[["url"]]) |>
        add_req_defaults() |>
        req_no_redirect() |>
        req_with_retry(),
      silent = TRUE
    )
    if (inherits(resp, "try-error")) {
      cnd <- attr(resp, "condition")
      while (!is.null(cnd) && !is.null(cnd[["parent"]])) {
        cnd <- cnd[["parent"]]
      }
      msg <- try(conditionMessage(cnd), silent = TRUE)
      if (!inherits(msg, "try-error")) {
        last_error_message <- as.character(msg)
      }
      next
    }

    redirect_check <- try(
      reject_redirect_response(resp, context = "jwks_discovery"),
      silent = TRUE
    )
    if (inherits(redirect_check, "try-error")) {
      msg <- try(conditionMessage(redirect_check), silent = TRUE)
      if (!inherits(msg, "try-error")) {
        last_error_message <- as.character(msg)
      }
      next
    }

    if (httr2::resp_is_error(resp)) {
      last_response <- resp
      next
    }

    # Once a metadata endpoint returns 2xx, fail closed on body/JSON
    # validation errors instead of falling through to another representation.
    check_resp_body_size(resp, context = "jwks_discovery")
    disc <- .discover_parse_json(resp)
    if (!is.list(disc)) {
      err_parse(c(
        "x" = "Authorization server metadata JSON did not parse to an object"
      ))
    }

    return(list(
      document = disc,
      metadata_url = target[["url"]],
      metadata_source = target[["source"]]
    ))
  }

  if (!is.null(last_response)) {
    err_http(
      c("x" = "Failed to fetch authorization server metadata"),
      last_response,
      context = list(
        issuer = issuer,
        discovery_url = utils::tail(attempted_urls, 1),
        attempted_metadata_urls = attempted_urls
      )
    )
  }

  err_config(
    c(
      "x" = "Failed to fetch authorization server metadata",
      "i" = paste0("Issuer: ", issuer),
      "i" = paste0("Tried: ", paste(attempted_urls, collapse = ", ")),
      if (is_valid_string(last_error_message)) {
        stats::setNames(paste0("Last failure: ", last_error_message), "i")
      }
    ),
    context = list(
      issuer = issuer,
      attempted_metadata_urls = attempted_urls,
      metadata_error = last_error_message
    )
  )
}

#' Internal: Fetch JWKS for issuer (cachem-only)
#'
#' Attempts to resolve an explicit provider `jwks_uri` or download
#' authorization server metadata to locate the JWKS URI, then fetches and
#' caches the key set. Used by ID token, JARM, Request Object, and signed
#' UserInfo verification.
#'
#' Caching details:
#' - Cache entries are keyed by a stable hex sha256 of the issuer URL, combined
#'   with a hex sha256 of the current pinning configuration (sorted pins and
#'   `pin_mode`), discovery issuer policy (`issuer_match`), and host-policy
#'   fields (`jwks_host_issuer_match`, `jwks_host_allow_only`), plus the
#'   effective runtime values of `options(shinyOAuth.allowed_hosts)` and
#'   `options(shinyOAuth.allowed_non_https_hosts)`. This prevents reusing a
#'   JWKS cached under a different discovery, pinning, or host policy.
#' - For additional safety, cached entries are re-validated against the current
#'   `pins`/`pin_mode` before being returned. The JWKS source host is also
#'   re-checked against the current global and provider host-policy, and the
#'   discovery issuer is re-checked against the current issuer-match policy. If
#'   validation fails, the cache entry is evicted and a fresh JWKS is fetched.
#'
#' @param issuer Issuer base URL (must include scheme)
#' @param jwks_cache A cachem cache used for caching (keys by hashed issuer)
#' @param force_refresh Force re-fetching JWKS and overwrite cache
#' @param pins Optional character vector of JWK thumbprints (base64url, RFC 7638)
#'  to pin against
#' @param pin_mode Either "any" (at least one key matches a pin) or "all"
#'  (every RSA/EC/OKP key must match a pin)
#' @param provider Optional [OAuthProvider] used for discovery issuer policy and
#'   JWKS host-policy validation.
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
  issuer_match <- provider_issuer_match(provider)
  jwks_uri_override <- provider_jwks_uri(provider)

  # Extract host-policy from provider (if available)
  host_match <- FALSE
  allow_only <- NA_character_
  if (!is.null(provider)) {
    host_match <- isTRUE(try(provider@jwks_host_issuer_match, silent = TRUE))
    ao <- try(provider@jwks_host_allow_only, silent = TRUE)
    if (!inherits(ao, "try-error")) allow_only <- ao
  }

  # Compute a cache key that incorporates issuer + pinning + provider/global
  # host policy.
  cache_key <- jwks_cache_key(
    issuer,
    pins = pins,
    pin_mode = pin_mode,
    issuer_match = issuer_match,
    jwks_host_issuer_match = host_match,
    jwks_host_allow_only = allow_only,
    jwks_uri_override = jwks_uri_override
  )

  entry <- jwks_cache$get(cache_key, missing = NULL)

  cached_jwks_source_valid <- function(entry) {
    cached_jwks_uri <- entry[["jwks_uri"]] %||% NULL
    if (
      is_valid_string(jwks_uri_override) &&
        !identical(cached_jwks_uri, jwks_uri_override)
    ) {
      return(FALSE)
    }
    if (
      is.character(cached_jwks_uri) &&
        length(cached_jwks_uri) == 1L &&
        !is.na(cached_jwks_uri) &&
        nzchar(cached_jwks_uri)
    ) {
      global_ok <- try(is_ok_host(cached_jwks_uri), silent = TRUE)
      if (!isTRUE(global_ok)) {
        return(FALSE)
      }

      host_ok <- try(
        validate_jwks_host_matches_issuer(
          issuer,
          cached_jwks_uri,
          provider = provider
        ),
        silent = TRUE
      )
      return(!inherits(host_ok, "try-error"))
    }

    cached_jwks_host <- entry[["jwks_uri_host"]] %||% NULL
    if (
      is.character(cached_jwks_host) &&
        length(cached_jwks_host) == 1L &&
        !is.na(cached_jwks_host) &&
        nzchar(cached_jwks_host)
    ) {
      host_ok <- try(
        validate_jwks_host_matches_issuer(
          issuer,
          paste0("https://", cached_jwks_host, "/jwks"),
          provider = provider
        ),
        silent = TRUE
      )
      return(!inherits(host_ok, "try-error"))
    }

    FALSE
  }

  # Rely entirely on cachem's own eviction policy (max_age). If an entry is
  # present, treat it as fresh; if it has been evicted/expired, $get() will
  # return NULL and we'll refetch. We still record fetched_at for diagnostics.
  if (!force_refresh && !is.null(entry) && !is.null(entry[["jwks"]])) {
    # Defense-in-depth: re-validate cached JWKS under current pinning policy
    ok <- try(
      validate_jwks(
        entry[["jwks"]],
        pins = pins,
        pin_mode = pin_mode
      ),
      silent = TRUE
    )
    if (inherits(ok, "try-error")) {
      # Evict incompatible/invalid cached entry and continue to refetch
      if (!is.null(jwks_cache$remove) && is.function(jwks_cache$remove)) {
        jwks_cache$remove(cache_key)
      }
    } else {
      discovery_issuer <- entry[["discovery_issuer"]]
      if (
        is.character(discovery_issuer) &&
          length(discovery_issuer) == 1L &&
          !is.na(discovery_issuer) &&
          nzchar(discovery_issuer)
      ) {
        issuer_ok <- try(
          validate_discovery_issuer(
            issuer_input = issuer,
            issuer_discovered = discovery_issuer,
            issuer_match = issuer_match
          ),
          silent = TRUE
        )
        if (inherits(issuer_ok, "try-error")) {
          if (!is.null(jwks_cache$remove) && is.function(jwks_cache$remove)) {
            jwks_cache$remove(cache_key)
          }
        } else {
          if (isTRUE(cached_jwks_source_valid(entry))) {
            return(entry[["jwks"]])
          }
          if (!is.null(jwks_cache$remove) && is.function(jwks_cache$remove)) {
            jwks_cache$remove(cache_key)
          }
        }
      } else {
        if (isTRUE(cached_jwks_source_valid(entry))) {
          return(entry[["jwks"]])
        }
        if (!is.null(jwks_cache$remove) && is.function(jwks_cache$remove)) {
          jwks_cache$remove(cache_key)
        }
      }
    }
  }

  if (is_valid_string(jwks_uri_override)) {
    discovery_issuer <- issuer
    jwks_uri <- jwks_uri_override
  } else {
    metadata <- fetch_authorization_server_metadata(issuer)
    disc <- metadata[["document"]]
    discovery_issuer <- validate_discovery_issuer(
      issuer_input = issuer,
      issuer_discovered = disc[["issuer"]] %||% NULL,
      issuer_match = issuer_match
    )
    jwks_uri <- disc[["jwks_uri"]] %||%
      {
        err_parse(c("x" = "Authorization server metadata missing jwks_uri"))
      }
  }
  if (!is_ok_host(jwks_uri)) {
    err_config(c(
      "x" = "jwks_uri is not in an allowed host",
      "!" = paste0("Value: ", jwks_uri),
      "i" = "See `?is_ok_host` to configure allowed hosts"
    ))
  }
  validate_jwks_host_matches_issuer(issuer, jwks_uri, provider = provider)
  # Capture the JWKS host so we can store both the original URI and host for
  # defense-in-depth re-validation on cache reads.
  fetched_jwks_host <- try(
    parse_url_host(jwks_uri, "jwks_uri"),
    silent = TRUE
  )
  if (inherits(fetched_jwks_host, "try-error")) {
    fetched_jwks_host <- NULL
  }

  jresp <- httr2::request(jwks_uri) |>
    add_req_defaults() |>
    req_no_redirect() |>
    req_with_retry()
  # Security: reject redirect responses to prevent bypassing host validation
  reject_redirect_response(jresp, context = "jwks_fetch")
  if (httr2::resp_is_error(jresp)) {
    err_http(
      c("x" = "Failed to fetch JWKS"),
      jresp,
      context = list(jwks_uri = jwks_uri)
    )
  }
  check_resp_body_size(jresp, context = "jwks_fetch")
  jwks_body <- httr2::resp_body_string(jresp)
  reject_duplicate_json_object_members(jwks_body, "JWKS JSON")
  jwks <- try(
    jsonlite::fromJSON(jwks_body, simplifyVector = FALSE),
    silent = TRUE
  )
  if (inherits(jwks, "try-error")) {
    err_parse(c("x" = "Failed to parse JWKS JSON"))
  }
  if (is.data.frame(jwks)) {
    jwks <- as.list(jwks)
  }
  if (!is.list(jwks)) {
    err_parse(c("x" = "JWKS JSON did not parse to an object"))
  }
  # Validate structure and (optionally) pin before caching
  validate_jwks(jwks, pins = pins, pin_mode = pin_mode)
  new_entry <- list(
    jwks = jwks,
    fetched_at = now,
    jwks_uri = jwks_uri,
    jwks_uri_host = fetched_jwks_host,
    discovery_issuer = discovery_issuer
  )
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
#' - The key is derived from `jwks_cache_key()` (issuer + pinning + host policy).
#'
#' @param issuer Issuer URL.
#' @param jwks_cache Cache backend used to persist throttle state.
#' @param pins Optional vector of pinned JWK thumbprints.
#' @param pin_mode Pinning mode.
#' @param min_interval Minimum number of seconds between forced refreshes.
#' @param now Current epoch time used for the throttle check.
#' @param issuer_match Discovery issuer-match policy.
#' @param jwks_host_issuer_match Whether the JWKS host must match the issuer
#'   host.
#' @param jwks_host_allow_only Optional explicitly allowed JWKS host.
#' @param jwks_uri_override Optional explicit provider JWKS URI.
#' Used by `fetch_jwks()` to throttle forced JWKS refreshes triggered by new
#' or unexpected key IDs.
#' @return `TRUE` when a forced refresh is allowed and recorded; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
jwks_force_refresh_allowed <- function(
  issuer,
  jwks_cache,
  pins = NULL,
  pin_mode = c("any", "all"),
  min_interval = 30,
  now = as.numeric(Sys.time()),
  issuer_match = "url",
  jwks_host_issuer_match = FALSE,
  jwks_host_allow_only = NA_character_,
  jwks_uri_override = NA_character_
) {
  pin_mode <- match.arg(pin_mode)
  issuer_match <- match.arg(issuer_match, choices = c("url", "host", "none"))
  stopifnot(
    is.numeric(min_interval),
    length(min_interval) == 1L,
    !is.na(min_interval),
    min_interval >= 0
  )

  # Derive a stable, cache-safe key for the throttle entry
  base_key <- jwks_cache_key(
    issuer,
    pins = pins,
    pin_mode = pin_mode,
    issuer_match = issuer_match,
    jwks_host_issuer_match = jwks_host_issuer_match,
    jwks_host_allow_only = jwks_host_allow_only,
    jwks_uri_override = jwks_uri_override
  )
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

#' Internal: Compute cache key for JWKS entries
#'
#' Internal: normalize host allowlist patterns for JWKS cache keys
#'
#' Converts host allowlist vectors into a stable, case-insensitive string so
#' JWKS cache entries stay scoped to the effective runtime host policy.
#' Used by `jwks_cache_key()`.
#'
#' @param patterns Optional character vector of host patterns.
#' @return Single cache-stable string.
#' @keywords internal
#' @noRd
normalize_jwks_cache_host_patterns <- function(patterns) {
  if (is.null(patterns) || length(patterns) == 0) {
    return("")
  }

  normalized <- vapply(
    patterns,
    function(pattern) {
      if (is.null(pattern) || is.na(pattern)) {
        return(NA_character_)
      }
      tolower(host_normalize_pattern(pattern))
    },
    character(1)
  )
  normalized <- normalized[!is.na(normalized) & nzchar(normalized)]
  if (length(normalized) == 0) {
    return("")
  }

  paste(sort(unique(normalized)), collapse = ",")
}

#' Internal: Compute cache key for JWKS entries
#'
#' Uses hex SHA-256 of issuer URL concatenated with hex SHA-256 of the
#' pinning configuration (sorted unique pins + pin_mode), discovery issuer
#' policy, provider host-policy fields (`jwks_host_issuer_match`,
#' `jwks_host_allow_only`), and the effective global host allowlists.
#' Including issuer and host policy prevents cross-policy cache reuse where a
#' relaxed provider or looser runtime allowlist populates the cache and a
#' stricter configuration skips validation on hit.
#' Used by `fetch_jwks()` and `jwks_force_refresh_allowed()` so cached JWKS
#' data and refresh throttles stay scoped to the same issuer and host policy.
#'
#' @param issuer Issuer URL.
#' @param pins Optional vector of pinned JWK thumbprints.
#' @param pin_mode Pinning mode.
#' @param issuer_match Discovery issuer-match policy.
#' @param jwks_host_issuer_match Whether the JWKS host must match the issuer
#'   host.
#' @param jwks_host_allow_only Optional explicitly allowed JWKS host.
#' @param jwks_uri_override Optional explicit provider JWKS URI.
#' @param allowed_hosts Optional effective value of
#'   `options(shinyOAuth.allowed_hosts)`.
#' @param allowed_non_https_hosts Optional effective value of
#'   `options(shinyOAuth.allowed_non_https_hosts)`.
#' @return Cache-safe key string.
#' @keywords internal
#' @noRd
jwks_cache_key <- function(
  issuer,
  pins = NULL,
  pin_mode = c("any", "all"),
  issuer_match = "url",
  jwks_host_issuer_match = FALSE,
  jwks_host_allow_only = NA_character_,
  jwks_uri_override = NA_character_,
  allowed_hosts = getOption("shinyOAuth.allowed_hosts", default = NULL),
  allowed_non_https_hosts = getOption(
    "shinyOAuth.allowed_non_https_hosts",
    default = c("localhost", "127.0.0.1", "::1", "[::1]")
  )
) {
  pin_mode <- match.arg(pin_mode)
  issuer_match <- match.arg(issuer_match, choices = c("url", "host", "none"))
  # Normalize pins: NULL and length-0 both treated as empty
  pins_norm <- character(0)
  if (!is.null(pins) && length(pins) > 0) {
    pins_norm <- sort(unique(as.character(pins)))
  }
  # Normalize host-policy fields
  host_match <- isTRUE(jwks_host_issuer_match)
  allow_only <- ""
  if (
    is.character(jwks_host_allow_only) &&
      length(jwks_host_allow_only) == 1L &&
      !is.na(jwks_host_allow_only) &&
      nzchar(jwks_host_allow_only)
  ) {
    allow_only <- tolower(trimws(jwks_host_allow_only))
  }
  jwks_uri_override_norm <- ""
  if (
    is.character(jwks_uri_override) &&
      length(jwks_uri_override) == 1L &&
      !is.na(jwks_uri_override) &&
      nzchar(jwks_uri_override)
  ) {
    jwks_uri_override_norm <- trimws(jwks_uri_override)
  }
  allowed_hosts_norm <- normalize_jwks_cache_host_patterns(allowed_hosts)
  allowed_non_https_norm <- normalize_jwks_cache_host_patterns(
    allowed_non_https_hosts
  )
  # issuer hash
  ih_raw <- openssl::sha256(charToRaw(as.character(issuer)))
  ih <- paste0(sprintf("%02x", as.integer(ih_raw)), collapse = "")
  # config hash: "<mode>|<pin1>,<pin2>,...|<issuer_match>|<host_match>|<allow_only>|<allowed_hosts>|<allowed_non_https_hosts>"
  cfg_str <- paste0(
    pin_mode,
    "|",
    paste(pins_norm, collapse = ","),
    "|",
    issuer_match,
    "|",
    as.character(host_match),
    "|",
    allow_only,
    "|",
    jwks_uri_override_norm,
    "|",
    allowed_hosts_norm,
    "|",
    allowed_non_https_norm
  )
  ch_raw <- openssl::sha256(charToRaw(cfg_str))
  ch <- paste0(sprintf("%02x", as.integer(ch_raw)), collapse = "")
  # Use an alphanumeric delimiter to satisfy cache key constraints while keeping clarity
  paste0(ih, "x", ch)
}

#' Internal: ensure JWKS host aligns with issuer
#'
#' Validates the discovery `jwks_uri` hostname according to the provider's
#' JWKS policy. When `provider@jwks_host_allow_only` is set, the `jwks_uri` host must equal
#' that value exactly. Otherwise, when `provider@jwks_host_issuer_match` is TRUE, the
#' `jwks_uri` host must match the issuer host exactly. If both
#' settings are absent/disabled, no host relation is enforced. Prefer
#' configuring `jwks_host_allow_only` for providers that serve JWKS from a
#' different host rather than disabling issuer-match entirely.
#' Used by `fetch_jwks()` before network fetches and when revalidating cached
#' JWKS metadata against the current provider policy.
#'
#' @param issuer Issuer URL.
#' @param jwks_uri JWKS URI to validate.
#' @param provider Optional provider object carrying JWKS host policy.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   configuration error.
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

  # If strict check requested, require the exact issuer host.
  if (isTRUE(check_host)) {
    if (!identical(jwks_host, issuer_host)) {
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
