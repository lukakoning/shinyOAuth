#' OAuthProvider S7 class
#'
#' @description
#' S7 class representing an OAuth 2.0 provider configuration.
#' Includes endpoints, OIDC settings, and various security options which
#' govern the OAuth and OIDC flows.
#'
#' This is a low-level constructor intended for advanced use. Most users should
#' prefer the helper constructors [oauth_provider()] for generic OAuth 2.0
#' providers or [oauth_provider_oidc()] / [oauth_provider_oidc_discover()] for
#' OpenID Connect providers. Those helpers enable secure defaults based on the
#' presence of an issuer and available endpoints.
#'
#' @param name Provider name (e.g., "github", "google"). Cosmetic
#' only; used in logging and audit events
#'
#' @param auth_url Authorization endpoint URL
#' @param token_url Token endpoint URL
#' @param userinfo_url User info endpoint URL (optional)
#' @param introspection_url Token introspection endpoint URL (optional; RFC 7662)
#' @param revocation_url Token revocation endpoint URL (optional; RFC 7009)
#'
#' @param issuer OIDC issuer URL (optional; required for ID token validation).
#' This is the base URL that identifies the OpenID Provider (OP). It is used
#' during ID token validation to verify the `iss` claim in the ID
#' token matches the expected issuer. It is also used to fetch the provider's
#' JSON Web Key Set (JWKS) for verifying ID token signatures (typically via
#' the OIDC discovery document located at `/.well-known/openid-configuration`
#' relative to the issuer URL)
#'
#' @param use_nonce Whether to use OIDC nonce. This adds a `nonce` parameter to
#' the authorization request and validates the `nonce` claim in the ID token.
#' This is recommended for OIDC flows to mitigate replay attacks
#' @param use_pkce Whether to use PKCE. This adds a `code_challenge` parameter to
#' the authorization request and requires a `code_verifier` when exchanging
#' the authorization code for tokens. This is prevents authorization code
#' interception attacks
#' @param pkce_method PKCE code challenge method ("S256" or "plain"). "S256" is
#' recommended. "plain" should only be used for non-compliant providers that
#' do not support "S256"
#'
#' @param userinfo_required Whether to fetch userinfo after token exchange.
#' User information will be stored in the `userinfo` field of the returned
#' `OAuthToken` object. This requires a valid `userinfo_url` to be set.
#' If fetching the userinfo fails, the token exchange will fail.
#'
#' For the low-level constructor [oauth_provider()], when not explicitly
#' supplied, this is inferred from the presence of a non-empty `userinfo_url`:
#' if a `userinfo_url` is provided, `userinfo_required` defaults to `TRUE`,
#' otherwise it defaults to `FALSE`. This avoids unexpected validation errors
#' when `userinfo_url` is omitted (since it is optional).
#'
#' @param userinfo_id_token_match Whether to verify that the user ID ("sub") from the ID token
#' matches the user ID extracted from the userinfo response. This requires both
#' `userinfo_required` and `id_token_validation` to be TRUE (and thus a valid `userinfo_url`
#' and `issuer` to be set, plus potentially setting the client's scope to include "openid",
#' so that an ID token is returned). Furthermore, the provider's `userinfo_id_selector` must be configured
#' to extract the user ID from the userinfo response. This check helps ensure
#' the integrity of the user information by confirming that both sources agree on the user's identity.
#'
#' For [oauth_provider()], when not explicitly supplied, this is inferred as
#' `TRUE` only if both `userinfo_required` and `id_token_validation` are `TRUE`;
#' otherwise it defaults to `FALSE`.
#'
#' @param userinfo_id_selector A function that extracts the user ID from the userinfo response.#'
#' Should take a single argument (the userinfo list) and return the user ID
#' as a string.
#'
#' This is used when `userinfo_id_token_match` is TRUE.
#' Optional otherwise; when not supplied, some features (like subject matching)
#' will be unavailable. Helper constructors like [oauth_provider()] and [oauth_provider_oidc()]
#' provide a default selector that extracts the `sub` field.
#'
#' @param id_token_required Whether to require an ID token to be returned
#' during token exchange. If no ID token is returned, the token exchange
#' will fail. This requires the provider to be a valid OpenID Connect
#' provider and may require setting the client's scope to include "openid".
#'
#' Note: At the S7 class level, this defaults to FALSE so that pure OAuth 2.0
#' providers can be configured without OIDC. Helper constructors like
#' [oauth_provider()] and [oauth_provider_oidc()] will enable this when an
#' issuer is supplied or OIDC is explicitly requested.
#'
#' @param id_token_validation Whether to perform ID token validation after token exchange.
#' This requires the provider to be a valid OpenID Connect provider with a configured
#' `issuer` and the token response to include an ID token (may require setting
#' the client's scope to include "openid").
#'
#' Note: At the S7 class level, this defaults to FALSE. Helper constructors like
#' [oauth_provider()] and [oauth_provider_oidc()] turn this on when an issuer
#' is provided or when OIDC is used.
#'
#' @param extra_auth_params Extra parameters for authorization URL
#' @param extra_token_params Extra parameters for token exchange
#' @param extra_token_headers Extra headers for token exchange requests (named character vector)
#'
#' @param token_auth_style How to authenticate when exchanging tokens. One of:
#'   - "header": HTTP Basic (client_secret_basic)
#'   - "body": Form body (client_secret_post)
#'   - "client_secret_jwt": JWT client assertion signed with HMAC using client_secret
#'     (RFC 7523)
#'   - "private_key_jwt": JWT client assertion signed with an asymmetric key
#'     (RFC 7523)
#'
#' @param jwks_cache JWKS cache backend. If not provided, a `cachem::cache_mem(max_age = 3600)`
#'   (1 hour) cache will be created. May be any cachem‑compatible backend, including
#'   [cachem::cache_disk()] for a filesystem cache shared across workers, or a custom
#'   implementation created via [custom_cache()] (e.g., database/Redis backed).
#'
#'   TTL guidance: Choose `max_age` in line with your identity platform’s JWKS rotation
#'   and cache‑control cadence. A range of 15 minutes to 2 hours is typically sensible;
#'   the default is 1 hour. Shorter TTLs adopt new keys faster at the cost of more JWKS
#'   traffic; longer TTLs reduce traffic but may delay new keys slightly. Signature
#'   verification will automatically perform a one‑time JWKS refresh when a new `kid`
#'   appears in an ID token.
#'
#'   Cache keys are internal, hashed by issuer and pinning configuration. Cache values are
#'   lists with elements `jwks` and `fetched_at` (numeric epoch seconds)
#' @param jwks_pins Optional character vector of RFC 7638 JWK thumbprints
#'   (base64url) to pin against. If non-empty, fetched JWKS must contain keys
#'   whose thumbprints match these values depending on `jwks_pin_mode`.
#'   Use to reduce key substitution risks by pre-authorizing expected keys
#' @param jwks_pin_mode Pinning policy when `jwks_pins` is provided. Either
#'   "any" (default; at least one key in JWKS must match) or "all" (every
#'   RSA/EC/OKP public key in JWKS must match one of the configured pins)
#' @param jwks_host_issuer_match When TRUE, enforce that the discovery `jwks_uri` host
#'   matches the issuer host (or a subdomain). Defaults to FALSE at the class
#'   level, but helper constructors for OIDC (e.g., [oauth_provider_oidc()] and
#'   [oauth_provider_oidc_discover()]) enable this by default for safer config.
#'   The generic helper [oauth_provider()] will also automatically set this to
#'   TRUE when an `issuer` is provided and either `id_token_validation` or
#'   `id_token_required` is TRUE (OIDC-like configuration). Set explicitly to
#'   FALSE to opt out. For providers that legitimately publish JWKS on a
#'   different host (e.g., Google), prefer setting `jwks_host_allow_only` to
#'   the exact hostname rather than disabling this check
#' @param jwks_host_allow_only Optional explicit hostname that the jwks_uri must match.
#'   When provided, jwks_uri host must equal this value (exact match). You can
#'   pass either just the host (e.g., "www.googleapis.com") or a full URL; only
#'   the host component will be used. If you need to include a port or an IPv6
#'   literal, pass a full URL (e.g., \verb{https://[::1]:8443}) — the port is ignored
#'   and only the hostname part is used for matching. Takes precedence over
#'   `jwks_host_issuer_match`
#'
#' @param allowed_algs Optional vector of allowed JWT algorithms for ID tokens.
#'   Use to restrict acceptable `alg` values on a per-provider basis. Supported
#'   asymmetric algorithms include `RS256`, `RS384`, `RS512`, `PS256`, `PS384`,
#'   `PS512`, `ES256`, `ES384`, `ES512`, and `EdDSA` (Ed25519/Ed448 via OKP).
#'   Symmetric HMAC algorithms `HS256`, `HS384`, `HS512` are also supported but
#'   require that you supply a `client_secret` and explicitly enable HMAC
#'   verification via the option `options(shinyOAuth.allow_hs = TRUE)`.
#'   Defaults to `c("RS256","RS384","RS512","PS256","PS384","PS512",
#'   "ES256","ES384","ES512","EdDSA")`, which intentionally excludes HS*.
#'   Only include `HS*` if you are certain the `client_secret` is stored strictly
#'   server-side and is never shipped to, or derivable by, the browser or other
#'   untrusted environments. Prefer rotating secrets regularly when enabling this.
#' @param allowed_token_types Character vector of acceptable OAuth token types
#'   returned by the token endpoint (case-insensitive). When non-empty, the
#'   token response MUST include `token_type` and it must be one of the allowed
#'   values; otherwise the flow fails fast with a `shinyOAuth_token_error`.
#'   When empty, no check is performed and `token_type` may be omitted by the
#'   provider. The [oauth_provider()] helper defaults to `c("Bearer")` for all
#'   providers because the package only supports Bearer tokens (i.e.,
#'   [client_bearer_req()] sends `Authorization: Bearer`). This ensures that if
#'   a provider returns a non-Bearer token type (e.g., DPoP, MAC), the flow
#'   fails fast rather than misusing the token. Set `allowed_token_types =
#'   character()` explicitly to opt out of enforcement.
#'
#' @param leeway Clock skew leeway (seconds) applied to ID token `exp`/`iat`/`nbf` checks
#'   and state payload `issued_at` future check. Default 30. Can be globally
#'   overridden via option `shinyOAuth.leeway`
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
OAuthProvider <- S7::new_class(
  "OAuthProvider",
  package = "shinyOAuth",
  properties = list(
    name = S7::class_character,
    auth_url = S7::class_character,
    token_url = S7::class_character,
    userinfo_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    introspection_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    revocation_url = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    issuer = S7::new_property(S7::class_character, default = NA_character_),
    use_nonce = S7::new_property(S7::class_logical, default = FALSE),
    use_pkce = S7::new_property(S7::class_logical, default = TRUE),
    pkce_method = S7::new_property(S7::class_character, default = "S256"),
    userinfo_required = S7::new_property(S7::class_logical, default = FALSE),
    userinfo_id_selector = S7::new_property(
      S7::class_any,
      default = quote(function(userinfo) userinfo$sub)
    ),
    userinfo_id_token_match = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    id_token_required = S7::new_property(S7::class_logical, default = FALSE),
    id_token_validation = S7::new_property(S7::class_logical, default = FALSE),
    extra_auth_params = S7::class_list,
    extra_token_params = S7::class_list,
    extra_token_headers = S7::new_property(
      S7::class_character,
      default = character()
    ),
    token_auth_style = S7::new_property(
      S7::class_character,
      default = "header"
    ),
    jwks_cache = S7::new_property(
      S7::class_any,
      default = quote(cachem::cache_mem(max_age = 3600))
    ),
    jwks_pins = S7::new_property(S7::class_character, default = character()),
    jwks_pin_mode = S7::new_property(S7::class_character, default = "any"),
    jwks_host_issuer_match = S7::new_property(
      S7::class_logical,
      default = FALSE
    ),
    # Use NA_character_ instead of NULL so the property always respects
    # the declared character type; constructors normalize to a hostname or NA
    jwks_host_allow_only = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    allowed_algs = S7::new_property(
      S7::class_character,
      default = c(
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA"
      )
    ),
    allowed_token_types = S7::new_property(
      S7::class_character,
      default = c("Bearer")
    ),
    leeway = S7::new_property(
      S7::class_numeric,
      default = quote(getOption(
        "shinyOAuth.leeway",
        30
      ))
    )
  ),
  validator = function(self) {
    # Small helper to validate a single field
    .check_host_field <- function(value, name, required = FALSE) {
      if (required && !is_valid_string(value)) {
        return(sprintf(
          "OAuthProvider: %s is required and must be a non-empty string",
          name
        ))
      }
      if (!is_valid_string(value)) {
        return(NULL)
      }

      parsed <- try(httr2::url_parse(value), silent = TRUE)
      if (
        inherits(parsed, "try-error") ||
          !nzchar((parsed$scheme %||% "")) ||
          !nzchar((parsed$hostname %||% ""))
      ) {
        return(sprintf(
          "OAuthProvider: %s must be an absolute URL (including scheme and hostname)",
          name
        ))
      }

      if (!is_ok_host(value)) {
        return(sprintf(
          "OAuthProvider: %s provided but not accepted as a host (see `?is_ok_host` for details)",
          name
        ))
      }
      NULL
    }

    # Reuse for all properties (required vs optional mirrors your S7 defs)
    fields <- list(
      auth_url = list(val = self@auth_url, required = TRUE),
      token_url = list(val = self@token_url, required = TRUE),
      userinfo_url = list(val = self@userinfo_url, required = FALSE),
      introspection_url = list(val = self@introspection_url, required = FALSE),
      revocation_url = list(val = self@revocation_url, required = FALSE),
      issuer = list(val = self@issuer, required = FALSE)
    )
    for (nm in names(fields)) {
      f <- fields[[nm]]
      msg <- .check_host_field(f$val, nm, f$required)
      if (!is.null(msg)) {
        return(msg)
      } # early exit on first violation
    }

    # OIDC issuer identifiers must not contain query or fragment components
    if (is_valid_string(self@issuer)) {
      parsed_issuer <- try(httr2::url_parse(self@issuer), silent = TRUE)
      if (
        !inherits(parsed_issuer, "try-error") &&
          (length(parsed_issuer$query) > 0L ||
            nzchar(parsed_issuer$fragment %||% ""))
      ) {
        return(
          "OAuthProvider: issuer must not contain query or fragment components"
        )
      }
    }

    # Validate extra_token_headers: must be named character vector of length n
    # with all non-empty names and scalar (length-1) character values.
    if (length(self@extra_token_headers) > 0) {
      eth <- self@extra_token_headers
      # Coerce to character explicitly; disallow non-character types
      if (!is.character(eth)) {
        return(
          "OAuthProvider: extra_token_headers must be a named character vector"
        )
      }
      nms <- names(eth)
      if (is.null(nms) || !all(nzchar(nms))) {
        return(
          "OAuthProvider: extra_token_headers must have non-empty names for all headers"
        )
      }

      # Block reserved headers that could break/override client auth in surprising
      # ways during token exchange. Header names are case-insensitive in HTTP.
      # Users can unblock specific headers via shinyOAuth.unblock_token_headers.
      default_reserved_headers <- c("authorization", "cookie")
      unblocked <- tolower(getOption(
        "shinyOAuth.unblock_token_headers",
        character()
      ))
      reserved_header_names <- setdiff(default_reserved_headers, unblocked)
      bad_headers <- intersect(tolower(trimws(nms)), reserved_header_names)
      if (length(bad_headers) > 0) {
        return(sprintf(
          paste0(
            "OAuthProvider: extra_token_headers must not contain reserved headers: %s. ",
            "To unblock, set options(shinyOAuth.unblock_token_headers = c(...))"
          ),
          paste(sQuote(bad_headers), collapse = ", ")
        ))
      }

      # Ensure each entry is a single string (not vector)
      bad_len <- lengths(eth) != 1L
      if (any(bad_len)) {
        return("OAuthProvider: each extra_token_headers value must be length 1")
      }
      # Disallow NA values
      if (any(is.na(eth) | !nzchar(eth))) {
        return(
          "OAuthProvider: extra_token_headers values must be non-empty strings"
        )
      }
    }

    # Validate extra_auth_params: must be a named list if non-empty.
    # Unnamed elements would cause httr2::url_modify() to fail with an unhelpful
    # error, so we catch this early with a clearer message.
    if (length(self@extra_auth_params) > 0) {
      nms <- names(self@extra_auth_params)
      if (is.null(nms) || !all(nzchar(nms))) {
        return(
          "OAuthProvider: extra_auth_params must be a named list (all elements must have names)"
        )
      }
    }

    # Validate extra_auth_params: block reserved keys that could desync state,
    # bypass PKCE, or corrupt the authorization request.
    # These fields are managed internally by shinyOAuth and must not be overridden.
    # Users can unblock specific keys via shinyOAuth.unblock_auth_params.
    default_reserved_auth_keys <- c(
      "response_type",
      "client_id",
      "redirect_uri",
      "state",
      "scope",
      "code_challenge",
      "code_challenge_method",
      "nonce"
    )
    unblocked_auth <- getOption("shinyOAuth.unblock_auth_params", character())
    reserved_auth_keys <- setdiff(default_reserved_auth_keys, unblocked_auth)
    if (length(self@extra_auth_params) > 0) {
      nms <- names(self@extra_auth_params)
      bad <- intersect(nms, reserved_auth_keys)
      if (length(bad) > 0) {
        return(sprintf(
          paste0(
            "OAuthProvider: extra_auth_params must not contain reserved keys ",
            "managed by shinyOAuth: %s. ",
            "To unblock, set options(shinyOAuth.unblock_auth_params = c(...))"
          ),
          paste(sQuote(bad), collapse = ", ")
        ))
      }
    }

    # Validate extra_token_params: must be a named list if non-empty.
    # Unnamed elements would cause httr2::req_body_form() to fail with an
    # unhelpful error, so we catch this early with a clearer message.
    if (length(self@extra_token_params) > 0) {
      nms <- names(self@extra_token_params)
      if (is.null(nms) || !all(nzchar(nms))) {
        return(
          "OAuthProvider: extra_token_params must be a named list (all elements must have names)"
        )
      }
    }

    # Validate extra_token_params: block reserved keys that could corrupt the
    # token request, bypass PKCE verification, or interfere with client auth.
    # Users can unblock specific keys via shinyOAuth.unblock_token_params.
    default_reserved_token_keys <- c(
      "grant_type",
      "code",
      "redirect_uri",
      "code_verifier",
      "client_id",
      "client_secret",
      "client_assertion",
      "client_assertion_type"
    )
    unblocked_token <- getOption("shinyOAuth.unblock_token_params", character())
    reserved_token_keys <- setdiff(default_reserved_token_keys, unblocked_token)
    if (length(self@extra_token_params) > 0) {
      nms <- names(self@extra_token_params)
      bad <- intersect(nms, reserved_token_keys)
      if (length(bad) > 0) {
        return(sprintf(
          paste0(
            "OAuthProvider: extra_token_params must not contain reserved keys ",
            "managed by shinyOAuth: %s. ",
            "To unblock, set options(shinyOAuth.unblock_token_params = c(...))"
          ),
          paste(sQuote(bad), collapse = ", ")
        ))
      }
    }

    # token_auth_style must be one of:
    # - "header" (client_secret_basic)
    # - "body" (client_secret_post)
    # - "client_secret_jwt" (RFC 7523; HMAC-signed client assertion)
    # - "private_key_jwt" (RFC 7523; asymmetric-signed client assertion)
    if (
      !isTRUE(
        self@token_auth_style %in%
          c(
            "header",
            "body",
            "client_secret_jwt",
            "private_key_jwt"
          )
      )
    ) {
      return(paste0(
        "OAuthProvider: token_auth_style must be one of 'header', 'body', ",
        "'client_secret_jwt', or 'private_key_jwt'"
      ))
    }

    # pkce_method must be one of S256 (recommended) or plain (legacy/compat)
    if (!is.null(self@pkce_method)) {
      if (!isTRUE(self@pkce_method %in% c("S256", "plain"))) {
        return("OAuthProvider: pkce_method must be 'S256' or 'plain'")
      }
    }

    # Validate jwks_cache
    # Duck-type: require $get and $set functions; $remove/$info are optional
    has_get <- !is.null(self@jwks_cache$get) &&
      is.function(self@jwks_cache$get)
    has_set <- !is.null(self@jwks_cache$set) &&
      is.function(self@jwks_cache$set)
    if (!isTRUE(has_get && has_set)) {
      return(
        paste(
          "OAuthProvider: jwks_cache must provide $get(key, missing=NULL) and",
          "$set(key, value) methods"
        )
      )
    }
    # Probe/inspect signatures for robustness
    # - $get must accept a named `missing` argument (or `...`); probe-call
    jget_probe <- try(
      self@jwks_cache$get(
        key = "__jwks_sig_probe__",
        missing = NULL
      ),
      silent = TRUE
    )
    if (inherits(jget_probe, "try-error")) {
      return(paste0(
        "OAuthProvider: jwks_cache$get must accept argument 'missing' (expected signature get(key, missing = NULL)); got error: ",
        as.character(jget_probe)
      ))
    }
    # - $set must accept (key, value) or have ...
    jset_formals <- try(formals(self@jwks_cache$set), silent = TRUE)
    jset_args <- if (!inherits(jset_formals, "try-error")) {
      names(jset_formals)
    } else {
      character()
    }
    if (
      !("..." %in%
        jset_args ||
        ("key" %in% jset_args && "value" %in% jset_args))
    ) {
      return("OAuthProvider: jwks_cache$set must accept (key, value)")
    }
    # Optional $remove: if present, require at least one parameter or ...
    if (
      !is.null(self@jwks_cache$remove) && is.function(self@jwks_cache$remove)
    ) {
      jrm_formals <- try(formals(self@jwks_cache$remove), silent = TRUE)
      jrm_args <- if (!inherits(jrm_formals, "try-error")) {
        names(jrm_formals)
      } else {
        character()
      }
      if (!("..." %in% jrm_args || length(jrm_args) >= 1L)) {
        return(
          "OAuthProvider: jwks_cache$remove must accept (key) when provided"
        )
      }
    }

    # Validate jwks_pin_mode
    if (!isTRUE(self@jwks_pin_mode %in% c("any", "all"))) {
      return("OAuthProvider: jwks_pin_mode must be 'any' or 'all'")
    }
    # jwks_pins should look like base64url strings if provided
    if (length(self@jwks_pins) > 0) {
      ok <- vapply(
        self@jwks_pins,
        function(x) {
          is.character(x) && length(x) == 1 && grepl("^[A-Za-z0-9_-]+$", x)
        },
        logical(1)
      )
      if (!all(ok)) {
        return("OAuthProvider: jwks_pins must be base64url strings")
      }
    }

    # Validate allowed_algs: must be from supported set
    if (length(self@allowed_algs) > 0) {
      supported <- c(
        # RSA PKCS#1 v1.5
        "RS256",
        "RS384",
        "RS512",
        # RSA-PSS
        "PS256",
        "PS384",
        "PS512",
        # ECDSA
        "ES256",
        "ES384",
        "ES512",
        # EdDSA (OKP)
        "EDDSA",
        # HMAC
        "HS256",
        "HS384",
        "HS512"
      )
      aa <- toupper(self@allowed_algs)
      bad <- setdiff(aa, supported)
      if (length(bad) > 0) {
        return(paste0(
          "OAuthProvider: allowed_algs contains unsupported entries: ",
          paste(bad, collapse = ", ")
        ))
      }

      # Fail fast: HS* algs are supported but gated behind an opt-in option.
      # Without the option, validation would fail later at ID token validation
      # time, which is confusing for users who configured allowed_algs.
      if (any(aa %in% c("HS256", "HS384", "HS512"))) {
        allow_hs <- isTRUE(getOption("shinyOAuth.allow_hs", FALSE))
        if (!allow_hs) {
          return(
            "OAuthProvider: allowed_algs includes HS* but `options(shinyOAuth.allow_hs = TRUE)` is not enabled"
          )
        }
      }
    }

    # Fail fast: cannot enable nonce without a configured issuer
    if (isTRUE(self@use_nonce)) {
      if (!is_valid_string(self@issuer)) {
        return(
          "OAuthProvider: use_nonce = TRUE requires a non-empty provider issuer"
        )
      }
    }

    # Validate allowed_token_types shape
    if (length(self@allowed_token_types) > 0) {
      att <- self@allowed_token_types
      if (!is.character(att)) {
        return("OAuthProvider: allowed_token_types must be a character vector")
      }
      # Disallow empty strings/NA
      if (any(is.na(att) | !nzchar(att))) {
        return(
          "OAuthProvider: allowed_token_types must contain only non-empty strings"
        )
      }
    }

    # Fail fast: cannot enable ID token validation without a configured issuer
    if (isTRUE(self@id_token_validation)) {
      if (!is_valid_string(self@issuer)) {
        return(
          "OAuthProvider: id_token_validation = TRUE requires a non-empty provider issuer"
        )
      }
    }

    # Fail fast: userinfo_required implies a configured/valid userinfo_url
    if (isTRUE(self@userinfo_required)) {
      if (!is_valid_string(self@userinfo_url)) {
        return(
          "OAuthProvider: userinfo_required = TRUE requires a non-empty userinfo_url"
        )
      }
      if (!is_ok_host(self@userinfo_url)) {
        return(
          "OAuthProvider: userinfo_url provided but not accepted as a host (see `?is_ok_host`)"
        )
      }
    }

    # Fail fast: subject matching requires userinfo + id token validation
    if (isTRUE(self@userinfo_id_token_match)) {
      if (!isTRUE(self@userinfo_required)) {
        return(
          "OAuthProvider: userinfo_id_token_match = TRUE requires userinfo_required = TRUE"
        )
      }
      if (!isTRUE(self@id_token_validation)) {
        return(
          "OAuthProvider: userinfo_id_token_match = TRUE requires id_token_validation = TRUE"
        )
      }
      if (
        !is_valid_string(self@userinfo_url) || !is_ok_host(self@userinfo_url)
      ) {
        return(
          "OAuthProvider: userinfo_id_token_match = TRUE requires a valid userinfo_url"
        )
      }
      if (
        is.null(self@userinfo_id_selector) ||
          !is.function(self@userinfo_id_selector)
      ) {
        return(
          "OAuthProvider: userinfo_id_token_match = TRUE requires a configured userinfo_id_selector function"
        )
      }
    }

    # Validate leeway
    if (
      !is.numeric(self@leeway) ||
        length(self@leeway) != 1 ||
        is.na(self@leeway) ||
        self@leeway < 0
    ) {
      return(
        "OAuthProvider: leeway must be a single non-negative numeric value"
      )
    }

    # Validate jwks_host_allow_only (if provided): allow either bare host or URL; store as-is
    if (is_valid_string(self@jwks_host_allow_only)) {
      val <- trimws(self@jwks_host_allow_only)
      # If URL-like, extract host; else validate as hostname characters
      host_only <- val
      if (grepl("^https?://", tolower(val))) {
        # Safe parse; raise a clear error on failure
        host_only <- try(
          parse_url_host(val, "jwks_host_allow_only"),
          silent = TRUE
        )
        if (inherits(host_only, "try-error")) {
          return("OAuthProvider: jwks_host_allow_only URL could not be parsed")
        }
      } else {
        # Validate host characters roughly: letters, digits, hyphen, dot.
        # Note: bare-host form does not support ports or IPv6 literals; use URL form instead.
        if (!grepl("^[A-Za-z0-9.-]+$", host_only)) {
          return(
            "OAuthProvider: jwks_host_allow_only must be a hostname or a URL containing a hostname"
          )
        }
        # Trim trailing dot if present
        host_only <- sub("\\.$", "", tolower(host_only))
      }
      # No additional assignment here; we keep the original value so constructors can normalize if desired
    }

    NULL
  }
)

#' Create generic [OAuthProvider]
#'
#' Helper function to create an [OAuthProvider] object.
#' This function provides sensible defaults and infers
#' some settings based on the provided parameters.
#'
#' @inheritParams OAuthProvider
#'
#' @return [OAuthProvider] object
#'
#' @example inst/examples/oauth_provider.R
#'
#' @export
oauth_provider <- function(
  name,
  auth_url,
  token_url,
  userinfo_url = NA_character_,
  introspection_url = NA_character_,
  revocation_url = NA_character_,
  issuer = NA_character_,
  use_nonce = NULL,
  use_pkce = TRUE,
  pkce_method = "S256",
  userinfo_required = NULL,
  userinfo_id_token_match = NULL,
  userinfo_id_selector = function(userinfo) userinfo$sub,
  id_token_required = NULL,
  id_token_validation = NULL,
  extra_auth_params = list(),
  extra_token_params = list(),
  extra_token_headers = character(),
  token_auth_style = "header",
  jwks_cache = NULL,
  jwks_pins = character(),
  jwks_pin_mode = "any",
  jwks_host_issuer_match = NULL,
  jwks_host_allow_only = NULL,
  allowed_algs = c(
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA"
  ),
  allowed_token_types = c("Bearer"),
  leeway = getOption("shinyOAuth.leeway", 30)
) {
  # Use shared internal helper to normalize only the path component
  auth_url <- normalize_url(auth_url)
  token_url <- normalize_url(token_url)
  userinfo_url <- normalize_url(userinfo_url)
  introspection_url <- normalize_url(introspection_url)
  revocation_url <- normalize_url(revocation_url)

  if (is.null(jwks_cache)) {
    jwks_cache <- cachem::cache_mem(max_age = 3600)
  }

  # Normalize pkce_method (be tolerant of NULL/NA and case)
  if (is.null(pkce_method) || is.na(pkce_method)) {
    pkce_method <- "S256"
  }
  pkce_method <- if (tolower(pkce_method) == "plain") "plain" else "S256"

  # Normalize and validate allowed_algs
  if (is.null(allowed_algs)) {
    allowed_algs <- c(
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
      "ES256",
      "ES384",
      "ES512",
      "EdDSA"
    )
  }
  allowed_algs <- toupper(allowed_algs)

  # Normalize jwks_host_allow_only: allow either hostname or full URL; store hostname only
  if (is_valid_string(jwks_host_allow_only)) {
    jh <- trimws(jwks_host_allow_only)
    if (grepl("^https?://", tolower(jh))) {
      jh <- parse_url_host(jh, "jwks_host_allow_only")
    } else {
      jh <- tolower(sub("\\.$", "", jh))
    }
    jwks_host_allow_only <- jh
  } else {
    jwks_host_allow_only <- NA_character_
  }

  # If issuer is present, then set sensible defaults for nonce/id_token flags
  has_issuer <- is_valid_string(issuer)
  if (is.null(use_nonce)) {
    use_nonce <- if (has_issuer) TRUE else FALSE
  }
  if (is.null(id_token_required)) {
    id_token_required <- if (has_issuer) TRUE else FALSE
  }
  if (is.null(id_token_validation)) {
    id_token_validation <- if (has_issuer) TRUE else FALSE
  }

  # Auto-enable JWKS issuer-host match for OIDC-like configurations unless explicitly set
  if (is.null(jwks_host_issuer_match)) {
    jwks_host_issuer_match <- has_issuer &&
      (isTRUE(id_token_validation) || isTRUE(id_token_required))
  }

  # Default to Bearer for all providers. The package only supports Bearer tokens
  # (client_bearer_req sends Authorization: Bearer). If a provider returns a
  # non-Bearer token_type (e.g., DPoP, MAC), we fail fast rather than misusing
  # it. Set allowed_token_types = character() to opt out of enforcement.
  if (is.null(allowed_token_types)) {
    allowed_token_types <- c("Bearer")
  }

  # Gentle host configuration reminder:
  # In non-interactive (server) sessions, if no global host allowlist is set
  # and the provider is configured with OIDC features (issuer present or
  # ID token validation/requirement enabled), emit a once-per-session warning
  # pointing operators to host hardening guidance. Suppressed during tests.
  if (
    !.is_interactive() &&
      !.is_test() &&
      (has_issuer || isTRUE(id_token_required) || isTRUE(id_token_validation))
  ) {
    allowed_hosts_opt <- getOption("shinyOAuth.allowed_hosts", NULL)
    if (is.null(allowed_hosts_opt) || length(allowed_hosts_opt) == 0) {
      rlang::warn(
        c(
          "[{.pkg shinyOAuth}] - {.strong Configure allowed hosts for production}",
          "!" = paste0(
            "No host allowlist configured via ",
            "{.code options(shinyOAuth.allowed_hosts = c(\".example.com\", \"api.example.com\"))}."
          ),
          "i" = "Restricting hosts hardens redirect and API endpoint validation.",
          "i" = "See {.code ?is_ok_host} for policy details and review the 'authentication-flow' vignette"
        ),
        .frequency = "once",
        .frequency_id = "allowed_hosts_config_reminder"
      )
    }
  }

  # Infer sensible defaults for userinfo-related flags when not provided
  has_ui <- is_valid_string(userinfo_url) && is_ok_host(userinfo_url)
  if (is.null(userinfo_required)) {
    userinfo_required <- isTRUE(has_ui)
  }
  if (is.null(userinfo_id_token_match)) {
    userinfo_id_token_match <- isTRUE(userinfo_required) &&
      isTRUE(id_token_validation)
  }

  OAuthProvider(
    name = name,
    auth_url = auth_url,
    token_url = token_url,
    userinfo_url = userinfo_url,
    introspection_url = introspection_url,
    revocation_url = revocation_url,
    issuer = issuer,
    use_nonce = use_nonce,
    use_pkce = use_pkce,
    pkce_method = pkce_method,
    userinfo_required = userinfo_required,
    id_token_required = id_token_required,
    id_token_validation = id_token_validation,
    userinfo_id_token_match = userinfo_id_token_match,
    userinfo_id_selector = userinfo_id_selector,
    extra_auth_params = extra_auth_params,
    extra_token_params = extra_token_params,
    extra_token_headers = extra_token_headers,
    token_auth_style = token_auth_style,
    jwks_cache = jwks_cache,
    jwks_pins = jwks_pins,
    jwks_pin_mode = jwks_pin_mode,
    jwks_host_issuer_match = isTRUE(jwks_host_issuer_match),
    jwks_host_allow_only = jwks_host_allow_only,
    allowed_algs = allowed_algs,
    allowed_token_types = allowed_token_types,
    leeway = leeway
  )
}
