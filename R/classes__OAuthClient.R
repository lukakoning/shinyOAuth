#' OAuthClient S7 class
#'
#' @description
#' S7 class representing an OAuth 2.0 client configuration, including a provider,
#' client credentials, redirect URI, requested scopes, and state management.
#'
#' This is a low-level constructor intended for advanced use. Most users should
#' prefer the helper constructor [oauth_client()].
#'
#' @param provider [OAuthProvider] object
#'
#' @param client_id OAuth client ID
#' @param client_secret OAuth client secret.
#'
#'   Validation rules:
#'   - Required (non-empty) when the provider authenticates the client with
#'     HTTP Basic auth at the token endpoint (`token_auth_style = "header"`,
#'     also known as `client_secret_basic`).
#'   - Optional for public PKCE-only clients when the provider is configured
#'     with `use_pkce = TRUE` and uses form-body client authentication at the
#'     token endpoint (`token_auth_style = "body"`, also known as
#'     `client_secret_post`). In this case, the secret is omitted from token
#'     requests.
#'
#'   Note: If your provider issues HS256 ID tokens and `id_token_validation` is
#'   enabled, a non-empty `client_secret` is required for signature validation.
#'
#' @param client_private_key Optional private key for `private_key_jwt` client authentication
#'   at the token endpoint. Can be an `openssl::key` or a PEM string containing a
#'   private key. Required when the provider's `token_auth_style = 'private_key_jwt'`.
#'   Ignored for other auth styles.
#'
#' @param client_private_key_kid Optional key identifier (kid) to include in the JWT header
#'   for `private_key_jwt` assertions. Useful when the authorization server uses kid to
#'   select the correct verification key.
#'
#' @param client_assertion_alg Optional JWT signing algorithm to use for client assertions.
#'   When omitted, defaults to `HS256` for `client_secret_jwt`. For `private_key_jwt`, a
#'   compatible default is selected based on the private key type/curve (e.g., `RS256` for RSA,
#'   `ES256`/`ES384`/`ES512` for EC P-256/384/521, or `EdDSA` for Ed25519/Ed448). If an explicit
#'   value is provided but incompatible with the key, validation fails early with a configuration
#'   error.
#'   Supported values are `HS256`, `HS384`, `HS512` for client_secret_jwt and asymmetric algorithms
#'   supported by `jose::jwt_encode_sig` (e.g., `RS256`, `PS256`, `ES256`, `EdDSA`) for private keys.
#'
#' @param client_assertion_audience Optional override for the `aud` claim used when building
#'   JWT client assertions (`client_secret_jwt` / `private_key_jwt`). By default, shinyOAuth
#'   uses the exact token endpoint request URL. Some identity providers require a different
#'   audience value; set this to the exact value your IdP expects.
#'
#' @param redirect_uri Redirect URI registered with provider
#'
#' @param scopes Vector of scopes to request
#'
#' @param state_store State storage backend. Defaults to `cachem::cache_mem(max_age = 300)`.
#'    Alternative backends could include `cachem::cache_disk()` or a custom
#'    implementation (which you can create with [custom_cache()]. The backend
#'    must implement cachem-like methods `$get(key, missing)`, `$set(key, value)`,
#'    and `$remove(key)`; `$info()` is optional.
#'
#'    Trade-offs: `cache_mem` is in-memory and thus scoped to a single R process
#'    (good default for a single Shiny process). `cache_disk` persists to disk
#'    and can be shared across multiple R processes (useful for multi-process
#'    deployments or when Shiny workers aren't sticky). A [custom_cache()]
#'    backend could use a database or external store (e.g., Redis, Memcached).
#'    See also `vignette("usage", package = "shinyOAuth")`.
#'
#'    The client automatically generates, persists (in `state_store`), and
#'    validates the OAuth `state` parameter (and OIDC `nonce` when applicable)
#'    during the authorization code flow
#'
#' @param claims OIDC claims request parameter (OIDC Core §5.5). Allows
#'   requesting specific claims from the UserInfo Endpoint and/or in the ID
#'   Token. Can be:
#'   - `NULL` (default): no claims parameter is sent
#'   - A list: automatically JSON-encoded (via [jsonlite::toJSON()] with
#'     `auto_unbox = TRUE`) and URL-encoded into the authorization request.
#'     The list should have top-level members `userinfo` and/or `id_token`,
#'     each containing named lists of claims.
#'     Use `NULL` to request a claim without parameters (per spec).
#'     Example: `list(userinfo = list(email = NULL, given_name = list(essential = TRUE)), id_token = list(auth_time = list(essential = TRUE)))`
#'
#'     Note on single-element arrays: because `auto_unbox = TRUE` is used,
#'     single-element R vectors are serialized as JSON scalars, not arrays.
#'     The OIDC spec defines `values` as an array. To force array encoding
#'     for a single-element vector, wrap it in [I()], e.g.,
#'     `acr = list(values = I("urn:mace:incommon:iap:silver"))` produces
#'     `{"values":["urn:mace:incommon:iap:silver"]}`. Multi-element vectors
#'     are always encoded as arrays.
#'   - A character string: pre-encoded JSON string (for advanced use). Must
#'     be valid JSON. Use this when you need full control over JSON encoding.
#'   Note: The `claims` parameter is OPTIONAL per OIDC Core §5.5. Not all
#'   providers support it; consult your provider's documentation.
#'
#' @param state_payload_max_age Positive number of seconds. Maximum allowed age
#'   for the decrypted state payload's `issued_at` timestamp during callback
#'   validation.
#'
#'   This value is an independent freshness backstop against replay attacks on
#'   the encrypted `state` payload. It is intentionally decoupled from
#'   `state_store` TTL (which controls how long the single-use state entry can
#'   exist in the server-side cache, and also drives browser cookie max-age in
#'   [oauth_module_server()]).
#'
#'   Default is 300 seconds.
#'
#' @param state_entropy Integer. The length (in characters) of the randomly
#'   generated state parameter. Higher values provide more entropy and better
#'   security against CSRF attacks. Must be between 22 and 128 (to align with
#'   `validate_state()`'s default minimum which targets ~128 bits for base64url‑like
#'   strings). Default is 64, which provides approximately 384 bits of entropy
#'
#' @param state_key Optional per-client secret used as the state sealing key
#'   for AES-GCM AEAD (authenticated encryption) of the state payload that
#'   travels via the `state` query parameter. This provides confidentiality
#'   and integrity (via authentication tag) for the embedded data used during
#'   callback verification. If you omit this argument, a random value is
#'   generated via `random_urlsafe(128)`. This key is distinct from the
#'   OAuth `client_secret` and may be used with public clients.
#'
#'   Type: character string (>= 32 bytes when encoded) or raw vector
#'   (>= 32 bytes). Raw keys enable direct use of high-entropy secrets from
#'   external stores. Both forms are normalized internally by cryptographic
#'   helpers.
#'
#'   Multi-process deployments: if your app runs with multiple R workers or behind
#'   a non-sticky load balancer, you must configure a shared `state_store` and the
#'   same `state_key` across all workers. Otherwise callbacks that land on a
#'   different worker will be unable to decrypt/validate the state envelope and
#'   authentication will fail. In such environments, do not rely on the random
#'   per-process default: provide an explicit, high-entropy key (for example via
#'   a secret store or environment variable). Prefer values with substantial
#'   entropy (e.g., 64–128 base64url characters or a raw 32+ byte key). Avoid
#'   human‑memorable passphrases. See also `vignette("usage", package = "shinyOAuth")`.
#'
#' @param scope_validation Controls how scope discrepancies are handled when
#'   the authorization server grants fewer scopes than requested. RFC 6749
#'   Section 3.3 permits servers to issue tokens with reduced scope.
#'
#'   - `"strict"` (default): Throws an error if any requested scope is missing
#'     from the granted scopes.
#'   - `"warn"`: Emits a warning but continues authentication if scopes are
#'     missing.
#'   - `"none"`: Skips scope validation entirely.
#'
#' @param claims_validation Controls validation of essential claims requested
#'   via the `claims` parameter (OIDC Core §5.5). When `claims` includes
#'   entries with `essential = TRUE` for `id_token` or `userinfo`, this setting
#'   determines what happens if those essential claims are missing from the
#'   returned ID token or userinfo response.
#'
#'   - `"none"` (default): Skips claims validation entirely. This is the
#'     default because providers are expected to fulfil essential claims
#'     requests or return an error.
#'   - `"warn"`: Emits a warning but continues authentication if essential
#'     claims are missing.
#'   - `"strict"`: Throws an error if any requested essential claims are
#'     missing from the response.
#'
#' @param required_acr_values Optional character vector of acceptable
#'   Authentication Context Class Reference values (OIDC Core §2, §3.1.2.1).
#'   When non-empty, the ID token returned by the provider must contain an
#'   `acr` claim whose value is one of the specified entries; otherwise the
#'   login fails with a `shinyOAuth_id_token_error`.
#'
#'   Additionally, when non-empty, the authorization request automatically
#'   includes an `acr_values` query parameter (space-separated) as a voluntary
#'   hint to the provider (OIDC Core §3.1.2.1).  Note that the provider is
#'   not required to honour this hint; the client-side validation is the
#'   authoritative enforcement.
#'
#'   Requires an OIDC-capable provider with `id_token_validation = TRUE` and
#'   an `issuer` configured.  Default is `character(0)` (no enforcement).
#'
#' @param introspect If TRUE, the login flow will call the provider's token
#'   introspection endpoint (RFC 7662) to validate the access token. The login
#'   is not considered complete unless introspection succeeds and returns
#'   `active = TRUE`; otherwise the login fails and `authenticated` remains
#'   FALSE. Default is FALSE. Requires the provider to have an
#'   `introspection_url` configured.
#'
#' @param introspect_elements Optional character vector of additional
#'   requirements to enforce on the introspection response when
#'   `introspect = TRUE`. Supported values:
#'   - `"sub"`: require the introspected `sub` to match the session subject
#'     (from ID token `sub` when available, else from userinfo `sub`).
#'   - `"client_id"`: require the introspected `client_id` to match your OAuth
#'     client id.
#'   - `"scope"`: validate introspected `scope` against requested scopes
#'     (respects the client's `scope_validation` mode).
#'   Default is `character(0)`.
#'   (Note that not all providers may return each of these fields in
#'   introspection responses.)
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
OAuthClient <- S7::new_class(
  "OAuthClient",
  package = "shinyOAuth",
  properties = list(
    # Use class_any here to avoid load-order dependency on OAuthProvider symbol;
    # we validate it's actually an OAuthProvider in the validator below.
    provider = S7::class_any,
    client_id = S7::class_character,
    client_secret = S7::class_character,
    # Optional client private key (PEM string or openssl::key) for private_key_jwt
    client_private_key = S7::new_property(S7::class_any, default = NULL),
    # Optional kid header to include when using private_key_jwt
    client_private_key_kid = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for client assertion signing algorithm. If NULL, defaults
    # to HS256 for client_secret_jwt and RS256 for private_key_jwt
    client_assertion_alg = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    # Optional override for the client assertion audience claim.
    client_assertion_audience = S7::new_property(
      S7::class_character,
      default = NA_character_
    ),
    redirect_uri = S7::class_character,
    scopes = S7::class_character,
    # Optional OIDC claims request parameter (OIDC Core §5.5):
    # can be NULL (no claims), a list (auto JSON-encoded), or a character
    # string (pre-encoded JSON). When a list, it is JSON-encoded using
    # jsonlite::toJSON(auto_unbox = TRUE, null = "null") during auth URL
    # construction.
    claims = S7::new_property(
      S7::class_any,
      default = NULL
    ),
    state_store = S7::new_property(
      S7::class_any,
      default = quote(cachem::cache_mem(max_age = 300))
    ),
    state_payload_max_age = S7::new_property(S7::class_numeric, default = 300),
    state_entropy = S7::new_property(S7::class_numeric, default = 64),
    state_key = S7::new_property(
      S7::class_any,
      default = quote(random_urlsafe(n = 128))
    ),
    scope_validation = S7::new_property(
      S7::class_character,
      default = "strict"
    ),
    claims_validation = S7::new_property(
      S7::class_character,
      default = "none"
    ),

    # OIDC acr enforcement (OIDC Core §2, §3.1.2.1): when non-empty, the ID
    # token's acr claim must match one of these values.
    required_acr_values = S7::new_property(
      S7::class_character,
      default = character(0)
    ),

    # Token introspection settings (RFC 7662): control whether login validates
    # the access token via the provider's introspection endpoint.
    introspect = S7::new_property(S7::class_logical, default = FALSE),
    introspect_elements = S7::new_property(
      S7::class_character,
      default = character(0)
    )
  ),
  validator = function(self) {
    warn_about_oauth_client_created_in_shiny(state_key_missing = NA)

    if (!S7::S7_inherits(self@provider, OAuthProvider)) {
      return("OAuthClient: provider must be an OAuthProvider object")
    }

    # Require a non-empty client_id
    if (!is_valid_string(self@client_id)) {
      return("OAuthClient: client_id must be a non-empty string")
    }

    parsed <- try(httr2::url_parse(self@redirect_uri), silent = TRUE)
    if (
      inherits(parsed, "try-error") ||
        !nzchar((parsed$scheme %||% "")) ||
        !nzchar((parsed$hostname %||% ""))
    ) {
      return(
        "OAuthClient: redirect_uri must be an absolute URL (including scheme and hostname)"
      )
    }

    # RFC 6749 Section 3.1.2: redirect URI MUST NOT include a fragment
    if (nzchar(parsed$fragment %||% "")) {
      return(
        "OAuthClient: redirect_uri must not contain a URI fragment (RFC 6749 Section 3.1.2)"
      )
    }

    if (!is_ok_host(self@redirect_uri)) {
      return(paste0(
        "OAuthClient: redirect URI not accepted as a host ",
        "(see `?is_ok_host` for details)"
      ))
    }

    # State payload freshness window (issued_at)
    spma <- suppressWarnings(as.numeric(self@state_payload_max_age))
    if (length(spma) != 1L || !is.finite(spma) || spma <= 0) {
      return(
        "OAuthClient: state_payload_max_age must be a finite positive number of seconds"
      )
    }

    # Validate client_secret presence based on provider auth style and PKCE
    tok_style <- self@provider@token_auth_style %||% "header"
    uses_pkce <- isTRUE(self@provider@use_pkce)
    if (identical(tok_style, "header")) {
      # For client_secret_basic (header) auth, a non-empty secret is required
      if (!is_valid_string(self@client_secret)) {
        return(
          "OAuthClient: client_secret is required when token_auth_style = 'header'"
        )
      }
    } else if (identical(tok_style, "body")) {
      # For client_secret_post (body) auth, allow secretless only with PKCE
      if (!uses_pkce && !is_valid_string(self@client_secret)) {
        return(
          "OAuthClient: client_secret is required unless using PKCE with token_auth_style = 'body'"
        )
      }
    } else if (identical(tok_style, "client_secret_jwt")) {
      # JWT HMAC client assertion requires a non-empty client_secret
      if (!is_valid_string(self@client_secret)) {
        return(
          "OAuthClient: client_secret is required when token_auth_style = 'client_secret_jwt'"
        )
      }
      # Soft guardrail: warn when secret is short (< 32 bytes)
      if (
        !.is_test() &&
          nchar(self@client_secret, type = "bytes") < 32
      ) {
        rlang::warn(
          c(
            "!" = "client_secret appears short for HMAC (recommended >= 32 bytes)",
            "i" = "Consider using a longer, randomly generated secret for JWT client authentication"
          ),
          .frequency = "once",
          .frequency_id = "jwt-client-hmac-secret-short"
        )
      }
    } else if (identical(tok_style, "private_key_jwt")) {
      # Asymmetric client assertion requires a private key
      if (is.null(self@client_private_key)) {
        return(
          "OAuthClient: client_private_key is required when token_auth_style = 'private_key_jwt'"
        )
      }
      # Basic sanity: if a character was supplied, must look like a PEM
      if (is.character(self@client_private_key)) {
        pem <- paste(self@client_private_key, collapse = "\n")
        # Accept PKCS#1 ("BEGIN RSA PRIVATE KEY" / "BEGIN EC PRIVATE KEY")
        # and PKCS#8 ("BEGIN PRIVATE KEY"). Make the RSA/EC prefix optional.
        if (
          !grepl(
            "BEGIN (?:RSA |EC )?PRIVATE KEY",
            pem,
            ignore.case = TRUE,
            perl = TRUE
          )
        ) {
          return(
            "OAuthClient: client_private_key must be a PEM string (BEGIN ... PRIVATE KEY) or an openssl::key"
          )
        }
      }
    }

    # Fail fast: HS* ID token verification requires a strong client_secret.
    #
    # For PKCE/public clients, client_secret may legitimately be empty for token
    # exchange (token_auth_style = 'body' with PKCE), but if the provider allows
    # HS* ID token algs and the flow may validate ID tokens (id_token_validation
    # or use_nonce), validate_id_token() will later error when client_secret is
    # missing/too short.
    aa <- toupper(as.character(self@provider@allowed_algs %||% character(0)))
    hs_algs <- c("HS256", "HS384", "HS512")
    should_validate_id_token <-
      isTRUE(self@provider@id_token_validation) ||
      isTRUE(self@provider@use_nonce)
    if (any(aa %in% hs_algs) && isTRUE(should_validate_id_token)) {
      if (!is_valid_string(self@client_secret)) {
        return(
          "OAuthClient: client_secret is required for HS* ID token validation when id_token_validation or use_nonce is enabled"
        )
      }
      if (nchar(self@client_secret, type = "bytes") < 32) {
        return(
          "OAuthClient: HS* ID token validation requires client_secret >= 32 bytes"
        )
      }
    }

    # If an explicit client_assertion_alg is provided, validate compatibility
    # with the configured token authentication style so we fail fast with a
    # clear input error rather than later inside JWT signing.
    if (!is.null(self@client_assertion_alg)) {
      alg_chr <- as.character((self@client_assertion_alg %||% NA_character_)[[
        1
      ]])
      if (!is.na(alg_chr) && nzchar(alg_chr)) {
        alg <- toupper(alg_chr)
        allowed_hmac <- c("HS256", "HS384", "HS512")
        allowed_asym <- c(
          # RSA-PKCS1 v1.5
          "RS256",
          "RS384",
          "RS512",
          # RSA-PSS
          "PS256",
          "PS384",
          "PS512",
          # ECDSA over P-256/384/521
          "ES256",
          "ES384",
          "ES512",
          "EDDSA"
        )
        if (
          identical(tok_style, "client_secret_jwt") && !(alg %in% allowed_hmac)
        ) {
          return(paste0(
            "OAuthClient: client_assertion_alg '",
            alg,
            "' is incompatible with token_auth_style = 'client_secret_jwt' (expected one of: ",
            paste(allowed_hmac, collapse = ", "),
            ")"
          ))
        }
        if (
          identical(tok_style, "private_key_jwt") && !(alg %in% allowed_asym)
        ) {
          return(paste0(
            "OAuthClient: client_assertion_alg '",
            alg,
            "' is incompatible with token_auth_style = 'private_key_jwt' (expected one of: ",
            paste(allowed_asym, collapse = ", "),
            ")"
          ))
        }
      }
    }

    # Validate client_assertion_audience when provided
    caa <- self@client_assertion_audience %||% NA_character_
    caa_chr <- as.character(caa[[1]])
    if (!is.na(caa_chr) && nzchar(caa_chr) && !is_valid_string(caa_chr)) {
      return(
        "OAuthClient: client_assertion_audience must be a non-empty string when provided"
      )
    }

    # Validate state_entropy: must be a finite length-1 numeric integer in [22, 128]
    ent <- self@state_entropy
    if (is.null(ent) || length(ent) != 1L || is.na(ent)) {
      return(
        "OAuthClient: state_entropy must be a non-NA length-1 numeric value"
      )
    }
    if (!is.numeric(ent) || !is.finite(ent)) {
      return("OAuthClient: state_entropy must be a finite numeric value")
    }
    # Require integer-like (avoid fractional lengths causing truncation surprises)
    if (!isTRUE(all.equal(ent, as.integer(ent)))) {
      return(
        "OAuthClient: state_entropy must be an integer number of characters"
      )
    }
    ent <- as.integer(ent)
    if (ent < 22L || ent > 128L) {
      return("OAuthClient: state_entropy must be between 22 and 128")
    }

    # Validate state_key: allow character (>= 32 chars) OR raw (>= 32 bytes)
    sk <- self@state_key
    sk_valid <- (is.character(sk) && is_valid_string(sk, min_char = 32)) ||
      (is.raw(sk) && length(sk) >= 32L)
    if (!sk_valid) {
      return(
        "OAuthClient: state_key must be character (>= 32 chars) or raw (>= 32 bytes)"
      )
    }

    # Duck-type state_store: require $get, $set, and $remove; $info optional
    has_get <- !is.null(self@state_store$get) &&
      is.function(self@state_store$get)
    has_set <- !is.null(self@state_store$set) &&
      is.function(self@state_store$set)
    has_remove <- !is.null(self@state_store$remove) &&
      is.function(self@state_store$remove)
    if (!isTRUE(has_get && has_set && has_remove)) {
      return(paste(
        "OAuthClient: state_store must implement cachem methods:",
        "$get(key, missing)",
        "$set(key, value)",
        "$remove(key)",
        sep = " "
      ))
    }

    # Robustness: verify method signatures/compatibility.
    # - $get must accept a named `missing` argument (or `...`).
    #   Validated via formals inspection (no probe-call) to avoid triggering
    #   side-effects in stateful backends or test wrappers.
    get_formals <- try(formals(self@state_store$get), silent = TRUE)
    get_args <- if (!inherits(get_formals, "try-error")) {
      names(get_formals)
    } else {
      character()
    }
    if (!("..." %in% get_args || "missing" %in% get_args)) {
      return(
        "OAuthClient: state_store$get must accept argument 'missing' (expected signature get(key, missing = NULL))"
      )
    }

    # - $set must accept (key, value) either explicitly or via "..."
    #   (do not probe-call to avoid side-effects)
    set_formals <- try(formals(self@state_store$set), silent = TRUE)
    set_args <- if (!inherits(set_formals, "try-error")) {
      names(set_formals)
    } else {
      character()
    }
    if (
      !("..." %in% set_args || ("key" %in% set_args && "value" %in% set_args))
    ) {
      return("OAuthClient: state_store$set must accept (key, value)")
    }

    # - $remove must accept a key (explicitly or via "...")
    rm_formals <- try(formals(self@state_store$remove), silent = TRUE)
    rm_args <- if (!inherits(rm_formals, "try-error")) {
      names(rm_formals)
    } else {
      character()
    }
    # remove() is called positionally; require at least one parameter (any name) or allow ...
    if (!("..." %in% rm_args || length(rm_args) >= 1L)) {
      return("OAuthClient: state_store$remove must accept (key)")
    }

    # Optional $take for atomic state consumption (preferred for shared stores)
    # Validated via formals inspection (no probe-call) to avoid triggering
    # side-effects in stateful backends or test wrappers.
    if (
      !is.null(self@state_store$take) &&
        is.function(self@state_store$take)
    ) {
      take_formals <- try(formals(self@state_store$take), silent = TRUE)
      take_args <- if (!inherits(take_formals, "try-error")) {
        names(take_formals)
      } else {
        character()
      }
      if (!("..." %in% take_args || "missing" %in% take_args)) {
        return(
          "OAuthClient: state_store$take must accept argument 'missing' (expected signature take(key, missing = NULL))"
        )
      }
    }

    # Validate scopes
    scopes_valid <- try(validate_scopes(self@scopes), silent = TRUE)
    if (inherits(scopes_valid, "try-error")) {
      return(paste0("OAuthClient: scopes validation error: ", scopes_valid))
    }

    # Validate claims
    if (!is.null(self@claims)) {
      # Must be either a list or a single non-empty character string
      if (is.list(self@claims)) {
        # Lists are valid; they will be JSON-encoded later
      } else if (is.character(self@claims)) {
        if (length(self@claims) != 1L || !nzchar(self@claims)) {
          return(
            "OAuthClient: claims must be a single non-empty character string when provided as character"
          )
        }
        # Try to validate it's valid JSON
        json_valid <- try(jsonlite::validate(self@claims), silent = TRUE)
        if (inherits(json_valid, "try-error") || !isTRUE(json_valid)) {
          return(
            "OAuthClient: claims provided as character must be valid JSON"
          )
        }
      } else {
        return(
          "OAuthClient: claims must be NULL, a list, or a character string"
        )
      }
    }

    # Validate scope_validation
    if (
      !is_valid_string(self@scope_validation) ||
        !self@scope_validation %in% c("strict", "warn", "none")
    ) {
      return(
        "OAuthClient: scope_validation must be one of 'strict', 'warn', or 'none'"
      )
    }

    # Validate claims_validation
    if (
      !is_valid_string(self@claims_validation) ||
        !self@claims_validation %in% c("strict", "warn", "none")
    ) {
      return(
        "OAuthClient: claims_validation must be one of 'strict', 'warn', or 'none'"
      )
    }

    # Validate required_acr_values
    racr <- self@required_acr_values
    if (!is.character(racr)) {
      return("OAuthClient: required_acr_values must be a character vector")
    }
    if (anyNA(racr)) {
      return("OAuthClient: required_acr_values must not contain NA")
    }
    if (!all(nzchar(racr))) {
      return("OAuthClient: required_acr_values must not contain empty strings")
    }
    if (length(racr) > 0) {
      # acr enforcement requires an OIDC-capable provider (issuer + id_token_validation)
      if (!is_valid_string(self@provider@issuer)) {
        return(
          "OAuthClient: required_acr_values requires the provider to have an issuer configured"
        )
      }
      if (!isTRUE(self@provider@id_token_validation)) {
        return(
          "OAuthClient: required_acr_values requires id_token_validation = TRUE on the provider"
        )
      }
    }

    # Validate introspect
    if (
      !is.logical(self@introspect) ||
        length(self@introspect) != 1L ||
        is.na(self@introspect)
    ) {
      return("OAuthClient: introspect must be TRUE or FALSE (non-NA)")
    }

    # Validate introspect_elements
    ie <- self@introspect_elements
    if (!is.character(ie)) {
      return("OAuthClient: introspect_elements must be a character vector")
    }
    if (anyNA(ie)) {
      return("OAuthClient: introspect_elements must not contain NA")
    }
    if (!all(nzchar(ie))) {
      return("OAuthClient: introspect_elements must not contain empty strings")
    }
    ie <- unique(ie)
    if (!isTRUE(self@introspect) && length(ie) > 0) {
      return(
        "OAuthClient: introspect_elements was provided but introspect = FALSE; set introspect = TRUE or pass introspect_elements = character(0)"
      )
    }
    if (isTRUE(self@introspect) && length(ie) > 0) {
      allowed_ie <- c("sub", "client_id", "scope")
      bad <- setdiff(ie, allowed_ie)
      if (length(bad) > 0) {
        return(
          paste0(
            "OAuthClient: invalid introspect_elements value(s): ",
            paste(bad, collapse = ", "),
            "; allowed: ",
            paste(allowed_ie, collapse = ", ")
          )
        )
      }
    }

    # Fail fast: introspect = TRUE requires introspection_url
    if (isTRUE(self@introspect)) {
      introspection_url <- self@provider@introspection_url %||% NA_character_
      if (!is_valid_string(introspection_url)) {
        return(
          "OAuthClient: introspect = TRUE requires the provider to have an introspection_url configured"
        )
      }
    }
  }
)

warn_about_oauth_client_created_in_shiny <- function(state_key_missing = NA) {
  if (.is_test()) {
    return(invisible(NULL))
  }

  sess <- get_current_shiny_session()
  if (is.null(sess)) {
    return(invisible(NULL))
  }

  bullets <- c(
    "[{.pkg shinyOAuth}] - OAuthClient created inside Shiny",
    "!" = paste0(
      "Detected OAuth client construction while a Shiny session is active. ",
      "This is usually a bug: the OAuth login flow involves a redirect which creates a new session."
    )
  )

  if (isTRUE(state_key_missing)) {
    bullets <- c(
      bullets,
      "x" = paste0(
        "Because you did not supply {.code state_key}, it will be auto-generated for this session ",
        "and callbacks in the post-redirect session will be unable to decrypt/validate state."
      )
    )
  } else {
    bullets <- c(
      bullets,
      "i" = paste0(
        "Construct your {.code OAuthClient} once outside server logic (e.g., in global scope) and reuse it.",
        " If you must create clients dynamically, ensure {.code state_key} is stable across sessions and (for multi-worker deployments) shared across workers."
      )
    )
  }

  rlang::warn(
    bullets,
    .frequency = "once",
    .frequency_id = "oauth-client-created-in-shiny"
  )

  invisible(TRUE)
}

#' Create generic [OAuthClient]
#'
#' @inheritParams OAuthClient
#'
#' @return [OAuthClient] object
#'
#' @example inst/examples/oauth_module_server.R
#'
#' @export
oauth_client <- function(
  provider,
  client_id = Sys.getenv("OAUTH_CLIENT_ID"),
  client_secret = Sys.getenv("OAUTH_CLIENT_SECRET"),
  redirect_uri,
  scopes = character(0),
  claims = NULL,
  state_store = cachem::cache_mem(max_age = 300),
  state_payload_max_age = 300,
  state_entropy = 64,
  state_key = random_urlsafe(128),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  client_assertion_alg = NULL,
  client_assertion_audience = NULL,
  scope_validation = c("strict", "warn", "none"),
  claims_validation = c("none", "warn", "strict"),
  required_acr_values = character(0),
  introspect = FALSE,
  introspect_elements = character(0)
) {
  warn_about_oauth_client_created_in_shiny(
    state_key_missing = missing(state_key)
  )

  scope_validation <- match.arg(scope_validation)
  claims_validation <- match.arg(claims_validation)

  # Normalize scopes early so callers can provide a single space-delimited
  # string (common in OAuth examples) while internal code consistently sees
  # a character vector of individual tokens.
  if (!is.null(scopes)) {
    scopes_for_validation <- if (is.list(scopes)) {
      unlist(scopes, recursive = TRUE, use.names = FALSE)
    } else {
      scopes
    }
    validate_scopes(as.character(scopes_for_validation))
  }
  scopes <- as_scope_tokens(scopes %||% NULL)

  OAuthClient(
    provider = provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = redirect_uri,
    scopes = scopes,
    claims = claims,
    state_store = state_store,
    state_payload_max_age = state_payload_max_age,
    state_entropy = state_entropy,
    state_key = state_key,
    client_private_key = client_private_key,
    client_private_key_kid = client_private_key_kid %||% NA_character_,
    client_assertion_alg = client_assertion_alg %||% NA_character_,
    client_assertion_audience = client_assertion_audience %||% NA_character_,
    scope_validation = scope_validation,
    claims_validation = claims_validation,
    required_acr_values = required_acr_values,
    introspect = introspect,
    introspect_elements = introspect_elements
  )
}
