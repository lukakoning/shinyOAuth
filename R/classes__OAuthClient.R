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
    redirect_uri = S7::class_character,
    scopes = S7::class_character,
    state_store = S7::new_property(
      S7::class_any,
      default = quote(cachem::cache_mem(max_age = 300))
    ),
    state_entropy = S7::new_property(S7::class_numeric, default = 64),
    state_key = S7::new_property(
      S7::class_any,
      default = quote(random_urlsafe(n = 128))
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

    if (!is_ok_host(self@redirect_uri)) {
      return(paste0(
        "OAuthClient: redirect URI not accepted as a host ",
        "(see `?is_ok_host` for details)"
      ))
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
    #   Probe-call it with a sentinel key to detect unsupported signatures
    #   early (avoids failing later during the login flow).
    get_ok <- try(
      self@state_store$get(
        key = "__signature_probe__",
        missing = NULL
      ),
      silent = TRUE
    )
    if (inherits(get_ok, "try-error")) {
      return(paste0(
        "OAuthClient: state_store$get must accept argument 'missing' (expected signature get(key, missing = NULL)); got error: ",
        as.character(get_ok)
      ))
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

    # Validate scopes
    scopes_valid <- try(validate_scopes(self@scopes), silent = TRUE)
    if (inherits(scopes_valid, "try-error")) {
      return(paste0("OAuthClient: scopes validation error: ", scopes_valid))
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
  state_store = cachem::cache_mem(max_age = 300),
  state_entropy = 64,
  state_key = random_urlsafe(128),
  client_private_key = NULL,
  client_private_key_kid = NULL,
  client_assertion_alg = NULL
) {
  warn_about_oauth_client_created_in_shiny(state_key_missing = missing(state_key))

  OAuthClient(
    provider = provider,
    client_id = client_id,
    client_secret = client_secret,
    redirect_uri = redirect_uri,
    scopes = scopes,
    state_store = state_store,
    state_entropy = state_entropy,
    state_key = state_key,
    client_private_key = client_private_key,
    client_private_key_kid = client_private_key_kid %||% NA_character_,
    client_assertion_alg = client_assertion_alg %||% NA_character_
  )
}
