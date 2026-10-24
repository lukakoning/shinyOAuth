# RFC 8725 section 3.1 binds each key to one algorithm, including when a client
# uses its shared secret in several JWT profiles. These checks inspect settings
# only: they do not load private keys, sign probes or construct endpoint clients.

compatible_hmac_assertion_algs <- function(secret, algs) {
  Filter(
    function(alg) {
      alg %in%
        c("HS256", "HS384", "HS512") &&
        length(hmac_secret_bytes(secret)) >= min_hmac_key_bytes(alg)
    },
    algs
  )
}

client_hmac_algorithm_problem <- function(
  client,
  alg = NULL,
  profile = "operation"
) {
  provider <- client@provider
  secret <- client@client_secret
  bindings <- list()
  add <- function(secret, algs, profile) {
    if (!is_valid_string(secret)) {
      return(invisible(NULL))
    }
    for (alg in intersect(c("HS256", "HS384", "HS512"), algs)) {
      bindings[[length(bindings) + 1L]] <<- list(
        key = hmac_secret_bytes(secret),
        alg = alg,
        profile = profile
      )
    }
    invisible(NULL)
  }
  if (isTRUE(provider@id_token_validation) || isTRUE(provider@use_nonce)) {
    add(secret, provider@allowed_algs, "ID tokens")
  }
  if (
    normalize_token_auth_style(provider@token_auth_style) == "client_secret_jwt"
  ) {
    assertion_alg <- if (is_valid_string(client@client_assertion_alg)) {
      canonicalize_jws_alg(client@client_assertion_alg)
    } else {
      "HS256"
    }
    add(secret, assertion_alg, "token endpoint assertions")
  }
  if (client@request_object_mode %in% c("request", "request_uri")) {
    request_alg <- if (is_valid_string(client@request_object_signing_alg)) {
      canonicalize_jws_alg(client@request_object_signing_alg)
    } else if (is.null(client@client_assertion_private_key)) {
      "HS256"
    } else {
      NULL
    }
    add(secret, request_alg, "JAR")
  }
  if (
    resolve_oauth_client_response_mode(client)[["mode"]] %in%
      c("query.jwt", "form_post.jwt")
  ) {
    add(secret, resolve_authorization_response_signing_alg(client), "JARM")
  }
  for (endpoint in c("par", "introspection", "revocation")) {
    url <- switch(
      endpoint,
      par = provider@par_url,
      introspection = provider@introspection_url,
      revocation = provider@revocation_url
    )
    if (!is_valid_string(url)) {
      next
    }
    override <- client@endpoint_auth[[endpoint]] %||% list()
    method <- resolve_endpoint_auth_method(provider, endpoint, override)
    if (
      !is.null(method[["problem"]]) || method[["style"]] != "client_secret_jwt"
    ) {
      next
    }
    endpoint_secret <- override[["client_secret"]] %||% secret
    configured_alg <- override[["client_assertion_alg"]] %||%
      client@client_assertion_alg
    endpoint_alg <- if (is_valid_string(configured_alg)) {
      canonicalize_jws_alg(configured_alg)
    } else {
      "HS256"
    }
    # Introspection/revocation negotiate an omitted algorithm from metadata.
    # PAR instead inherits the token endpoint algorithm and its default.
    if (
      !is_valid_string(configured_alg) &&
        endpoint %in% c("introspection", "revocation")
    ) {
      algs <- provider@endpoint_auth_metadata[[endpoint]][["signing_algs"]]
      if (length(algs) && is_valid_string(endpoint_secret)) {
        compatible <- compatible_hmac_assertion_algs(endpoint_secret, algs)
        endpoint_alg <- if (length(compatible)) compatible[[1L]] else NULL
      }
    }
    add(endpoint_secret, endpoint_alg, paste(endpoint, "endpoint assertions"))
  }
  # Include the actual operation too, so restored objects cannot evade binding
  # by disabling a profile's configuration while invoking its helper directly.
  add(secret, alg, profile)
  for (i in seq_along(bindings)) {
    for (j in seq_len(i - 1L)) {
      first <- bindings[[j]]
      second <- bindings[[i]]
      if (
        identical(first[["key"]], second[["key"]]) &&
          first[["alg"]] != second[["alg"]]
      ) {
        return(paste0(
          "OAuthClient: the same HMAC secret must use exactly one HS algorithm ",
          "across JWT profiles (RFC 8725 section 3.1): ",
          first[["profile"]],
          " uses ",
          first[["alg"]],
          "; ",
          second[["profile"]],
          " uses ",
          second[["alg"]],
          ". Configure matching algorithms or distinct secrets."
        ))
      }
    }
  }
  NULL
}

check_client_hmac_algorithm <- function(
  client,
  alg,
  profile,
  signal_error = err_config
) {
  problem <- client_hmac_algorithm_problem(client, alg, profile)
  if (!is.null(problem)) {
    signal_error(problem)
  }
  invisible(NULL)
}
