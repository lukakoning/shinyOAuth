# Bind outgoing RSA signing profiles by normalized public material, independently
# of PEM spelling, key objects and kid values. Inspect active profiles and repeat
# the check at signing time so restored clients and changed key files fail closed.
client_rsa_algorithm_problem <- function(client, key = NULL, alg = NULL, profile = "operation") {
  provider <- client@provider
  profiles <- list()
  add <- function(key, alg, profile, metadata = NULL) {
    if (is.null(key) || (is_valid_string(alg) && startsWith(toupper(alg), "HS"))) {
      return(invisible(NULL))
    }
    profiles[[length(profiles) + 1L]] <<- list(
      key = key, alg = alg, profile = profile, metadata = metadata
    )
    invisible(NULL)
  }
  if (normalize_token_auth_style(provider@token_auth_style) == "private_key_jwt") {
    add(client@client_assertion_private_key, client@client_assertion_alg, "token endpoint assertions")
  }
  if (client@request_object_mode %in% c("request", "request_uri")) {
    add(client@client_assertion_private_key, client@request_object_signing_alg, "JAR")
  }
  if (!is.null(client@dpop_private_key)) {
    add(client@dpop_private_key, client@dpop_signing_alg, "DPoP")
  }
  for (endpoint in c("par", "introspection", "revocation")) {
    url <- switch(endpoint,
      par = provider@par_url,
      introspection = provider@introspection_url,
      revocation = provider@revocation_url
    )
    if (!is_valid_string(url)) {
      next
    }
    override <- client@endpoint_auth[[endpoint]] %||% list()
    method <- resolve_endpoint_auth_method(provider, endpoint, override)
    if (!is.null(method[["problem"]]) || method[["style"]] != "private_key_jwt") {
      next
    }
    add(
      override[["client_assertion_private_key"]] %||% client@client_assertion_private_key,
      override[["client_assertion_alg"]] %||% client@client_assertion_alg,
      paste(endpoint, "endpoint assertions"),
      if (endpoint %in% c("introspection", "revocation")) {
        provider@endpoint_auth_metadata[[endpoint]][["signing_algs"]]
      }
    )
  }
  # Include the actual operation even when its profile is currently disabled.
  add(key, alg, profile)
  if (length(profiles) < 2L) {
    return(NULL)
  }
  bindings <- list()
  for (entry in profiles) {
    key <- normalize_private_key_input(entry[["key"]])
    if (!inherits(key, "rsa")) {
      next
    }
    configured <- entry[["alg"]]
    bound_alg <- if (is_valid_string(configured)) canonicalize_jws_alg(configured) else "RS256"
    if (!is_valid_string(configured) && length(entry[["metadata"]])) {
      # Match endpoint_auth_client(): prefer the usual RSA default when offered,
      # otherwise select the first advertised algorithm supported for signing.
      compatible <- intersect(entry[["metadata"]], c("RS256", "RS384"))
      if (!length(compatible)) {
        next
      }
      bound_alg <- if ("RS256" %in% compatible) "RS256" else compatible[[1L]]
    }
    if (!bound_alg %in% c("RS256", "RS384", "RS512")) {
      # Impossible key/algorithm pairs are reported by their profile's existing
      # compatibility validator; they cannot create a usable second binding.
      next
    }
    tp <- compute_jwk_thumbprint(private_key_public_jwk(key))
    previous <- bindings[[tp]]
    if (!is.null(previous) && !identical(previous[["alg"]], bound_alg)) {
      return(paste0(
        "OAuthClient: the same RSA key material must use exactly one algorithm across signing profiles: ",
        previous[["profile"]], " uses ", previous[["alg"]], "; ",
        entry[["profile"]], " uses ", bound_alg,
        ". Configure matching algorithms or distinct keys."
      ))
    }
    bindings[[tp]] <- list(alg = bound_alg, profile = entry[["profile"]])
  }
  NULL
}

check_client_rsa_algorithm <- function(client, key, alg, profile) {
  problem <- client_rsa_algorithm_problem(client, key, alg, profile)
  if (!is.null(problem)) {
    err_config(problem)
  }
  invisible(NULL)
}
