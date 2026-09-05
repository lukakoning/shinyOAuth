# Endpoint authentication is resolved into a temporary client used only to
# shape the outgoing request. Identity validation retains the original client.
endpoint_auth_config_problem <- function(config) {
  if (
    !is.list(config) ||
      (length(config) &&
        (is.null(names(config)) ||
          anyDuplicated(names(config)) ||
          !all(names(config) %in% c("par", "introspection", "revocation"))))
  ) {
    return(
      "endpoint_auth must be a named list of par/introspection/revocation settings"
    )
  }
  fields <- c(
    "token_auth_style",
    "client_id",
    "client_secret",
    "client_assertion_private_key",
    "client_assertion_private_key_kid",
    "client_assertion_alg",
    "client_assertion_audience",
    "extra_headers",
    "mtls_client_cert_file",
    "mtls_client_key_file",
    "mtls_client_key_password",
    "mtls_client_ca_file"
  )
  for (endpoint in names(config)) {
    entry <- config[[endpoint]]
    if (
      !is.list(entry) ||
        (length(entry) &&
          (is.null(names(entry)) ||
            anyDuplicated(names(entry)) ||
            !all(names(entry) %in% fields)))
    ) {
      return(paste0("endpoint_auth$", endpoint, " contains invalid fields"))
    }
    if (endpoint %in% c("token", "par") && "client_id" %in% names(entry)) {
      return(
        "endpoint_auth cannot change the authorization client_id for token or PAR"
      )
    }
    for (field in setdiff(
      names(entry),
      c("client_assertion_private_key", "extra_headers")
    )) {
      value <- entry[[field]]
      if (!is.character(value) || length(value) != 1L || is.na(value)) {
        return(paste0(
          "endpoint_auth$",
          endpoint,
          "$",
          field,
          " must be a string"
        ))
      }
    }
    headers <- entry$extra_headers
    if (
      !is.null(headers) &&
        (!is.character(headers) ||
          anyNA(headers) ||
          (length(headers) &&
            (is.null(names(headers)) ||
              !all(nzchar(names(headers))) ||
              anyDuplicated(tolower(names(headers))) ||
              any(grepl("[[:cntrl:]]", c(names(headers), headers))) ||
              any(tolower(names(headers)) %in% c("authorization", "cookie")))))
    ) {
      return(
        "endpoint_auth extra_headers must be named, unique safe headers; configure credentials separately"
      )
    }
  }
  NULL
}

endpoint_auth_metadata_problem <- function(metadata) {
  if (
    !is.list(metadata) ||
      (length(metadata) &&
        (is.null(names(metadata)) ||
          anyDuplicated(names(metadata)) ||
          !all(names(metadata) %in% c("introspection", "revocation"))))
  ) {
    return(
      "endpoint_auth_metadata must contain introspection/revocation metadata"
    )
  }
  for (entry in metadata) {
    if (
      !is.list(entry) ||
        (length(entry) &&
          (is.null(names(entry)) ||
            anyDuplicated(names(entry)) ||
            !all(names(entry) %in% c("methods", "signing_algs"))))
    ) {
      return("endpoint_auth_metadata entries require methods/signing_algs")
    }
    for (value in entry) {
      if (
        !is.null(value) &&
          (!is.character(value) || anyNA(value) || !all(nzchar(value)))
      ) {
        return("endpoint_auth_metadata values must be string vectors or NULL")
      }
    }
    if ("none" %in% tolower(entry$signing_algs)) {
      return("endpoint_auth_metadata signing algorithms must not include none")
    }
  }
  NULL
}

discover_endpoint_auth_metadata <- function(disc) {
  out <- list()
  for (endpoint in c("introspection", "revocation")) {
    methods <- disc[[paste0(endpoint, "_endpoint_auth_methods_supported")]]
    algs <- disc[[paste0(
      endpoint,
      "_endpoint_auth_signing_alg_values_supported"
    )]]
    if (
      any(unlist(methods) %in% c("private_key_jwt", "client_secret_jwt")) &&
        is.null(algs)
    ) {
      err_parse(paste0(
        "Discovery ",
        endpoint,
        " JWT authentication requires signing algorithm metadata"
      ))
    }
    out[[endpoint]] <- list(
      methods = if (is.null(methods)) {
        NULL
      } else {
        unlist(methods, use.names = FALSE)
      },
      signing_algs = if (is.null(algs)) {
        NULL
      } else {
        unlist(algs, use.names = FALSE)
      }
    )
    if (endpoint == "revocation" && is.null(methods)) {
      out[[endpoint]]$methods <- "client_secret_basic"
    }
  }
  out
}

endpoint_auth_policy_digest <- function(config) {
  values <- lapply(config, function(entry) {
    key <- entry$client_assertion_private_key
    if (!is.null(key)) {
      entry$client_assertion_private_key <- openssl::write_pem(
        normalize_private_key_input(key)$pubkey
      )
    }
    entry
  })
  state_policy_value_digest(values)
}

endpoint_auth_client <- function(client, endpoint) {
  endpoint <- match.arg(
    endpoint,
    c("token", "par", "introspection", "revocation")
  )
  override <- client@endpoint_auth[[endpoint]] %||% list()
  if (endpoint == "token") {
    return(client)
  }
  provider <- client@provider
  endpoint_url <- switch(
    endpoint,
    token = provider@token_url,
    par = provider@par_url,
    introspection = provider@introspection_url,
    revocation = provider@revocation_url
  )
  if (!is_valid_string(endpoint_url)) {
    return(client)
  }
  metadata <- provider@endpoint_auth_metadata[[endpoint]]
  methods <- metadata$methods
  style <- normalize_token_auth_style(
    override$token_auth_style %||% provider@token_auth_style
  )
  method_name <- function(style) {
    switch(
      style,
      header = "client_secret_basic",
      body = "client_secret_post",
      public = "none",
      style
    )
  }
  if (length(methods) && !method_name(style) %in% methods) {
    # Only infer shared-secret methods; JWT/mTLS credentials need explicit setup.
    if (
      is.null(override$token_auth_style) && "client_secret_basic" %in% methods
    ) {
      style <- "header"
    } else if (
      is.null(override$token_auth_style) && "client_secret_post" %in% methods
    ) {
      style <- "body"
    } else {
      err_config(paste0(
        "endpoint_auth$",
        endpoint,
        ": authentication method is not advertised"
      ))
    }
  }
  headers <- override$extra_headers %||%
    if (endpoint == "token") {
      provider@extra_token_headers
    } else {
      character()
    }
  algs <- if (endpoint %in% c("token", "par")) {
    provider@token_endpoint_auth_signing_alg_values_supported
  } else {
    metadata$signing_algs %||% character()
  }
  provider_changes <- list(
    token_auth_style = style,
    extra_token_headers = headers,
    token_endpoint_auth_signing_alg_values_supported = algs
  )
  # S7 validates the entire resolved configuration, including credentials and keys.
  S7::props(provider) <- provider_changes
  changes <- override[setdiff(
    names(override),
    c("token_auth_style", "extra_headers")
  )]
  if (
    length(algs) &&
      is.null(override$client_assertion_alg) &&
      endpoint %in% c("introspection", "revocation")
  ) {
    compatible <- if (style == "client_secret_jwt") {
      secret <- changes$client_secret %||% client@client_secret
      Filter(
        function(alg) {
          alg %in%
            c("HS256", "HS384", "HS512") &&
            nchar(secret, type = "bytes") >= min_hmac_key_bytes(alg)
        },
        algs
      )
    } else if (style == "private_key_jwt") {
      key <- normalize_private_key_input(
        changes$client_assertion_private_key %||%
          client@client_assertion_private_key
      )
      Filter(
        function(alg) private_key_can_sign_jws_alg(key, alg, typ = "JWT"),
        algs
      )
    } else {
      character()
    }
    if (style %in% c("client_secret_jwt", "private_key_jwt")) {
      if (!length(compatible)) {
        err_config(paste0("No compatible assertion algorithm for ", endpoint))
      }
      changes$client_assertion_alg <- compatible[[1]]
    }
  }
  changes$provider <- provider
  changes$endpoint_auth <- list()
  S7::props(client) <- changes
  client
}
