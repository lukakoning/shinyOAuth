# Explicit data-only credential schema. Never serialize clients, environments,
# functions, cached validation code, or sender-constraint private keys.
connection_token_fields <- c(
  "access_token",
  "token_type",
  "refresh_token",
  "id_token",
  "original_id_token",
  "expires_at",
  "userinfo",
  "cnf",
  "granted_scopes",
  "granted_scopes_verified",
  "id_token_validated",
  "extra_fields",
  "initial_extra_fields",
  "smart_context"
)

connection_credential_key <- function(key) {
  if (!is.raw(key) || length(key) != 32L) {
    err_config(
      "Connection encryption requires a deployment-controlled 32-byte raw key"
    )
  }
  as.raw(openssl::sha256(
    charToRaw("shinyOAuth/retained-connection/credentials/v1"),
    key = key
  ))
}

connection_current_target_fingerprint <- function(target) {
  if (!inherits(target, "OAuthTarget")) {
    err_config("Connection credentials require an OAuthTarget")
  }
  # Re-read key/certificate references and material validation policy. A cached
  # target fingerprint alone cannot detect changed key files or process policy.
  current <- oauth_target(
    target$client,
    target$resource_bases,
    target$required_scopes,
    target$label
  )$fingerprint
  if (!identical(current, target$fingerprint)) {
    err_token(
      "Connection target configuration changed; reconnect with a new target"
    )
  }
  current
}

connection_credential_binding <- function(owner, id, target) {
  for (value in list(owner, id)) {
    if (!is_valid_string(value) || !grepl("^[A-Za-z0-9_-]{16,128}$", value)) {
      err_input("Invalid connection credential binding")
    }
  }
  list(
    purpose = "shinyOAuth/retained-connection",
    version = 1L,
    owner = owner,
    id = id,
    fingerprint = connection_current_target_fingerprint(target)
  )
}

# Tagged JSON nodes preserve NULL, NA, Inf, empty vectors and both extension
# snapshots exactly, without R unserialization or arbitrary object construction.
connection_data_encode <- function(value) {
  budget <- new.env(parent = emptyenv())
  budget$nodes <- 0L
  budget$bytes <- 0
  encode <- function(value, depth = 0L) {
    budget$nodes <- budget$nodes + 1L + length(value)
    if (
      depth > 16L ||
        budget$nodes > 20000L ||
        is.object(value) ||
        !all(names(attributes(value)) %in% "names")
    ) {
      err_token("Connection credentials must contain bounded plain data")
    }
    kind <- typeof(value)
    if (
      !kind %in% c("NULL", "list", "character", "logical", "integer", "double")
    ) {
      err_token("Connection credentials must contain bounded plain data")
    }
    labels <- names(value)
    if (
      !is.null(labels) &&
        (anyNA(labels) || anyDuplicated(labels) || !all(nzchar(labels)))
    ) {
      err_token("Connection data has invalid or duplicate names")
    }
    if (kind == "NULL") {
      return(list(kind = "NULL"))
    }
    if (kind == "list") {
      return(list(
        kind = kind,
        names = as.list(labels),
        values = unname(lapply(value, encode, depth = depth + 1L))
      ))
    }
    missing_values <- is.na(value)
    if (kind == "double") {
      missing_values <- missing_values & !is.nan(value)
    }
    values <- if (kind == "double") {
      sprintf("%.17g", value)
    } else {
      as.character(value)
    }
    values[missing_values] <- ""
    budget$bytes <- budget$bytes +
      sum(nchar(values, type = "bytes")) +
      sum(nchar(labels, type = "bytes"))
    if (budget$bytes > 512 * 1024) {
      err_token("Connection credential data exceeds the size limit")
    }
    list(
      kind = kind,
      names = as.list(labels),
      values = unname(as.list(values)),
      missing = unname(as.list(missing_values))
    )
  }
  encode(value)
}

connection_data_decode <- function(node) {
  budget <- 0L
  decode <- function(node, depth = 0L) {
    budget <<- budget + 1L + length(node$values)
    bad <- function() err_token("Invalid stored connection credential schema")
    if (
      depth > 16L ||
        budget > 20000L ||
        !is.list(node) ||
        !is_valid_string(node$kind)
    ) {
      bad()
    }
    if (identical(node$kind, "NULL")) {
      if (!identical(names(node), "kind")) {
        bad()
      }
      return(NULL)
    }
    fields <- c("kind", "names", "values")
    if (!identical(node$kind, "list")) {
      fields <- c(fields, "missing")
    }
    if (
      !identical(names(node), fields) ||
        !is.list(node$values) ||
        !is.list(node$names)
    ) {
      bad()
    }
    labels <- unlist(node$names, use.names = FALSE)
    if (
      length(labels) &&
        (!is.character(labels) ||
          length(labels) != length(node$values) ||
          anyNA(labels) ||
          anyDuplicated(labels) ||
          !all(nzchar(labels)))
    ) {
      bad()
    }
    if (identical(node$kind, "list")) {
      value <- lapply(node$values, decode, depth = depth + 1L)
    } else {
      if (
        !node$kind %in% c("character", "logical", "integer", "double") ||
          !is.list(node$missing) ||
          length(node$missing) != length(node$values) ||
          !all(vapply(
            node$values,
            function(x) is.character(x) && length(x) == 1L && !is.na(x),
            logical(1)
          )) ||
          !all(vapply(
            node$missing,
            function(x) is.logical(x) && length(x) == 1L && !is.na(x),
            logical(1)
          ))
      ) {
        bad()
      }
      text <- unlist(node$values, use.names = FALSE) %||% character()
      absent <- unlist(node$missing, use.names = FALSE) %||% logical()
      value <- switch(
        node$kind,
        character = text,
        logical = {
          if (any(!absent & !text %in% c("TRUE", "FALSE"))) {
            bad()
          }
          text == "TRUE"
        },
        integer = suppressWarnings(as.integer(text)),
        double = suppressWarnings(as.numeric(text))
      )
      if (
        node$kind %in%
          c("integer", "double") &&
          any(!absent & is.na(value) & !(node$kind == "double" & text == "NaN"))
      ) {
        bad()
      }
      value[absent] <- NA
    }
    if (length(labels)) {
      names(value) <- labels
    }
    value
  }
  decode(node)
}

connection_credentials_seal <- function(
  token,
  owner,
  id,
  target,
  key,
  authenticated_at
) {
  S7::check_is_S7(token, OAuthToken)
  if (
    !is.numeric(authenticated_at) ||
      length(authenticated_at) != 1L ||
      !is.finite(authenticated_at) ||
      authenticated_at < 0
  ) {
    err_input("Connection authentication time must be a finite timestamp")
  }
  values <- stats::setNames(
    lapply(connection_token_fields, function(field) S7::prop(token, field)),
    connection_token_fields
  )
  payload <- list(
    binding = connection_credential_binding(owner, id, target),
    authenticated_at = authenticated_at,
    credentials = connection_data_encode(values)
  )
  json <- jsonlite::toJSON(
    payload,
    auto_unbox = TRUE,
    digits = NA,
    null = "null"
  )
  if (nchar(json, type = "bytes") > 1024^2) {
    err_token("Connection credential data exceeds the size limit")
  }
  state_encrypt_gcm(payload, connection_credential_key(key))
}

connection_credentials_open <- function(sealed, owner, id, target, key) {
  derived_key <- connection_credential_key(key)
  binding <- connection_credential_binding(owner, id, target)
  tryCatch(
    {
      payload <- state_decrypt_gcm(
        sealed,
        derived_key,
        size_limits = list(
          token = 3 * 1024^2,
          wrapper = 2 * 1024^2,
          ct_b64 = 2 * 1024^2,
          ct = 1024^2
        )
      )
      if (
        !identical(
          names(payload),
          c("binding", "authenticated_at", "credentials")
        ) ||
          !identical(payload$binding, binding) ||
          !is.numeric(payload$authenticated_at) ||
          length(payload$authenticated_at) != 1L ||
          !is.finite(payload$authenticated_at) ||
          payload$authenticated_at < 0
      ) {
        err_token("Invalid stored connection credential schema")
      }
      fields <- connection_data_decode(payload$credentials)
      if (
        !is.list(fields) || !identical(names(fields), connection_token_fields)
      ) {
        err_token("Invalid stored connection credential schema")
      }
      list(
        token = do.call(OAuthToken, fields),
        authenticated_at = payload$authenticated_at
      )
    },
    error = function(...) {
      err_token("Stored connection credentials are unavailable or incompatible")
    }
  )
}
