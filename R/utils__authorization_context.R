# Internal, data-only transaction context. The manager owns the meaning of its
# target/owner/resource/profile fields; the core binds a bounded immutable JSON
# snapshot without serializing functions, environments, credentials or clients.
authorization_context_json <- function(context) {
  if (is.null(context)) {
    return(NULL)
  }
  invalid <- function() {
    err_config("Authorization context must be a bounded named data list")
  }
  check <- function(value, depth = 0L) {
    if (depth > 8L || is.object(value) || length(value) > 128L) {
      invalid()
    }
    if (is.null(value)) {
      return(invisible(NULL))
    }
    if (is.list(value)) {
      nm <- names(value)
      if (
        !is.null(nm) && (anyNA(nm) || !all(nzchar(nm)) || anyDuplicated(nm))
      ) {
        invalid()
      }
      lapply(value, check, depth = depth + 1L)
    } else if (
      !(is.character(value) || is.logical(value) || is.numeric(value)) ||
        anyNA(value) ||
        !is.null(attributes(value)) ||
        (is.numeric(value) && !all(is.finite(value))) ||
        (is.character(value) && sum(nchar(value, type = "bytes")) > 4096L)
    ) {
      invalid()
    }
    invisible(NULL)
  }
  if (!is.list(context) || !length(context) || is.null(names(context))) {
    invalid()
  }
  check(context)
  json <- as.character(jsonlite::toJSON(
    context,
    auto_unbox = TRUE,
    null = "null",
    digits = NA
  ))
  if (nchar(json, type = "bytes") > 4096L) {
    invalid()
  }
  json
}

authorization_context_digest <- function(json) {
  if (is.null(json)) {
    return(NULL)
  }
  if (!is_valid_string(json) || nchar(json, type = "bytes") > 4096L) {
    err_invalid_state("Invalid authorization context binding")
  }
  unclass(as.character(openssl::sha256(charToRaw(enc2utf8(json)))))
}

# Read-only binding check. Routing still needs independent callback issuer,
# browser, owner and single-use state validation before exchanging a code.
payload_verify_authorization_context <- function(client, payload) {
  expected <- payload[["transaction_context_digest"]]
  if (is.null(expected)) {
    return(invisible(NULL))
  }
  if (!is_valid_string(expected) || !grepl("^[a-f0-9]{64}$", expected)) {
    err_invalid_state("Invalid authorization context binding")
  }
  invisible(NULL)
}

state_record_verify_authorization_context <- function(record, expected_digest) {
  actual <- authorization_context_digest(record[["transaction_context"]])
  if (is.null(expected_digest) && is.null(actual)) {
    return(invisible(NULL))
  }
  if (
    !is_valid_string(expected_digest) ||
      !is_valid_string(actual) ||
      !constant_time_compare(expected_digest, actual)
  ) {
    err_invalid_state("Authorization context does not match its transaction")
  }
  invisible(NULL)
}

# Structured internal preparation uses the exact generated state, including
# with PAR/JAR, rather than attempting to recover state from a redirect URL.
prepare_authorization <- function(
  client,
  browser_token,
  transaction_context = NULL,
  request_uri_publisher = NULL
) {
  prepared <- prepare_call(
    client,
    browser_token,
    .defer_build = TRUE,
    .transaction_context = transaction_context
  )
  tryCatch(
    {
      url <- finish_prepared_authorization(
        build_prepared_authorization(client, prepared),
        client,
        prepared,
        request_uri_publisher
      )
      payload <- state_payload_decrypt_validate(
        client,
        prepared$build_args$payload
      )
      state_record_verify_authorization_context(
        state_store_get(client, payload$state),
        payload$transaction_context_digest
      )
      expires_at <- as.POSIXct(
        payload$issued_at + client@state_payload_max_age,
        origin = "1970-01-01",
        tz = "UTC"
      )
      if (client@request_object_mode %in% c("request", "request_uri")) {
        # Conservative bound from preparation; signing can occur later in a worker.
        expires_at <- min(
          expires_at,
          as.POSIXct(
            payload$issued_at + client@request_object_ttl,
            origin = "1970-01-01",
            tz = "UTC"
          )
        )
      }
      par_expiry <- attr(url, "shinyOAuth.par_expires_at")
      if (!is.null(par_expiry)) {
        expires_at <- min(expires_at, par_expiry)
      }
      structure(
        list(
          url = url,
          state = prepared$build_args$payload,
          state_key = prepared$state_key,
          expires_at = expires_at
        ),
        class = "shinyOAuth_authorization"
      )
    },
    error = function(e) {
      try(client@state_store$remove(prepared$state_key), silent = TRUE)
      stop(e)
    }
  )
}

#' @export
format.shinyOAuth_authorization <- function(x, ...) {
  "<shinyOAuth_authorization: redirect and transaction data redacted>"
}

#' @export
print.shinyOAuth_authorization <- function(x, ...) {
  cat(format(x), "\n")
  invisible(x)
}
