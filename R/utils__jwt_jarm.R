# This file contains the helpers that validate JWT Secured Authorization
# Responses (JARM) before the regular callback path consumes state or swaps the
# authorization code

# 1 JARM validation helpers ----------------------------------------------------

## 1.1 Client policy resolution ------------------------------------------------

#' Resolve the expected JARM signing algorithm for one client
#'
#' Used by JARM validation helpers after OAuthClient validation has already
#' normalized the effective callback response mode.
#'
#' @param oauth_client [OAuthClient] object.
#' @return Canonicalized JWS algorithm string.
#' @keywords internal
#' @noRd
resolve_authorization_response_signing_alg <- function(oauth_client) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  alg <- canonicalize_jws_alg(
    oauth_client@authorization_signed_response_alg %||% NA_character_
  )
  if (!nzchar(alg)) {
    return("RS256")
  }

  alg
}

#' Resolve encrypted JARM configuration for one client
#'
#' Used by inbound JARM validation to decide whether the callback JWT must be
#' decrypted before signature and claim checks.
#'
#' @param oauth_client [OAuthClient] object.
#' @return `NULL` when encrypted JARM is disabled, otherwise a named list.
#' @keywords internal
#' @noRd
resolve_authorization_response_encryption_config <- function(oauth_client) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  alg <- canonicalize_jwe_alg(
    oauth_client@authorization_encrypted_response_alg %||% NA_character_
  )
  enc <- canonicalize_jwe_enc(
    oauth_client@authorization_encrypted_response_enc %||% NA_character_
  )
  if (nzchar(alg) && !nzchar(enc)) {
    enc <- "A128CBC-HS256"
  }

  if (!nzchar(alg) && !nzchar(enc)) {
    return(NULL)
  }

  list(
    alg = alg,
    enc = enc,
    private_key = oauth_client@authorization_response_decryption_private_key,
    kid = oauth_client@authorization_response_decryption_private_key_kid %||%
      NA_character_
  )
}

#' Resolve the configured JARM callback transport for one client
#'
#' Used by inbound JARM validation to bind the callback transport to the
#' response mode the client requested before any JWT claims are processed.
#'
#' @param oauth_client [OAuthClient] object.
#' @return `NULL` when the client is not configured for JARM; otherwise a named
#'   list containing the configured mode and callback transport.
#' @keywords internal
#' @noRd
resolve_jarm_callback_transport <- function(oauth_client) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  response_mode_info <- resolve_oauth_client_response_mode(oauth_client)
  if (!is.null(response_mode_info$error)) {
    err_config(response_mode_info$error)
  }

  mode <- response_mode_info$mode %||% "query"
  if (mode %in% c("query.jwt", "jwt")) {
    return(list(mode = mode, transport = "query"))
  }
  if (identical(mode, "form_post.jwt")) {
    return(list(mode = mode, transport = "form_post"))
  }

  NULL
}

## 1.2 Signature and claim validation -----------------------------------------

#' Verify one signed JARM signature
#'
#' Used after the JARM payload has been parsed and its issuer claim has been
#' checked, so asymmetric verification can fetch provider JWKS without trusting
#' an attacker-controlled issuer value.
#'
#' @param oauth_client [OAuthClient] object.
#' @param jwt_str Compact JWS string to verify.
#' @param alg Expected JOSE signing algorithm.
#' @param kid Optional JOSE key id.
#' @return Invisibly returns `TRUE` on success. Otherwise this function raises a
#'   typed callback validation error.
#' @keywords internal
#' @noRd
verify_jarm_signature <- function(oauth_client, jwt_str, alg, kid = NULL) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  alg <- canonicalize_jws_alg(alg)
  prov <- oauth_client@provider

  if (alg %in% c("HS256", "HS384", "HS512")) {
    if (!is_valid_string(oauth_client@client_secret)) {
      err_invalid_state("JARM HMAC validation requires client_secret")
    }

    min_secret_bytes <- min_hmac_key_bytes(alg)
    if (nchar(oauth_client@client_secret, type = "bytes") < min_secret_bytes) {
      err_invalid_state(paste0(
        "JARM ",
        alg,
        " validation requires client_secret >= ",
        min_secret_bytes,
        " bytes"
      ))
    }
    if (
      !isTRUE(verify_hmac_jws_signature_no_time(
        jwt_str,
        oauth_client@client_secret,
        alg
      ))
    ) {
      err_invalid_state("JARM HMAC signature is invalid")
    }

    return(invisible(TRUE))
  }

  if (
    !alg %in%
      c(
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA"
      )
  ) {
    err_invalid_state(paste0("Unsupported JARM signing algorithm: ", alg))
  }

  jwks <- fetch_jwks(
    prov@issuer,
    prov@jwks_cache,
    pins = prov@jwks_pins %||% character(),
    pin_mode = prov@jwks_pin_mode %||% "any",
    provider = prov
  )
  keys <- select_candidate_jwks(
    jwks,
    header_alg = alg,
    kid = kid,
    pins = prov@jwks_pins %||% character()
  )
  keys <- filter_jwks_for_alg(keys, alg)
  if (length(keys) == 0L) {
    err_invalid_state("No compatible provider JWKS keys found for JARM")
  }

  for (jk in keys) {
    pub <- try(jwk_to_pubkey(jk), silent = TRUE)
    if (inherits(pub, "try-error")) {
      next
    }
    if (isTRUE(verify_jws_signature_no_time(jwt_str, pub, alg))) {
      return(invisible(TRUE))
    }
  }

  err_invalid_state("JARM signature is invalid")
}

#' Read one JARM claim by exact name
#'
#' Used by JARM validation so near-match JSON member names cannot satisfy
#' required claims or response parameters via R partial matching.
#'
#' @param claims Parsed JARM claim list.
#' @param name Exact claim name to read.
#' @return Claim value, or `NULL` when the claim is absent.
#' @keywords internal
#' @noRd
jarm_claim <- function(claims, name) {
  stopifnot(
    is.list(claims),
    is.character(name),
    length(name) == 1L,
    !is.na(name)
  )

  claims[[name, exact = TRUE]]
}

#' Validate required pre-signature JARM claims
#'
#' Used before JWKS fetch or signature verification so malformed audience or
#' expiration claims fail closed without performing unnecessary key work.
#'
#' @param oauth_client [OAuthClient] object.
#' @param claims Parsed JARM claim list.
#' @return Named list with the validated `iss`, `aud`, and `exp` values.
#' @keywords internal
#' @noRd
validate_jarm_pre_signature_claims <- function(oauth_client, claims) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is.list(claims)) {
    err_invalid_state("JARM payload must be a JSON object")
  }

  iss <- jarm_claim(claims, "iss")
  aud <- jarm_claim(claims, "aud")
  exp <- jarm_claim(claims, "exp")

  issuer <- oauth_client@provider@issuer %||% NA_character_
  if (!is_valid_string(iss)) {
    err_invalid_state("JARM payload missing required iss claim")
  }
  if (!identical(iss, issuer)) {
    err_invalid_state("JARM issuer does not match provider issuer")
  }

  if (
    !(is.character(aud) &&
      length(aud) >= 1L &&
      !anyNA(aud) &&
      all(nzchar(aud)))
  ) {
    err_invalid_state("JARM aud claim is invalid")
  }
  if (!(oauth_client@client_id %in% aud)) {
    err_invalid_state("JARM aud claim does not include client_id")
  }

  if (is.null(exp)) {
    err_invalid_state("JARM payload missing required exp claim")
  }
  if (!jwt_is_single_finite_number(exp)) {
    err_invalid_state("JARM exp claim must be a single finite number")
  }

  now <- floor(as.numeric(Sys.time()))
  leeway <- as.numeric(oauth_client@provider@leeway %||% 0)
  if (!is.finite(leeway) || is.na(leeway) || length(leeway) != 1L) {
    leeway <- 0
  }
  if (as.numeric(exp) < (now - leeway)) {
    err_invalid_state("JARM payload expired")
  }

  list(iss = iss, aud = aud, exp = exp)
}

#' Validate required JARM claims and normalize one response payload
#'
#' Used after optional decryption and required signature verification.
#'
#' @param oauth_client [OAuthClient] object.
#' @param claims Parsed JARM claim list.
#' @param prechecked Optional result from validate_jarm_pre_signature_claims().
#' @return Normalized callback payload list.
#' @keywords internal
#' @noRd
validate_jarm_claims <- function(oauth_client, claims, prechecked = NULL) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  if (!is.list(claims)) {
    err_invalid_state("JARM payload must be a JSON object")
  }

  prechecked <- prechecked %||%
    validate_jarm_pre_signature_claims(
      oauth_client,
      claims
    )

  iss <- prechecked$iss
  iat <- jarm_claim(claims, "iat")
  nbf <- jarm_claim(claims, "nbf")
  code <- jarm_claim(claims, "code")
  state <- jarm_claim(claims, "state")
  error <- jarm_claim(claims, "error")
  error_description <- jarm_claim(claims, "error_description")
  error_uri <- jarm_claim(claims, "error_uri")
  limits <- oauth_callback_limits()

  now <- floor(as.numeric(Sys.time()))
  leeway <- as.numeric(oauth_client@provider@leeway %||% 0)
  if (!is.finite(leeway) || is.na(leeway) || length(leeway) != 1L) {
    leeway <- 0
  }
  if (!is.null(iat) && !jwt_is_single_finite_number(iat)) {
    err_invalid_state("JARM iat claim must be a single finite number")
  }
  if (!is.null(iat) && as.numeric(iat) > (now + leeway)) {
    err_invalid_state("JARM payload issued in the future")
  }
  if (!is.null(nbf) && !jwt_is_single_finite_number(nbf)) {
    err_invalid_state("JARM nbf claim must be a single finite number")
  }
  if (!is.null(nbf) && as.numeric(nbf) > (now + leeway)) {
    err_invalid_state("JARM payload is not yet valid")
  }

  validate_untrusted_query_param("code", code, limits$code)
  validate_untrusted_query_param("state", state, limits$state)
  validate_untrusted_query_param("error", error, limits$error)
  validate_untrusted_query_param(
    "error_description",
    error_description,
    max_bytes = limits$error_description,
    allow_empty = TRUE
  )
  validate_untrusted_query_param(
    "error_uri",
    error_uri,
    max_bytes = limits$error_uri,
    allow_empty = TRUE
  )

  has_code <- !is.null(code)
  has_error <- !is.null(error)
  if (isTRUE(has_code) && isTRUE(has_error)) {
    err_invalid_state("JARM payload must not contain both code and error")
  }
  if (!isTRUE(has_code) && !isTRUE(has_error)) {
    err_invalid_state("JARM payload missing code or error")
  }

  compact_list(list(
    type = if (isTRUE(has_error)) "error" else "code",
    code = code,
    state = state,
    iss = iss,
    error = error,
    error_description = error_description,
    error_uri = error_uri,
    claims = claims
  ))
}

#' Parse a JARM payload with optional duplicate-`iss` interoperability handling
#'
#' Preserve strict duplicate-member rejection by default, and only collapse
#' repeated identical top-level `iss` members when the caller has explicitly
#' enabled this narrow interoperability workaround.
#'
#' @param jwt_str Compact JWS string.
#' @param tolerate_duplicate_top_level_iss Whether to collapse repeated
#'   identical top-level `iss` members before parsing.
#' @return Parsed JARM claim object.
#' @keywords internal
#' @noRd
parse_jarm_payload <- function(
  jwt_str,
  tolerate_duplicate_top_level_iss = FALSE
) {
  parts <- jwt_compact_parts(jwt_str)
  payload_text <- strict_decode_jwt_json_text(parts$payload_raw, "payload")
  if (isTRUE(tolerate_duplicate_top_level_iss)) {
    payload_text <- normalize_duplicate_jarm_iss_claim(payload_text)
  }
  reject_duplicate_json_object_members(payload_text, "JWT payload")
  assert_json_text_is_object(payload_text, "JWT payload")

  tryCatch(
    jsonlite::fromJSON(payload_text, simplifyVector = TRUE),
    error = function(e) {
      err_parse(c(
        "Failed to parse JWT payload JSON",
        "i" = conditionMessage(e)
      ))
    }
  )
}

#' Collapse repeated identical JARM iss members emitted by Keycloak
#'
#' @param payload_text UTF-8 JSON object text.
#' @return JSON text with duplicate identical `iss` members removed.
#' @keywords internal
#' @noRd
normalize_duplicate_jarm_iss_claim <- function(payload_text) {
  stopifnot(
    is.character(payload_text),
    length(payload_text) == 1L,
    !is.na(payload_text)
  )

  duplicate_check <- tryCatch(
    {
      reject_duplicate_json_object_members(payload_text, "JWT payload")
      NULL
    },
    error = identity
  )
  if (
    is.null(duplicate_check) ||
      !grepl(
        "duplicate member name: iss",
        conditionMessage(duplicate_check),
        fixed = TRUE
      )
  ) {
    return(payload_text)
  }

  chars <- strsplit(enc2utf8(payload_text), "", fixed = TRUE)[[1]]

  parse_json_string_token <- function(start_index) {
    if (
      start_index > length(chars) ||
        !identical(chars[[start_index]], '"')
    ) {
      return(NULL)
    }

    token <- character(0)
    index <- start_index + 1L
    escaping <- FALSE

    while (index <= length(chars)) {
      ch <- chars[[index]]
      if (isTRUE(escaping)) {
        token <- c(token, ch)
        escaping <- FALSE
      } else if (identical(ch, "\\")) {
        token <- c(token, ch)
        escaping <- TRUE
      } else if (identical(ch, '"')) {
        return(list(
          end = index,
          value = jwt_decode_json_string_token(paste(token, collapse = ""))
        ))
      } else {
        token <- c(token, ch)
      }
      index <- index + 1L
    }

    NULL
  }

  find_top_level_jarm_iss_members <- function() {
    index <- 1L
    container_stack <- character(0)
    members <- list()

    while (index <= length(chars)) {
      ch <- chars[[index]]

      if (identical(ch, '"')) {
        token_start <- index
        parsed_key <- parse_json_string_token(index)
        if (is.null(parsed_key)) {
          return(list())
        }

        lookahead <- parsed_key$end + 1L
        while (
          lookahead <= length(chars) &&
            grepl("[[:space:]]", chars[[lookahead]])
        ) {
          lookahead <- lookahead + 1L
        }

        if (
          length(container_stack) == 1L &&
            identical(container_stack[[1L]], "object") &&
            lookahead <= length(chars) &&
            identical(chars[[lookahead]], ":") &&
            identical(parsed_key$value, "iss")
        ) {
          value_start <- lookahead + 1L
          while (
            value_start <= length(chars) &&
              grepl("[[:space:]]", chars[[value_start]])
          ) {
            value_start <- value_start + 1L
          }

          parsed_value <- parse_json_string_token(value_start)
          if (is.null(parsed_value)) {
            return(list())
          }

          members[[length(members) + 1L]] <- list(
            start = token_start,
            end = parsed_value$end,
            value = parsed_value$value
          )
        }

        index <- parsed_key$end
      } else if (identical(ch, "{")) {
        container_stack <- c(container_stack, "object")
      } else if (identical(ch, "[")) {
        container_stack <- c(container_stack, "array")
      } else if (identical(ch, "}") || identical(ch, "]")) {
        if (length(container_stack) > 0L) {
          container_stack <- container_stack[-length(container_stack)]
        }
      }

      index <- index + 1L
    }

    members
  }

  members <- find_top_level_jarm_iss_members()
  if (length(members) <= 1L) {
    return(payload_text)
  }

  values <- vapply(members, `[[`, character(1), "value")
  if (!all(vapply(values, identical, logical(1), values[[1]]))) {
    return(payload_text)
  }

  normalized <- payload_text
  duplicate_indices <- rev(seq_along(members)[-1L])
  for (idx in duplicate_indices) {
    remove_start <- members[[idx]]$start
    remove_end <- members[[idx]]$end

    before <- remove_start - 1L
    while (
      before >= 1L &&
        grepl("[[:space:]]", substr(normalized, before, before))
    ) {
      before <- before - 1L
    }

    if (before >= 1L && identical(substr(normalized, before, before), ",")) {
      remove_start <- before
    } else {
      after <- remove_end + 1L
      while (
        after <= nchar(normalized) &&
          grepl("[[:space:]]", substr(normalized, after, after))
      ) {
        after <- after + 1L
      }
      if (
        after <= nchar(normalized) &&
          identical(substr(normalized, after, after), ",")
      ) {
        remove_end <- after
      }
    }

    normalized <- paste0(
      substr(normalized, 1L, remove_start - 1L),
      substr(normalized, remove_end + 1L, nchar(normalized))
    )
  }

  normalized_duplicate_check <- tryCatch(
    {
      reject_duplicate_json_object_members(normalized, "JWT payload")
      NULL
    },
    error = identity
  )
  if (!is.null(normalized_duplicate_check)) {
    return(payload_text)
  }

  normalized
}

## 1.3 Main validation entry point --------------------------------------------

#' Validate the protected header on one encrypted JARM response
#'
#' Used before JWE decryption so unsupported critical extensions, missing
#' nested-JWT signaling, and configured decryption-key mismatches fail closed on
#' the outer object.
#'
#' @param header Parsed JWE protected header.
#' @param encryption_config Named list from
#'   resolve_authorization_response_encryption_config().
#' @return Normalized outer JWE header fields.
#' @keywords internal
#' @noRd
validate_encrypted_jarm_protected_header <- function(
  header,
  encryption_config
) {
  stopifnot(is.list(encryption_config))

  header_fields <- validate_jose_header_fields(
    header,
    signal_error = err_invalid_state
  )
  enc <- jwt_validate_scalar_string_field(
    header$enc %||% NULL,
    "enc",
    signal_error = err_invalid_state,
    required = TRUE
  )
  cty <- jwt_validate_scalar_string_field(
    header$cty %||% NULL,
    "cty",
    signal_error = err_invalid_state
  )

  if (!is.null(header_fields$crit) && length(header_fields$crit) > 0L) {
    err_invalid_state(paste0(
      "Encrypted JARM contains unsupported critical header parameter(s): ",
      paste(header_fields$crit, collapse = ", ")
    ))
  }

  if (is.null(cty)) {
    err_invalid_state("Encrypted JARM missing required cty header 'JWT'")
  }
  if (!identical(toupper(cty), "JWT")) {
    err_invalid_state(paste0(
      "Encrypted JARM cty header invalid: expected 'JWT', got ",
      cty
    ))
  }

  configured_kid <- encryption_config$kid %||% NA_character_
  if (is_valid_string(configured_kid)) {
    header_kid <- header_fields$kid %||% "<missing>"
    if (!identical(header_kid, configured_kid)) {
      err_invalid_state(paste0(
        "Encrypted JARM kid mismatch: expected ",
        configured_kid,
        ", got ",
        header_kid
      ))
    }
  }

  c(header_fields, list(enc = enc, cty = cty))
}

#' Validate a JWT Secured Authorization Response (JARM)
#'
#' Used by callback handling before any OAuth state, PKCE, or token-exchange
#' logic runs.
#'
#' @param oauth_client [OAuthClient] object.
#' @param response Compact JARM JWT string.
#' @return Normalized callback payload list.
#' @keywords internal
#' @noRd
validate_jarm_response <- function(
  oauth_client,
  response,
  transport = c("query", "form_post")
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)
  transport <- match.arg(transport)

  configured_transport <- resolve_jarm_callback_transport(oauth_client)
  if (is.null(configured_transport)) {
    err_invalid_state("Client is not configured to accept JARM responses")
  }
  if (!identical(configured_transport$transport, transport)) {
    err_invalid_state(paste0(
      "JARM callback transport mismatch: client requested ",
      configured_transport$mode,
      " but callback arrived via ",
      transport
    ))
  }

  limits <- oauth_callback_limits()
  validate_untrusted_query_param(
    "response",
    response,
    max_bytes = max(limits$query, limits$form_post_body)
  )
  if (!is_valid_string(response)) {
    err_invalid_state("JARM response must be a single non-empty compact JWT")
  }

  encryption_config <- resolve_authorization_response_encryption_config(
    oauth_client
  )
  jwt_str <- response
  if (length(strsplit(response, ".", fixed = TRUE)[[1]]) == 5L) {
    if (is.null(encryption_config)) {
      err_invalid_state(
        "Received encrypted JARM response but client is not configured for JARM decryption"
      )
    }

    jwe_parts <- tryCatch(
      jwe_compact_parts(response),
      error = function(e) {
        err_invalid_state(paste0(
          "Encrypted JARM response could not be parsed: ",
          conditionMessage(e)
        ))
      }
    )
    outer_header_fields <- validate_encrypted_jarm_protected_header(
      jwe_parts$protected_header,
      encryption_config
    )
    outer_alg <- canonicalize_jwe_alg(
      outer_header_fields$alg %||% ""
    )
    outer_enc <- canonicalize_jwe_enc(
      outer_header_fields$enc %||% ""
    )
    if (!identical(outer_alg, encryption_config$alg)) {
      err_invalid_state(paste0(
        "Encrypted JARM alg mismatch: expected ",
        encryption_config$alg,
        ", got ",
        outer_alg
      ))
    }
    if (!identical(outer_enc, encryption_config$enc)) {
      err_invalid_state(paste0(
        "Encrypted JARM enc mismatch: expected ",
        encryption_config$enc,
        ", got ",
        outer_enc
      ))
    }

    decrypted <- tryCatch(
      jwe_compact_decrypt(
        response,
        encryption_config$private_key
      ),
      error = function(e) {
        err_invalid_state(paste0(
          "Encrypted JARM response could not be decrypted: ",
          conditionMessage(e)
        ))
      }
    )
    jwt_str <- decrypted$plaintext %||% NA_character_
    if (!is_valid_string(jwt_str)) {
      err_invalid_state("Encrypted JARM plaintext is not a valid compact JWT")
    }
  } else if (!is.null(encryption_config)) {
    err_invalid_state(
      "Client expects encrypted JARM responses but callback response was not encrypted"
    )
  }

  header <- tryCatch(
    parse_jwt_header(jwt_str),
    error = function(e) {
      err_invalid_state(paste0(
        "JARM header could not be parsed: ",
        conditionMessage(e)
      ))
    }
  )
  header_fields <- validate_jose_header_fields(
    header,
    signal_error = err_invalid_state
  )
  if (!is.null(header_fields$crit) && length(header_fields$crit) > 0L) {
    err_invalid_state(paste0(
      "JARM contains unsupported critical header parameter(s): ",
      paste(header_fields$crit, collapse = ", ")
    ))
  }

  alg <- canonicalize_jws_alg(header_fields$alg)
  expected_alg <- resolve_authorization_response_signing_alg(oauth_client)
  if (identical(toupper(alg), "NONE")) {
    err_invalid_state("JARM alg=none is not allowed")
  }
  if (!identical(alg, expected_alg)) {
    err_invalid_state(paste0(
      "JARM signing alg mismatch: expected ",
      expected_alg,
      ", got ",
      alg
    ))
  }

  claims <- tryCatch(
    parse_jarm_payload(
      jwt_str,
      tolerate_duplicate_top_level_iss = isTRUE(
        oauth_client@provider@tolerate_duplicate_top_level_jarm_iss
      )
    ),
    error = function(e) {
      err_invalid_state(paste0(
        "JARM payload could not be parsed: ",
        conditionMessage(e)
      ))
    }
  )
  claims <- as.list(claims)
  prechecked <- validate_jarm_pre_signature_claims(oauth_client, claims)

  verify_jarm_signature(
    oauth_client = oauth_client,
    jwt_str = jwt_str,
    alg = alg,
    kid = header_fields$kid %||% NULL
  )

  validate_jarm_claims(oauth_client, claims, prechecked = prechecked)
}
