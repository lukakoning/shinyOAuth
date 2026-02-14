#' Get user info from OAuth 2.0 provider
#'
#' @description
#' Fetches user information from the provider's userinfo endpoint using the
#' provided access token. Emits an audit event with redacted details.
#'
#' @param oauth_client [OAuthClient] object. The client must have a
#' `userinfo_url` configured in its [OAuthProvider].
#' @param token Either an [OAuthToken] object or a raw access token string.
#'
#' @return A list containing the user information as returned by the provider.
#'
#' @example inst/examples/token_methods.R
#'
#' @export
get_userinfo <- function(
  oauth_client,
  token
) {
  # Type checks/helpers --------------------------------------------------------

  S7::check_is_S7(oauth_client, OAuthClient)

  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
  } else {
    access_token <- token
  }

  if (!is_valid_string(access_token)) {
    err_input("access_token must be a non-empty string")
  }

  if (!is_valid_string(oauth_client@provider@userinfo_url)) {
    err_config("provider userinfo_url is not configured")
  }

  # Main logic -----------------------------------------------------------------

  # Define request; disable redirects to prevent leaking Bearer token
  req <- httr2::request(oauth_client@provider@userinfo_url) |>
    httr2::req_auth_bearer_token(access_token) |>
    add_req_defaults() |>
    req_no_redirect()

  # Execute request
  resp <- try(req_with_retry(req), silent = TRUE)

  # Security: reject redirect responses to prevent leaking Bearer token
  if (!inherits(resp, "try-error")) {
    reject_redirect_response(resp, context = "userinfo")
  }

  # Check for errors
  if (inherits(resp, "try-error") || httr2::resp_is_error(resp)) {
    if (inherits(resp, "try-error")) {
      err_userinfo(c(
        "x" = "Failed to get user info",
        "!" = conditionMessage(attr(resp, "condition"))
      ))
    } else {
      err_http(
        c("x" = "Failed to get user info"),
        resp,
        context = list(phase = "userinfo")
      )
    }
  }

  # Detect Content-Type to handle JWT-encoded userinfo (OIDC Core §5.3.2)
  resp_ct <- try(httr2::resp_content_type(resp), silent = TRUE)
  if (inherits(resp_ct, "try-error")) {
    resp_ct <- NA_character_
  }
  is_jwt_response <- is_valid_string(resp_ct) &&
    grepl("^application/jwt", resp_ct, ignore.case = TRUE)

  require_signed <- isTRUE(oauth_client@provider@userinfo_signed_jwt_required)

  # Enforce signed JWT requirement: if the provider mandates application/jwt
  # but the response is not application/jwt, fail immediately.
  if (require_signed && !is_jwt_response) {
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "userinfo_not_jwt",
          content_type = if (is_valid_string(resp_ct)) {
            resp_ct
          } else {
            NA_character_
          }
        )
      ),
      silent = TRUE
    )
    err_userinfo(c(
      "x" = "UserInfo response is not application/jwt but signed JWT is required",
      "i" = paste0(
        "Content-Type: ",
        if (is_valid_string(resp_ct)) resp_ct else "<not available>"
      ),
      "i" = "The provider's userinfo_signed_jwt_required = TRUE mandates a signed JWT response",
      "i" = "Verify the provider is configured to return signed JWTs from its userinfo endpoint"
    ))
  }

  # Guard against oversized responses before parsing
  check_resp_body_size(resp, context = "userinfo")

  # Parse from response
  if (is_jwt_response) {
    ui <- try(
      decode_userinfo_jwt(resp, oauth_client),
      silent = TRUE
    )
  } else {
    ui <- try(httr2::resp_body_json(resp, simplifyVector = TRUE), silent = TRUE)
  }
  if (inherits(ui, "try-error")) {
    # Extract non-sensitive context to aid debugging without leaking tokens
    url <- try(httr2::resp_url(resp), silent = TRUE)
    if (inherits(url, "try-error")) {
      url <- NA_character_
    }
    status <- try(httr2::resp_status(resp), silent = TRUE)
    if (inherits(status, "try-error")) {
      status <- NA_integer_
    }
    headers <- try(httr2::resp_headers(resp), silent = TRUE)
    ct <- NA_character_
    if (!inherits(headers, "try-error") && is.list(headers)) {
      ct <- headers[["content-type"]] %||% NA_character_
    }
    body_str <- try(httr2::resp_body_string(resp), silent = TRUE)
    if (inherits(body_str, "try-error")) {
      body_str <- NA_character_
    }
    body_digest <- NA_character_
    if (is_valid_string(body_str)) {
      dig <- try(openssl::sha256(charToRaw(body_str)), silent = TRUE)
      if (!inherits(dig, "try-error")) {
        body_digest <- paste0(sprintf("%02x", as.integer(dig)), collapse = "")
      }
    }

    # Emit audit event even on parse failures
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "parse_error",
          http_status = status,
          url = url,
          content_type = ct,
          body_digest = body_digest
        )
      ),
      silent = TRUE
    )

    parse_type <- if (is_jwt_response) "jwt" else "json"
    err_userinfo(
      c(
        "x" = if (is_jwt_response) {
          "Failed to parse userinfo response as JWT"
        } else {
          "Failed to parse userinfo response as JSON"
        },
        "!" = conditionMessage(attr(ui, "condition")),
        "i" = if (is_valid_string(ct)) paste0("Content-Type: ", ct) else NULL,
        "i" = if (!is.na(status)) paste0("Status: ", status) else NULL,
        "i" = if (is_valid_string(url)) paste0("URL: ", url) else NULL
      ),
      context = list(
        phase = "userinfo",
        parse = parse_type,
        http_status = status,
        url = url,
        content_type = ct,
        body_digest = body_digest
      )
    )
  }

  # Emit audit event for userinfo fetch (redacted)
  subject <- try(oauth_client@provider@userinfo_id_selector(ui), silent = TRUE)
  if (inherits(subject, "try-error")) {
    subject <- ui$sub %||% NA_character_
  }
  try(
    audit_event(
      "userinfo",
      context = list(
        provider = oauth_client@provider@name %||% NA_character_,
        issuer = oauth_client@provider@issuer %||% NA_character_,
        client_id_digest = string_digest(oauth_client@client_id),
        sub_digest = string_digest(subject),
        status = "ok"
      )
    ),
    silent = TRUE
  )

  return(ui)
}

#' Internal: decode JWT-encoded userinfo response (OIDC Core §5.3.2)
#'
#' When the UserInfo endpoint returns Content-Type: application/jwt, the
#' response body is a signed (and optionally encrypted) JWT whose payload
#' contains the claims.
#'
#' Per §5.3.2, if the JWT is signed, the claims MUST include `iss` (matching
#' the OP's Issuer Identifier) and `aud` (matching or including the RP's
#' Client ID). These are validated after successful signature verification.
#'
#' Encrypted JWTs (JWE, 5-part compact serialization) are detected and
#' rejected with a clear error since JWE decryption is not supported.
#'
#' Signature verification uses the provider's `allowed_algs` (filtered to
#' asymmetric algorithms) and fail-closes unconditionally: if the JWKS
#' cannot be fetched, no compatible keys exist, or all candidate keys fail
#' verification, an error is raised.
#'
#' Verification is always enforced when a JWT response is received,
#' regardless of `userinfo_signed_jwt_required`. That flag only controls
#' whether the response *must* be `application/jwt` (vs. JSON).
#' `alg=none` is always rejected unless the testing-only softener
#' `allow_unsigned_userinfo_jwt()` permits it (requires test or interactive mode).
#' Unparseable headers, missing issuer/JWKS infrastructure, and algorithms
#' not in `allowed_algs` all raise errors with audit events.
#'
#' @param resp An httr2 response object with a JWT body.
#' @param oauth_client An OAuthClient object (used for JWKS-based verification).
#' @return A named list of userinfo claims.
#' @keywords internal
#' @noRd
decode_userinfo_jwt <- function(resp, oauth_client) {
  jwt_str <- httr2::resp_body_string(resp)

  if (!is_valid_string(jwt_str)) {
    err_userinfo("UserInfo JWT response body is empty")
  }

  # Trim whitespace that some servers may include
  jwt_str <- trimws(jwt_str)

  # Detect JWE (encrypted JWT): 5 dot-separated parts per RFC 7516 §3.
  # We do not support JWE decryption; surface a clear error.
  n_parts <- length(strsplit(jwt_str, ".", fixed = TRUE)[[1]])
  if (n_parts == 5L) {
    err_userinfo(c(
      "x" = "UserInfo response is an encrypted JWT (JWE)",
      "i" = "JWE decryption is not supported; configure the provider to return signed-only or plain JSON userinfo"
    ))
  }

  prov <- oauth_client@provider

  # Parse JWT header — always required for application/jwt responses.
  # If the header cannot be parsed, the JWT cannot be verified or trusted.
  header <- try(parse_jwt_header(jwt_str), silent = TRUE)

  if (inherits(header, "try-error")) {
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = prov@name %||% NA_character_,
          issuer = prov@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "userinfo_jwt_header_parse_failed"
        )
      ),
      silent = TRUE
    )
    err_userinfo(c(
      "x" = "UserInfo JWT header could not be parsed",
      "i" = "A well-formed JWT header is required for verification (OIDC Core 5.3.2)"
    ))
  }

  # RFC 7515 s4.1.11: reject tokens that carry critical header parameters we
  # do not support (mirrors the same check in validate_id_token()).
  supported_crit <- character()
  crit <- header$crit
  if (!is.null(crit)) {
    if (
      !is.character(crit) ||
        length(crit) == 0L ||
        anyNA(crit) ||
        !all(nzchar(crit))
    ) {
      err_userinfo(
        "JWT crit header must be a non-empty character vector of extension names"
      )
    }
    unsupported <- setdiff(crit, supported_crit)
    if (length(unsupported) > 0L) {
      err_userinfo(paste0(
        "JWT contains unsupported critical header parameter(s): ",
        paste(unsupported, collapse = ", ")
      ))
    }
  }

  alg <- toupper(header$alg %||% "")
  kid <- header$kid %||% NULL

  # Always reject alg=none — unsigned JWTs cannot be trusted for userinfo.

  # Testing-only escape hatch, gated via allow_unsigned_userinfo_jwt() softener
  if (alg == "" || alg == "NONE") {
    if (allow_unsigned_userinfo_jwt()) {
      payload <- parse_jwt_payload(jwt_str)
      return(as.list(payload))
    }
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = prov@name %||% NA_character_,
          issuer = prov@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "userinfo_jwt_unsigned",
          jwt_alg = alg
        )
      ),
      silent = TRUE
    )
    err_userinfo(c(
      "x" = "UserInfo JWT uses alg=none which is not allowed (OIDC Core 5.3.2)",
      "i" = "The provider must sign userinfo JWTs with an asymmetric algorithm"
    ))
  }

  # Use provider's allowed_algs for algorithm enforcement (filtering to
  # asymmetric only, since HMAC is not supported for userinfo JWTs)
  asymmetric_algs <- intersect(
    toupper(prov@allowed_algs),
    c(
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
      "ES256",
      "ES384",
      "ES512",
      "EDDSA"
    )
  )

  # Always enforce algorithm is in allowed asymmetric algs
  if (!(alg %in% asymmetric_algs)) {
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = prov@name %||% NA_character_,
          issuer = prov@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "userinfo_jwt_alg_rejected",
          jwt_alg = alg
        )
      ),
      silent = TRUE
    )
    err_userinfo(c(
      "x" = paste0(
        "UserInfo JWT algorithm '",
        alg,
        "' is not in provider's allowed asymmetric algorithms"
      ),
      "i" = paste0(
        "Allowed algorithms: ",
        paste(asymmetric_algs, collapse = ", ")
      ),
      "i" = "Adjust the provider's allowed_algs if this algorithm should be permitted"
    ))
  }

  # Issuer must be configured for JWKS-based verification
  if (!is_valid_string(prov@issuer) || is.na(prov@issuer)) {
    try(
      audit_event(
        "userinfo",
        context = list(
          provider = prov@name %||% NA_character_,
          issuer = NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = NA_character_,
          status = "userinfo_jwt_no_issuer"
        )
      ),
      silent = TRUE
    )
    err_userinfo(c(
      "x" = "Provider issuer is not configured but is required for UserInfo JWT verification",
      "i" = "A valid issuer URL is required for JWKS-based signature verification (OIDC Core 5.3.2)",
      "i" = "Set the provider's issuer (or use OIDC discovery) to enable JWKS verification"
    ))
  }

  # Verify signature against JWKS
  jwks <- try(
    fetch_jwks(
      prov@issuer,
      prov@jwks_cache,
      pins = prov@jwks_pins %||% character(),
      pin_mode = prov@jwks_pin_mode %||% "any",
      provider = prov
    ),
    silent = TRUE
  )
  if (inherits(jwks, "try-error")) {
    # JWKS fetch failed — fail closed.
    err_userinfo(c(
      "x" = "UserInfo JWT signature could not be verified: JWKS fetch failed",
      "i" = "The provider JWKS endpoint could not be reached or returned an error",
      "i" = "Signature verification is required for signed UserInfo JWTs (OIDC Core 5.3.2)"
    ))
  }
  keys <- select_candidate_jwks(
    jwks,
    header_alg = alg,
    kid = kid,
    pins = prov@jwks_pins %||% character()
  )

  # One-shot JWKS refresh-on-kid-miss: if kid is present but no candidate keys
  # match, force-refresh JWKS once then re-select (mirrors validate_id_token()).
  if (length(keys) == 0L && !is.null(kid)) {
    if (
      isTRUE(jwks_force_refresh_allowed(
        prov@issuer,
        prov@jwks_cache,
        pins = prov@jwks_pins %||% character(),
        pin_mode = prov@jwks_pin_mode %||% "any",
        min_interval = 30,
        jwks_host_issuer_match = isTRUE(try(
          prov@jwks_host_issuer_match,
          silent = TRUE
        )),
        jwks_host_allow_only = {
          ao <- try(prov@jwks_host_allow_only, silent = TRUE)
          if (inherits(ao, "try-error")) NA_character_ else ao
        }
      ))
    ) {
      jwks <- try(
        fetch_jwks(
          prov@issuer,
          prov@jwks_cache,
          force_refresh = TRUE,
          pins = prov@jwks_pins %||% character(),
          pin_mode = prov@jwks_pin_mode %||% "any",
          provider = prov
        ),
        silent = TRUE
      )
      if (!inherits(jwks, "try-error")) {
        keys <- select_candidate_jwks(
          jwks,
          header_alg = alg,
          kid = kid,
          pins = prov@jwks_pins %||% character()
        )
      }
    }
  }

  if (length(keys) > 0L) {
    for (jk in keys) {
      pub <- try(jwk_to_pubkey(jk), silent = TRUE)
      if (inherits(pub, "try-error")) {
        next
      }
      decoded <- try(jose::jwt_decode_sig(jwt_str, pub), silent = TRUE)
      if (!inherits(decoded, "try-error")) {
        claims <- as.list(decoded)
        # §5.3.2 MUST: signed userinfo MUST contain iss matching the
        # OP's Issuer Identifier and aud matching/including the RP's
        # Client ID.
        validate_signed_userinfo_claims(
          claims,
          expected_issuer = prov@issuer,
          expected_client_id = oauth_client@client_id
        )
        return(claims)
      }
    }
    # Candidate keys existed but none verified the signature —
    # this indicates tampering or serious misconfiguration.
    err_userinfo(c(
      "x" = "UserInfo JWT signature is invalid",
      "i" = "Signature could not be verified against any candidate JWKS key"
    ))
  }
  # No compatible candidate keys in JWKS — fail closed.
  err_userinfo(c(
    "x" = "UserInfo JWT signature could not be verified: no compatible keys in provider JWKS",
    "i" = "Signature verification is required for signed UserInfo JWTs (OIDC Core 5.3.2)"
  ))
}

#' Internal: validate iss/aud claims in a signed UserInfo JWT (§5.3.2)
#'
#' @param claims Named list of JWT claims.
#' @param expected_issuer The OP's Issuer Identifier URL.
#' @param expected_client_id The RP's Client ID.
#' @keywords internal
#' @noRd
validate_signed_userinfo_claims <- function(
  claims,
  expected_issuer,
  expected_client_id
) {
  # iss MUST be present and match the OP's Issuer Identifier
  iss <- claims$iss
  if (!is_valid_string(iss)) {
    err_userinfo(c(
      "x" = "Signed UserInfo JWT missing required 'iss' claim (OIDC Core 5.3.2)"
    ))
  }
  # Strict string equality — no trailing-slash normalization (OIDC Core §3.1.3.7).
  if (!identical(iss, expected_issuer)) {
    err_userinfo(c(
      "x" = "Signed UserInfo JWT 'iss' claim does not match provider issuer (OIDC Core 5.3.2)",
      "i" = paste0("Expected: ", expected_issuer),
      "i" = paste0("Got: ", iss)
    ))
  }

  # aud MUST be or include the RP's Client ID
  aud <- claims$aud
  if (
    is.null(aud) ||
      (is.character(aud) && (length(aud) == 0L || !any(nzchar(aud))))
  ) {
    err_userinfo(c(
      "x" = "Signed UserInfo JWT missing required 'aud' claim (OIDC Core 5.3.2)"
    ))
  }
  if (!is.character(aud) || !(expected_client_id %in% aud)) {
    err_userinfo(c(
      "x" = "Signed UserInfo JWT 'aud' claim does not include client_id (OIDC Core 5.3.2)",
      "i" = paste0("Expected client_id: ", expected_client_id),
      "i" = paste0("Got aud: ", paste(aud, collapse = ", "))
    ))
  }

  invisible(TRUE)
}

verify_userinfo_id_token_subject_match <- function(
  oauth_client,
  userinfo,
  id_token
) {
  # Type checks/helpers --------------------------------------------------------

  S7::check_is_S7(oauth_client, OAuthClient)

  if (!is.list(userinfo) || length(userinfo) == 0) {
    err_input("userinfo must be a non-empty list")
  }

  if (!is_valid_string(id_token)) {
    err_input("id_token must be a valid string")
  }

  if (
    is.null(oauth_client@provider@userinfo_id_selector) ||
      !is.function(oauth_client@provider@userinfo_id_selector)
  ) {
    err_config("provider userinfo_id_selector is not configured")
  }

  # Compare -----------------------------------------------------------------

  # Parse id_token payload without re-validating signature
  # (already validated in earlier step)
  id_payload <- try(parse_jwt_payload(id_token), silent = TRUE)

  if (inherits(id_payload, "try-error")) {
    err_userinfo(c(
      "x" = "Failed to parse id_token payload",
      "i" = "Needed for userinfo/ID token subject check"
    ))
  }

  id_sub <- id_payload$sub
  ui_val <- oauth_client@provider@userinfo_id_selector(userinfo)

  # Validate selector output before comparison; coerce safely and fail with
  # a targeted message if inappropriate
  if (is.null(ui_val) || length(ui_val) == 0) {
    err_userinfo(c(
      "x" = "userinfo_id_selector returned no value",
      "i" = "Expected a scalar string"
    ))
  }
  # If selector returns a vector/list, take the first element but require it's
  # a non-empty scalar character after coercion. If multiple, raise a
  # targeted error to aid debugging rather than silently truncating.
  if (length(ui_val) > 1) {
    err_userinfo(c(
      "x" = "userinfo_id_selector returned multiple values",
      "i" = "Expected a scalar string"
    ))
  }
  # Coerce to character(1) where possible (e.g., numeric ids)
  if (!is.character(ui_val)) {
    ui_val <- try(as.character(ui_val), silent = TRUE)
    if (inherits(ui_val, "try-error")) {
      err_userinfo(c(
        "x" = "userinfo_id_selector returned non-coercible value",
        "i" = "Must be coercible to character(1)"
      ))
    }
  }
  ui_sub <- ui_val[[1]]

  if (!is_valid_string(id_sub) || !is_valid_string(ui_sub)) {
    err_userinfo("Missing sub claim in id_token or invalid userinfo subject")
  }

  if (!identical(id_sub, ui_sub)) {
    err_userinfo_mismatch("userinfo subject does not match id_token subject")
  }

  return(invisible(TRUE))
}
