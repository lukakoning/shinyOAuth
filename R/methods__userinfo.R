#' Get user info from OAuth 2.0 provider
#'
#' @description
#' Fetches user information from the provider's userinfo endpoint using the
#' provided access token. Emits an audit event with redacted details.
#'
#' @param oauth_client [OAuthClient] object. The client must have a
#' `userinfo_url` configured in its [OAuthProvider].
#' @param token Either an [OAuthToken] object or a raw access token string.
#' @param token_type Optional override for the access token type when `token`
#'   is provided as a raw string. Supported values are `Bearer` and `DPoP`.
#' @param shiny_session Optional pre-captured Shiny session context (from
#'   `capture_shiny_session_context()`) to include in audit events and span
#'   attributes. Used when calling from async workers that lack access to the
#'   reactive domain.
#'
#' @return A list containing the user information as returned by the provider.
#'
#' @example inst/examples/token_methods.R
#'
#' @export
get_userinfo <- function(
  oauth_client,
  token,
  token_type = NULL,
  shiny_session = NULL
) {
  # Type checks/helpers --------------------------------------------------------

  S7::check_is_S7(oauth_client, OAuthClient)

  if (S7::S7_inherits(token, class = OAuthToken)) {
    access_token <- token@access_token
    token_type <- token@token_type %||% token_type
  } else {
    access_token <- token
  }

  if (!is_valid_string(access_token)) {
    err_input("access_token must be a non-empty string")
  }

  if (!is_valid_string(oauth_client@provider@userinfo_url)) {
    err_config("provider userinfo_url is not configured")
  }

  userinfo_url <- resolve_provider_endpoint_url(
    oauth_client@provider,
    "userinfo_endpoint",
    prefer_mtls = token_requires_mtls_sender_constraint(token, oauth_client)
  )

  with_trace_id(
    NULL,
    with_otel_span(
      "shinyOAuth.userinfo",
      {
        # Main logic ---------------------------------------------------------------

        # Define request; disable redirects to prevent leaking the access token.
        req <- client_bearer_req(
          token = token,
          url = userinfo_url,
          oauth_client = oauth_client,
          token_type = token_type
        )

        # Execute request. Let transport failures propagate as
        # shinyOAuth_transport_error so callers can distinguish network issues
        # from HTTP responses returned by the provider.
        resp <- with_otel_span(
          "shinyOAuth.userinfo.http",
          {
            if (is_dpop_token_type(token_type %||% NA_character_)) {
              resp <- req_with_dpop_retry(
                req,
                oauth_client,
                access_token = access_token,
                idempotent = TRUE
              )
            } else {
              resp <- req_with_retry(req, idempotent = TRUE)
            }
            otel_record_http_result(resp)
            resp
          },
          attributes = otel_http_attributes(
            method = "GET",
            url = userinfo_url,
            extra = list(oauth.phase = "userinfo")
          ),
          options = list(kind = "client"),
          mark_ok = FALSE
        )

        # Security: reject redirect responses to prevent leaking Bearer token
        reject_redirect_response(resp, context = "userinfo")

        # HTTP status errors are userinfo endpoint failures, not transport failures.
        if (httr2::resp_is_error(resp)) {
          err_http(
            c("x" = "Failed to get user info"),
            resp,
            context = list(phase = "userinfo")
          )
        }

        # Detect Content-Type to handle JWT-encoded userinfo (OIDC Core §5.3.2)
        resp_ct <- try(httr2::resp_content_type(resp), silent = TRUE)
        if (inherits(resp_ct, "try-error")) {
          resp_ct <- NA_character_
        }
        is_jwt_response <- is_valid_string(resp_ct) &&
          grepl("^application/jwt", resp_ct, ignore.case = TRUE)

        otel_set_span_attributes(
          attributes = list(
            oauth.userinfo.jwt_response = isTRUE(is_jwt_response)
          )
        )

        require_signed <- isTRUE(
          oauth_client@provider@userinfo_signed_jwt_required
        )

        # Enforce signed JWT requirement: if the provider mandates application/jwt
        # but the response is not application/jwt, fail immediately.
        if (require_signed && !is_jwt_response) {
          audit_userinfo_event(
            oauth_client,
            status = "userinfo_not_jwt",
            shiny_session = shiny_session,
            extra = list(
              content_type = if (is_valid_string(resp_ct)) {
                resp_ct
              } else {
                NA_character_
              }
            )
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
            decode_userinfo_jwt(
              resp,
              oauth_client,
              shiny_session = shiny_session
            ),
            silent = TRUE
          )
        } else {
          ui <- try(
            {
              body_txt <- httr2::resp_body_string(resp)
              reject_duplicate_json_object_members(
                body_txt,
                "UserInfo response JSON"
              )
              jsonlite::fromJSON(body_txt, simplifyVector = TRUE)
            },
            silent = TRUE
          )
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
              body_digest <- paste0(
                sprintf("%02x", as.integer(dig)),
                collapse = ""
              )
            }
          }

          # Emit audit event even on parse failures
          audit_userinfo_event(
            oauth_client,
            status = "parse_error",
            shiny_session = shiny_session,
            extra = list(
              http_status = status,
              url = url,
              content_type = ct,
              body_digest = body_digest
            )
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
              "i" = if (is_valid_string(ct)) {
                paste0("Content-Type: ", ct)
              } else {
                NULL
              },
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

        otel_set_span_attributes(
          attributes = list(
            oauth.userinfo.subject_present = isTRUE(is_valid_string(ui$sub))
          )
        )

        # OIDC Core §5.3: "The sub Claim MUST always be returned in the UserInfo
        # Response." Enforce for OIDC providers (issuer configured); leave generic
        # non-OIDC profile endpoints alone.
        if (
          is_valid_string(oauth_client@provider@issuer) &&
            !is.na(oauth_client@provider@issuer)
        ) {
          if (!is_valid_string(ui$sub)) {
            audit_userinfo_event(
              oauth_client,
              status = "userinfo_missing_sub",
              shiny_session = shiny_session
            )
            err_userinfo(c(
              "x" = "UserInfo response missing required 'sub' claim (OIDC Core 5.3)",
              "i" = "OIDC providers MUST always return a 'sub' claim in the UserInfo response"
            ))
          }
        }

        # Emit audit event for userinfo fetch (redacted)
        subject <- try(
          oauth_client@provider@userinfo_id_selector(ui),
          silent = TRUE
        )
        if (inherits(subject, "try-error")) {
          subject <- ui$sub %||% NA_character_
        }
        audit_userinfo_event(
          oauth_client,
          status = "ok",
          sub = subject,
          shiny_session = shiny_session
        )

        ui
      },
      attributes = otel_client_attributes(
        client = oauth_client,
        shiny_session = shiny_session,
        phase = "userinfo",
        extra = list(
          oauth.userinfo.jwt_required = isTRUE(
            oauth_client@provider@userinfo_signed_jwt_required
          )
        )
      )
    )
  )
}

audit_userinfo_event <- function(
  oauth_client,
  status,
  sub = NULL,
  shiny_session = NULL,
  extra = list()
) {
  try(
    audit_event(
      "userinfo",
      context = c(
        list(
          provider = oauth_client@provider@name %||% NA_character_,
          issuer = oauth_client@provider@issuer %||% NA_character_,
          client_id_digest = string_digest(oauth_client@client_id),
          sub_digest = string_digest(sub),
          status = status
        ),
        extra
      ),
      shiny_session = shiny_session
    ),
    silent = TRUE
  )

  invisible(NULL)
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
#' @param shiny_session Optional pre-captured Shiny session context for audit
#'   events emitted during JWT validation.
#' @return A named list of userinfo claims.
#' @keywords internal
#' @noRd
decode_userinfo_jwt <- function(
  resp,
  oauth_client,
  shiny_session = NULL
) {
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
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_encrypted",
      shiny_session = shiny_session
    )
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
    header_reason <- tryCatch(
      conditionMessage(attr(header, "condition")),
      error = function(e) as.character(header)
    )
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_header_parse_failed",
      shiny_session = shiny_session
    )
    err_userinfo(c(
      "x" = "UserInfo JWT header could not be parsed",
      "i" = header_reason,
      "i" = "A well-formed JWT header is required for verification (OIDC Core 5.3.2)"
    ))
  }

  header_fields <- tryCatch(
    validate_jose_header_fields(header, err_userinfo),
    shinyOAuth_userinfo_error = function(e) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_header_invalid",
        shiny_session = shiny_session
      )
      stop(e)
    }
  )

  # Defense-in-depth: if a typ header is present, require it to be exactly
  # "JWT" per RFC 7519. Many providers omit typ; that's fine.
  typ <- header_fields$typ
  if (!is.null(typ)) {
    if (
      !(is.character(typ) &&
        length(typ) == 1L &&
        identical(toupper(typ), "JWT"))
    ) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_typ_invalid",
        shiny_session = shiny_session
      )
      err_userinfo(paste0(
        "JWT typ header invalid: expected 'JWT' when present, got ",
        paste(as.character(typ), collapse = ", ")
      ))
    }
  }

  # RFC 7515 s4.1.11: reject tokens that carry critical header parameters we
  # do not support (mirrors the same check in validate_id_token()).
  supported_crit <- character()
  crit <- header_fields$crit
  if (!is.null(crit)) {
    unsupported <- setdiff(crit, supported_crit)
    if (length(unsupported) > 0L) {
      err_userinfo(paste0(
        "JWT contains unsupported critical header parameter(s): ",
        paste(unsupported, collapse = ", ")
      ))
    }
  }

  alg <- toupper(header_fields$alg)
  kid <- header_fields$kid

  # Always reject alg=none — unsigned JWTs cannot be trusted for userinfo.

  # Testing-only escape hatch, gated via allow_unsigned_userinfo_jwt() softener
  if (alg == "NONE") {
    if (allow_unsigned_userinfo_jwt()) {
      payload <- parse_jwt_payload(jwt_str)
      return(as.list(payload))
    }
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_unsigned",
      shiny_session = shiny_session,
      extra = list(jwt_alg = alg)
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
      "ES256",
      "ES384",
      "ES512",
      "EDDSA"
    )
  )

  # Always enforce algorithm is in allowed asymmetric algs
  if (!(alg %in% asymmetric_algs)) {
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_alg_rejected",
      shiny_session = shiny_session,
      extra = list(jwt_alg = alg)
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
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_no_issuer",
      shiny_session = shiny_session
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
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_jwks_fetch_failed",
      shiny_session = shiny_session
    )
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
  keys <- filter_jwks_for_alg(keys, alg)

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
        issuer_match = provider_issuer_match(prov),
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
        keys <- filter_jwks_for_alg(keys, alg)
      }
    }
  }

  if (length(keys) > 0L) {
    for (jk in keys) {
      pub <- try(jwk_to_pubkey(jk), silent = TRUE)
      if (inherits(pub, "try-error")) {
        next
      }
      if (!isTRUE(verify_jws_signature_no_time(jwt_str, pub, alg))) {
        next
      }

      claims <- try(parse_jwt_payload(jwt_str), silent = TRUE)
      if (inherits(claims, "try-error")) {
        audit_userinfo_event(
          oauth_client,
          status = "userinfo_jwt_payload_parse_failed",
          shiny_session = shiny_session
        )
        err_userinfo(c(
          "x" = "UserInfo JWT payload could not be parsed",
          "i" = tryCatch(
            conditionMessage(attr(claims, "condition")),
            error = function(e) as.character(claims)
          )
        ))
      }

      claims <- as.list(claims)
      # §5.3.2 MUST: signed userinfo MUST contain iss matching the
      # OP's Issuer Identifier and aud matching/including the RP's
      # Client ID. Temporal validation is delegated here so provider leeway
      # is applied consistently across signed UserInfo JWT verification.
      validate_signed_userinfo_claims(
        claims,
        expected_issuer = prov@issuer,
        expected_client_id = oauth_client@client_id,
        oauth_client = oauth_client,
        shiny_session = shiny_session
      )
      return(claims)
    }

    # Candidate keys existed but none verified the signature —
    # this indicates tampering or serious misconfiguration.
    audit_userinfo_event(
      oauth_client,
      status = "userinfo_jwt_signature_invalid",
      shiny_session = shiny_session
    )
    err_userinfo(c(
      "x" = "UserInfo JWT signature is invalid",
      "i" = "Signature could not be verified against any candidate JWKS key"
    ))
  }
  # No compatible candidate keys in JWKS — fail closed.
  audit_userinfo_event(
    oauth_client,
    status = "userinfo_jwt_no_matching_key",
    shiny_session = shiny_session
  )
  err_userinfo(c(
    "x" = "UserInfo JWT signature could not be verified: no compatible keys in provider JWKS",
    "i" = "Signature verification is required for signed UserInfo JWTs (OIDC Core 5.3.2)"
  ))
}

#' Internal: validate required and temporal claims in a signed UserInfo JWT
#'
#' @param claims Named list of JWT claims.
#' @param expected_issuer The OP's Issuer Identifier URL.
#' @param expected_client_id The RP's Client ID.
#' @keywords internal
#' @noRd
validate_signed_userinfo_claims <- function(
  claims,
  expected_issuer,
  expected_client_id,
  oauth_client = NULL,
  shiny_session = NULL
) {
  fail_signed_userinfo_claim_validation <- function(status, bullets) {
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = status,
        shiny_session = shiny_session
      )
    }
    err_userinfo(bullets)
  }

  is_single_finite_number <- function(x) {
    is.numeric(x) && length(x) == 1L && is.finite(x) && !is.na(x)
  }

  now <- floor(as.numeric(Sys.time()))
  lwe <- if (!is.null(oauth_client)) {
    as.numeric(oauth_client@provider@leeway %||% 0)
  } else {
    0
  }
  if (!is.finite(lwe) || is.na(lwe) || length(lwe) != 1L) {
    lwe <- 0
  }

  # sub MUST always be returned in the UserInfo Response (OIDC Core §5.3)
  sub <- claims$sub
  if (!is_valid_string(sub)) {
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_missing_sub",
        shiny_session = shiny_session
      )
    }
    err_userinfo(c(
      "x" = "Signed UserInfo JWT missing required 'sub' claim (OIDC Core 5.3)"
    ))
  }

  # iss MUST be present and match the OP's Issuer Identifier
  iss <- claims$iss
  if (!is_valid_string(iss)) {
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_missing_iss",
        shiny_session = shiny_session
      )
    }
    err_userinfo(c(
      "x" = "Signed UserInfo JWT missing required 'iss' claim (OIDC Core 5.3.2)"
    ))
  }
  # Strict string equality — no trailing-slash normalization (OIDC Core §3.1.3.7).
  if (!identical(iss, expected_issuer)) {
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_iss_mismatch",
        shiny_session = shiny_session
      )
    }
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
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_missing_aud",
        shiny_session = shiny_session
      )
    }
    err_userinfo(c(
      "x" = "Signed UserInfo JWT missing required 'aud' claim (OIDC Core 5.3.2)"
    ))
  }
  if (!is.character(aud) || !(expected_client_id %in% aud)) {
    if (!is.null(oauth_client)) {
      audit_userinfo_event(
        oauth_client,
        status = "userinfo_jwt_aud_mismatch",
        shiny_session = shiny_session
      )
    }
    err_userinfo(c(
      "x" = "Signed UserInfo JWT 'aud' claim does not include client_id (OIDC Core 5.3.2)",
      "i" = paste0("Expected client_id: ", expected_client_id),
      "i" = paste0("Got aud: ", paste(aud, collapse = ", "))
    ))
  }

  required_temporal_claims <- if (!is.null(oauth_client)) {
    unique(tolower(
      oauth_client@userinfo_jwt_required_temporal_claims %||% character(0)
    ))
  } else {
    character(0)
  }
  missing_temporal_claims <- setdiff(
    required_temporal_claims,
    names(claims) %||% character(0)
  )
  if (length(missing_temporal_claims) > 0) {
    fail_signed_userinfo_claim_validation(
      status = "userinfo_jwt_missing_required_temporal_claims",
      bullets = c(
        "x" = paste0(
          "Signed UserInfo JWT missing required temporal claim(s): ",
          paste(missing_temporal_claims, collapse = ", ")
        ),
        "i" = paste(
          "Configure userinfo_jwt_required_temporal_claims = character(0) to accept signed UserInfo JWTs without those temporal claims."
        )
      )
    )
  }

  if (!is.null(claims$exp)) {
    if (!is_single_finite_number(claims$exp)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_invalid_exp",
        bullets = c(
          "x" = "Signed UserInfo JWT 'exp' claim must be a single finite number when present"
        )
      )
    }

    exp_val <- as.numeric(claims$exp)
    if (exp_val < (now - lwe)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_expired",
        bullets = c(
          "x" = "Signed UserInfo JWT expired",
          "i" = paste0(
            "exp=",
            exp_val,
            ", now=",
            now,
            ", leeway=",
            lwe,
            "s"
          )
        )
      )
    }
  }

  if (!is.null(claims$iat)) {
    if (!is_single_finite_number(claims$iat)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_invalid_iat",
        bullets = c(
          "x" = "Signed UserInfo JWT 'iat' claim must be a single finite number when present"
        )
      )
    }

    iat_val <- as.numeric(claims$iat)
    if (iat_val > (now + lwe)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_iat_future",
        bullets = c(
          "x" = "Signed UserInfo JWT issued in the future",
          "i" = paste0(
            "iat=",
            iat_val,
            ", now=",
            now,
            ", leeway=",
            lwe,
            "s"
          )
        )
      )
    }
  }

  if (!is.null(claims$nbf)) {
    if (!is_single_finite_number(claims$nbf)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_invalid_nbf",
        bullets = c(
          "x" = "Signed UserInfo JWT 'nbf' claim must be a single finite number when present"
        )
      )
    }

    nbf_val <- as.numeric(claims$nbf)
    if (nbf_val > (now + lwe)) {
      fail_signed_userinfo_claim_validation(
        status = "userinfo_jwt_nbf_future",
        bullets = c(
          "x" = "Signed UserInfo JWT not yet valid (nbf)",
          "i" = paste0(
            "nbf=",
            nbf_val,
            ", now=",
            now,
            ", leeway=",
            lwe,
            "s"
          )
        )
      )
    }
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
