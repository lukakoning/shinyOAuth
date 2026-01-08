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

  # Parse from response
  ui <- try(httr2::resp_body_json(resp, simplifyVector = TRUE), silent = TRUE)
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

    err_userinfo(
      c(
        "x" = "Failed to parse userinfo response as JSON",
        "!" = conditionMessage(attr(ui, "condition")),
        "i" = if (is_valid_string(ct)) paste0("Content-Type: ", ct) else NULL,
        "i" = if (!is.na(status)) paste0("Status: ", status) else NULL,
        "i" = if (is_valid_string(url)) paste0("URL: ", url) else NULL
      ),
      context = list(
        phase = "userinfo",
        parse = "json",
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
