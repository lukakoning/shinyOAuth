opaque_mtls_client <- function(style = "body", aliases = TRUE) {
  endpoints <- c(
    token_endpoint = "token",
    userinfo_endpoint = "userinfo",
    introspection_endpoint = "introspect",
    revocation_endpoint = "revoke",
    pushed_authorization_request_endpoint = "par"
  )
  provider <- oauth_provider(
    name = "opaque-mtls",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = "https://example.com/userinfo",
    introspection_url = "https://example.com/introspect",
    revocation_url = "https://example.com/revoke",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    token_auth_style = style,
    mtls_client_certificate_bound_access_tokens = TRUE,
    mtls_endpoint_aliases = if (aliases) {
      as.list(setNames(
        paste0("https://example.com/mtls/", endpoints),
        names(endpoints)
      ))
    } else {
      list()
    }
  )
  oauth_client(
    provider = provider,
    client_id = "opaque-client",
    client_secret = if (style == "body") "opaque-client-secret" else "",
    client_assertion_private_key = if (style == "private_key_jwt") {
      openssl::rsa_keygen()
    } else {
      NULL
    },
    redirect_uri = "http://localhost:8100/callback",
    mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
    mtls_client_ca_file = mtls_pem_fixture("ca-cert.pem"),
    mtls_certificate_bound_access_tokens = TRUE,
    mtls_require_observed_cnf = FALSE
  )
}

for (style in c("body", "public", "private_key_jwt")) {
  for (aliases in c(FALSE, TRUE)) {
    test_that(
      paste(
        "opaque mTLS lifecycle presents the certificate:",
        style,
        "aliases",
        aliases
      ),
      {
        client <- opaque_mtls_client(style, aliases)
        captured <- list()
        form <- httr2::req_body_form
        local_mocked_bindings(
          req_body_form = function(req, ...) {
            req <- form(req, ...)
            attr(req, "test_form") <- list(...)
            req
          },
          .package = "httr2"
        )
        respond <- function(req, ...) {
          captured[[length(captured) + 1L]] <<- req
          endpoint <- sub(".*/", "", req$url)
          payload <- switch(
            endpoint,
            token = list(
              access_token = "opaque-access",
              refresh_token = "opaque-refresh",
              token_type = "Bearer",
              expires_in = 3600
            ),
            userinfo = list(sub = "local-user"),
            introspect = list(active = TRUE),
            revoke = list(),
            par = list(request_uri = "urn:example:opaque-par", expires_in = 60),
            stop("Unexpected endpoint")
          )
          httr2::response(
            url = req$url,
            status = if (endpoint == "par") 201L else 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
          )
        }
        local_mocked_bindings(
          req_with_dpop_retry = respond,
          req_with_retry = respond,
          .package = "shinyOAuth"
        )

        url <- prepare_call(client, valid_browser_token())
        token <- handle_callback(
          client,
          code = "local-code",
          payload = parse_query_param(url, "state"),
          browser_token = valid_browser_token()
        )
        expect_identical(token@access_token, "opaque-access")
        expect_length(token@cnf, 0L)
        expect_identical(get_userinfo(client, token)$sub, "local-user")
        refreshed <- refresh_token(client, token)
        expect_identical(refreshed@access_token, "opaque-access")
        expect_length(refreshed@cnf, 0L)
        expect_true(introspect_token(client, refreshed)$active)
        expect_true(revoke_token(client, refreshed)$revoked)
        client@provider@par_url <- "https://example.com/par"
        push_authorization_request(client, list(client_id = client@client_id))

        prefix <- if (aliases) {
          "https://example.com/mtls/"
        } else {
          "https://example.com/"
        }
        expect_true(all(vapply(
          captured,
          function(req) startsWith(req$url, prefix),
          logical(1)
        )))
        expect_setequal(
          vapply(captured, function(req) sub(".*/", "", req$url), ""),
          c("token", "userinfo", "introspect", "revoke", "par")
        )
        for (req in captured) {
          expect_identical(req$options$sslcert, client@mtls_client_cert_file)
          expect_identical(req$options$sslkey, client@mtls_client_key_file)
          if (endsWith(req$url, "/userinfo")) {
            next
          }
          fields <- attr(req, "test_form")
          expect_identical(fields$client_id, client@client_id)
          if (style == "body") {
            expect_identical(fields$client_secret, client@client_secret)
          } else {
            expect_false("client_secret" %in% names(fields))
            if (style == "private_key_jwt") {
              expect_identical(
                fields$client_assertion_type,
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
              )
              expect_identical(
                parse_jwt_header(fields$client_assertion)$alg,
                "RS256"
              )
            }
          }
        }
        # Both the object and raw opaque-string resource APIs retain the policy.
        for (access in list(refreshed, refreshed@access_token)) {
          req <- resource_req(
            access,
            "https://resource.example.com/api",
            oauth_client = client
          )
          expect_identical(req$options$sslcert, client@mtls_client_cert_file)
          expect_identical(req$options$sslkey, client@mtls_client_key_file)
        }
        metadata <- oauth_client_mtls_registration(client)
        expect_true(metadata$tls_client_certificate_bound_access_tokens)
        expect_identical(
          metadata$token_endpoint_auth_method,
          switch(style, body = "client_secret_post", public = "none", style)
        )
      }
    )
  }
}

test_that("opaque mode permits absent confirmation but still rejects observed invalid bindings", {
  client <- opaque_mtls_client()
  token_set <- list(
    access_token = "opaque-access",
    token_type = "Bearer",
    expires_in = 60
  )
  expect_silent(verify_token_set(client, token_set, nonce = NULL))
  for (is_refresh in c(FALSE, TRUE)) {
    for (surface in c("response", "jwt", "conflict")) {
      invalid <- token_set
      invalid$cnf <- list(`x5t#S256` = "incorrect-thumbprint")
      if (surface %in% c("jwt", "conflict")) {
        invalid$access_token <- build_dummy_jwt(list(cnf = invalid$cnf))
        invalid$cnf <- if (surface == "jwt") {
          NULL
        } else {
          list(`x5t#S256` = "different-thumbprint")
        }
      }
      expect_error(
        verify_token_set(
          client,
          invalid,
          nonce = NULL,
          is_refresh = is_refresh
        ),
        class = "shinyOAuth_token_error"
      )
    }
  }
  expect_error(
    resource_req(
      OAuthToken(access_token = "opaque", cnf = list(`x5t#S256` = "wrong")),
      "https://resource.example.com/api",
      oauth_client = client
    ),
    "does not match"
  )

  client@mtls_require_observed_cnf <- TRUE
  expect_error(
    verify_token_set(client, token_set, nonce = NULL),
    "required cnf"
  )
  expect_error(
    resource_req(
      "opaque",
      "https://resource.example.com/api",
      oauth_client = client
    ),
    "required cnf"
  )
})

test_that("opaque login and refresh validate any confirmation returned by introspection", {
  client <- opaque_mtls_client()
  client@introspect <- TRUE
  thumbprint <- tls_client_cert_thumbprint_s256(client@mtls_client_cert_file)
  confirmation <- NULL
  introspections <- 0L
  local_mocked_bindings(
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req$url,
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(
          '{"access_token":"opaque","refresh_token":"refresh","token_type":"Bearer","expires_in":60}'
        )
      )
    },
    req_with_retry = function(req, ...) {
      expect_identical(req$url, "https://example.com/mtls/introspect")
      expect_identical(req$options$sslcert, client@mtls_client_cert_file)
      introspections <<- introspections + 1L
      payload <- list(active = TRUE)
      if (!is.null(confirmation)) {
        payload$cnf <- list(`x5t#S256` = confirmation)
      }
      httr2::response(
        url = req$url,
        status = 200L,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(payload, auto_unbox = TRUE))
      )
    },
    .package = "shinyOAuth"
  )
  for (is_refresh in c(FALSE, TRUE)) {
    for (observed in list(NULL, thumbprint, "incorrect-thumbprint")) {
      confirmation <- observed
      run <- function() {
        if (is_refresh) {
          refresh_token(
            client,
            OAuthToken(access_token = "old", refresh_token = "refresh"),
            introspect = TRUE
          )
        } else {
          url <- prepare_call(client, valid_browser_token())
          handle_callback(
            client,
            code = "local-code",
            payload = parse_query_param(url, "state"),
            browser_token = valid_browser_token()
          )
        }
      }
      if (identical(observed, "incorrect-thumbprint")) {
        expect_error(run(), "does not match")
      } else {
        token <- run()
        expect_identical(token@access_token, "opaque")
        expect_identical(token@cnf[["x5t#S256"]], observed)
      }
    }
  }
  expect_identical(introspections, 6L)
})

test_that("mTLS observation policy is validated, defaults to strict, and binds pending state", {
  client <- opaque_mtls_client()
  args <- list(
    provider = client@provider,
    client_id = client@client_id,
    client_secret = client@client_secret,
    redirect_uri = client@redirect_uri,
    mtls_client_cert_file = client@mtls_client_cert_file,
    mtls_client_key_file = client@mtls_client_key_file,
    mtls_certificate_bound_access_tokens = TRUE
  )
  for (constructor in list(oauth_client, OAuthClient)) {
    strict <- do.call(constructor, args)
    expect_true(strict@mtls_require_observed_cnf)
    expect_error(
      validate_token_certificate_binding("opaque", strict),
      "required cnf"
    )
    for (invalid in list(NULL, NA, c(TRUE, FALSE), "FALSE")) {
      expect_error(
        do.call(
          constructor,
          c(args, list(mtls_require_observed_cnf = invalid))
        ),
        "mtls_require_observed_cnf"
      )
    }
  }
  for (invalid in list(NA, c(TRUE, FALSE))) {
    expect_error(
      {
        client@mtls_require_observed_cnf <- invalid
      },
      "mtls_require_observed_cnf"
    )
  }
  client@mtls_certificate_bound_access_tokens <- FALSE
  expect_null(
    resource_req(
      "opaque",
      "https://resource.example.com/api",
      oauth_client = client
    )$options$sslcert
  )
  client@mtls_certificate_bound_access_tokens <- TRUE
  client@mtls_require_observed_cnf <- TRUE
  url <- prepare_call(client, valid_browser_token())
  client@mtls_require_observed_cnf <- FALSE
  expect_error(
    handle_callback(
      client,
      code = "unused",
      payload = parse_query_param(url, "state"),
      browser_token = valid_browser_token()
    ),
    "policy",
    ignore.case = TRUE
  )
  expect_false(unserialize(serialize(client, NULL))@mtls_require_observed_cnf)
})
