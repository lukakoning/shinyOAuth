cnf_json_type_clients <- function() {
  provider <- oauth_provider(
    name = "cnf-json-types",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    introspection_url = "https://example.com/introspect",
    token_auth_style = "body"
  )
  args <- list(
    provider = provider, client_id = "cnf-client", client_secret = "secret",
    redirect_uri = "http://localhost:8100"
  )
  dpop <- do.call(oauth_client, c(args, list(
    dpop_private_key = openssl::ec_keygen("P-256"),
    dpop_require_access_token = TRUE, dpop_require_observed_cnf = TRUE
  )))
  args[["provider"]]@mtls_client_certificate_bound_access_tokens <- TRUE
  list(
    dpop = dpop,
    mtls = do.call(oauth_client, c(args, list(
      mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
      mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
      mtls_certificate_bound_access_tokens = TRUE,
      mtls_require_observed_cnf = TRUE
    )))
  )
}

cnf_json_type_shapes <- function(member, thumbprint) {
  valid <- setNames(list(thumbprint), member)
  list(
    valid = valid,
    thumbprint_array = setNames(list(list(thumbprint)), member),
    cnf_array = list(valid),
    thumbprint_object = setNames(list(list(value = thumbprint)), member),
    thumbprint_null = setNames(list(NULL), member),
    cnf_string = thumbprint,
    cnf_number = 42
  )
}

test_that("strict DPoP and mTLS reject malformed confirmation JSON on exchange and refresh", {
  local_options(shinyOAuth.access_token_cnf = "jwt")
  clients <- cnf_json_type_clients()
  server_key <- openssl::rsa_keygen(2048)
  for (kind in names(clients)) {
    client <- clients[[kind]]
    member <- if (kind == "dpop") "jkt" else "x5t#S256"
    thumbprint <- if (kind == "dpop") {
      client_dpop_jkt(client)
    } else {
      tls_client_cert_thumbprint_s256(
        client@mtls_client_cert_file, client@mtls_client_key_file
      )
    }
    shapes <- cnf_json_type_shapes(member, thumbprint)
    for (shape in names(shapes)) {
      for (surface in c("jwt", "response")) {
        response <- list(
          access_token = "opaque-access-token",
          token_type = if (kind == "dpop") "DPoP" else "Bearer",
          expires_in = 300
        )
        if (surface == "jwt") {
          # The server signature is real; the client observes only the JSON
          # binding and must not simplify a signed array into a scalar.
          response[["access_token"]] <- encode_asymmetric_jwt_with_header(
            list(cnf = shapes[[shape]]), server_key,
            list(alg = "RS256", typ = "JWT")
          )
        } else {
          response[["cnf"]] <- shapes[[shape]]
        }
        wire <- httr2::response(
          status = 200L, headers = list("content-type" = "application/json"),
          body = charToRaw(jsonlite::toJSON(response, auto_unbox = TRUE, null = "null"))
        )
        parsed <- parse_token_response(wire)
        for (refresh in c(FALSE, TRUE)) {
          if (shape == "valid") {
            verified <- verify_token_set(client, parsed, nonce = NULL, is_refresh = refresh)
            expect_identical(resolve_token_cnf(
              cnf = verified[["cnf"]], access_token = verified[["access_token"]]
            )[[member]], thumbprint)
          } else {
            expect_error(
              verify_token_set(client, parsed, nonce = NULL, is_refresh = refresh),
              class = "shinyOAuth_token_error", regexp = "Invalid token cnf"
            )
          }
        }
        if (surface == "jwt") {
          if (shape == "valid") {
            expect_s3_class(resource_req(
              parsed[["access_token"]], "https://example.com/api",
              client = client, token_type = parsed[["token_type"]]
            ), "httr2_request")
          } else {
            expect_error(resource_req(
              parsed[["access_token"]], "https://example.com/api",
              client = client, token_type = parsed[["token_type"]]
            ), regexp = "Invalid token cnf")
          }
        }
      }
    }
  }
})

test_that("introspection preserves confirmation JSON types before binding resolution", {
  clients <- cnf_json_type_clients()
  for (kind in names(clients)) {
    client <- clients[[kind]]
    member <- if (kind == "dpop") "jkt" else "x5t#S256"
    thumbprint <- if (kind == "dpop") client_dpop_jkt(client) else {
      tls_client_cert_thumbprint_s256(
        client@mtls_client_cert_file, client@mtls_client_key_file
      )
    }
    shapes <- cnf_json_type_shapes(member, thumbprint)
    for (shape in names(shapes)) {
      body <- charToRaw(jsonlite::toJSON(
        list(active = TRUE, cnf = shapes[[shape]]),
        auto_unbox = TRUE, null = "null"
      ))
      testthat::local_mocked_bindings(
        req_with_retry = function(req, ...) httr2::response(
          url = req[["url"]], status = 200L,
          headers = list("content-type" = "application/json"), body = body
        ),
        .package = "shinyOAuth"
      )
      result <- introspect_token(client, OAuthToken(
        access_token = "opaque-access-token",
        token_type = if (kind == "dpop") "DPoP" else "Bearer"
      ))
      expect_true(result[["active"]])
      if (shape == "valid") {
        expect_identical(resolve_token_cnf(introspection_result = result)[[member]], thumbprint)
      } else {
        expect_error(
          resolve_token_cnf(introspection_result = result),
          class = "shinyOAuth_token_error", regexp = "Invalid token cnf"
        )
      }
    }
  }
})
