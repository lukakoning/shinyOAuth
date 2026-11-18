for (response_mode in c("query.jwt", "form_post.jwt")) {
  for (inner_failure in c("signature", "unsigned")) {
    test_that(
      paste(
        "encrypted",
        response_mode,
        "rejects inner",
        inner_failure,
        "without consuming state"
      ),
      {
        withr::local_options(list(
          shinyOAuth.skip_browser_token = TRUE,
          shinyOAuth.expose_error_body = TRUE
        ))
        signing_key <- openssl::rsa_keygen(2048)
        encryption_key <- openssl::rsa_keygen(2048)
        public_jwk <- jsonlite::fromJSON(
          write_test_jwk(signing_key[["pubkey"]]),
          simplifyVector = FALSE
        )
        public_jwk[["kid"]] <- "issuer-signing-key"
        public_jwk[["alg"]] <- "RS256"
        public_jwk[["use"]] <- "sig"
        provider <- make_test_provider()
        provider@issuer <- "https://issuer.example.com"
        provider@jwks_uri <- "https://issuer.example.com/jwks"
        provider@response_modes_supported <- response_mode
        provider@jarm_signing_alg_values_supported <- "RS256"
        provider@jarm_encryption_alg_values_supported <- "RSA-OAEP"
        provider@jarm_encryption_enc_values_supported <- "A256CBC-HS512"
        client <- oauth_client(
          provider,
          client_id = "nested-jarm-client",
          client_secret = "",
          redirect_uri = "http://localhost:8100",
          scopes = "openid",
          response_mode = response_mode,
          jarm_signed_response_alg = "RS256",
          jarm_encrypted_response_alg = "RSA-OAEP",
          jarm_encrypted_response_enc = "A256CBC-HS512",
          jarm_decryption_private_key = encryption_key,
          state_key = openssl::rand_bytes(32)
        )
        exchanged_codes <- character()
        token_requests <- 0L
        jwks_downloads <- 0L
        json_response <- function(value) {
          httr2::response(
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(value, auto_unbox = TRUE))
          )
        }
        # Stub HTTP only; decryption, JWKS validation, signatures and code
        # exchange still use the package's normal implementations.
        local_mocked_bindings(
          req_with_retry = function(req, ...) {
            if (identical(req[["url"]], provider@jwks_uri)) {
              jwks_downloads <<- jwks_downloads + 1L
              return(json_response(list(keys = list(public_jwk))))
            }
            if (identical(req[["url"]], provider@token_url)) {
              token_requests <<- token_requests + 1L
              exchanged_codes <<- c(
                exchanged_codes,
                req[["body"]][["data"]][["code"]]
              )
              return(json_response(list(
                access_token = "nested-jarm-access-token",
                token_type = "Bearer",
                expires_in = 3600
              )))
            }
            stop("Unexpected HTTP request in nested JARM regression")
          },
          .package = "shinyOAuth"
        )
        encrypt <- function(inner) {
          shinyOAuth:::jwe_compact_encrypt(
            inner,
            encryption_key[["pubkey"]],
            alg = "RSA-OAEP",
            enc = "A256CBC-HS512",
            cty = "JWT"
          )
        }
        ui <- oauth_form_post_ui(
          shiny::fluidPage(),
          id = "auth",
          client = client
        )
        post_response <- function(response) {
          body <- httr2::url_query_build(list(response = response))
          request <- new.env(parent = emptyenv())
          request[["REQUEST_METHOD"]] <- "POST"
          request[["rook.url_scheme"]] <- "http"
          request[["HTTP_HOST"]] <- "localhost:8100"
          request[["PATH_INFO"]] <- "/"
          request[["QUERY_STRING"]] <- ""
          request[["CONTENT_TYPE"]] <- "application/x-www-form-urlencoded"
          request[["CONTENT_LENGTH"]] <- as.character(nchar(
            body,
            type = "bytes"
          ))
          request[["rook.input"]] <- list(read = function(n) charToRaw(body))
          ui(request)
        }
        shiny::testServer(
          oauth_module_server,
          args = list(
            id = "auth",
            client = client,
            auto_redirect = FALSE,
            indefinite_session = TRUE
          ),
          {
            values[["browser_token"]] <- valid_browser_token()
            authorization_url <- values[["build_auth_url"]]()
            state <- parse_query_param(
              authorization_url,
              "state",
              decode = TRUE
            )
            state_keys <- client@state_store[["keys"]]()
            expect_length(state_keys, 1L)
            pending <- client@state_store[["get"]](state_keys[[1L]])
            good_inner <- jose::jwt_encode_sig(
              jose::jwt_claim(
                iss = provider@issuer,
                aud = client@client_id,
                exp = floor(as.numeric(Sys.time())) + 300,
                code = "legitimate-code",
                state = state
              ),
              key = signing_key,
              header = list(kid = public_jwk[["kid"]])
            )
            parts <- strsplit(good_inner, ".", fixed = TRUE)[[1L]]
            if (identical(inner_failure, "signature")) {
              signature <- shinyOAuth:::base64url_decode_raw(parts[[3L]])
              signature[[1L]] <- as.raw(bitwXor(
                as.integer(signature[[1L]]),
                1L
              ))
              parts[[3L]] <- shinyOAuth:::base64url_encode(signature)
              expected_error <- "JARM signature is invalid"
            } else {
              parts[[1L]] <- shinyOAuth:::base64url_encode(charToRaw(
                '{"alg":"none"}'
              ))
              parts[[3L]] <- ""
              expected_error <- "JARM alg=none is not allowed"
            }
            bad_inner <- paste(parts, collapse = ".")
            bad_response <- encrypt(bad_inner)
            expect_identical(
              shinyOAuth:::jwe_compact_decrypt(bad_response, encryption_key)[[
                "plaintext"
              ]],
              bad_inner
            )
            if (identical(response_mode, "query.jwt")) {
              values[[".process_query"]](paste0(
                "?",
                httr2::url_query_build(list(response = bad_response))
              ))
              session[["flushReact"]]()
              expect_identical(values[["error"]], "invalid_state")
              expect_match(
                values[["error_description"]],
                expected_error,
                fixed = TRUE
              )
            } else {
              rejected <- post_response(bad_response)
              expect_identical(rejected[["status"]], 400L)
              expect_match(rejected[["content"]], expected_error, fixed = TRUE)
              expect_false("Location" %in% names(rejected[["headers"]]))
            }
            expect_false(isTRUE(values[["authenticated"]]))
            expect_null(values[["token"]])
            expect_identical(token_requests, 0L)
            expect_identical(exchanged_codes, character())
            expect_identical(client@state_store[["keys"]](), state_keys)
            expect_identical(
              client@state_store[["get"]](state_keys[[1L]]),
              pending
            )
            good_response <- encrypt(good_inner)
            if (identical(response_mode, "query.jwt")) {
              values[[".process_query"]](paste0(
                "?",
                httr2::url_query_build(list(response = good_response))
              ))
            } else {
              accepted <- post_response(good_response)
              expect_identical(accepted[["status"]], 303L)
              handle <- parse_query_param(
                accepted[["headers"]][["Location"]],
                "shinyOAuth_form_post",
                decode = TRUE
              )
              values[[".process_query"]](paste0(
                "?",
                httr2::url_query_build(list(
                  shinyOAuth_form_post = handle,
                  shinyOAuth_form_post_id = "auth"
                ))
              ))
            }
            session[["flushReact"]]()
            expect_true(isTRUE(values[["authenticated"]]))
            expect_null(values[["error"]])
            expect_identical(token_requests, 1L)
            expect_identical(exchanged_codes, "legitimate-code")
            expect_length(client@state_store[["keys"]](), 0L)
            expect_gt(jwks_downloads, 0L)
          }
        )
      }
    )
  }
}
