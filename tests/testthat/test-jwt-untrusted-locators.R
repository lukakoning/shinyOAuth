for (jwt_context in c("ID token", "JARM", "UserInfo")) {
  test_that(
    paste(jwt_context, "uses trusted JWKS rather than JWT header locators"),
    {
      withr::local_options(list(
        shinyOAuth.skip_browser_token = TRUE,
        shinyOAuth.skip_id_sig = FALSE,
        shinyOAuth.expose_error_body = TRUE
      ))
      signing_key <- openssl::rsa_keygen(2048)
      attacker_key <- openssl::rsa_keygen(2048)
      public_key <- function(key, kid) {
        jwk <- jsonlite::fromJSON(
          write_test_jwk(key[["pubkey"]]),
          simplifyVector = FALSE
        )
        c(jwk, list(kid = kid, alg = "RS256", use = "sig"))
      }
      locators <- list(
        jku = "https://attacker.example.invalid/keys.json",
        x5u = "https://attacker.example.invalid/certificate.pem"
      )
      sql_kid <- "trusted-key' OR '1'='1"
      path_kid <- "../../keys/issuer.pem"
      cases <- list(
        list(label = "plain positive control"),
        list(label = "ignored jku", headers = locators["jku"]),
        list(label = "ignored x5u", headers = locators["x5u"]),
        list(
          label = "attacker signature",
          headers = locators,
          wrong_key = TRUE
        ),
        list(
          label = "unknown SQL-shaped kid",
          headers = locators,
          kid = sql_kid
        ),
        list(
          label = "unknown path-shaped kid",
          headers = locators,
          kid = path_kid
        ),
        list(
          label = "registered literal SQL-shaped kid",
          headers = locators,
          kid = sql_kid,
          registered_kid = sql_kid
        ),
        list(
          label = "registered literal path-shaped kid",
          headers = locators,
          kid = path_kid,
          registered_kid = path_kid
        )
      )
      for (case in cases) {
        kid <- case[["kid"]] %||% "trusted-key"
        registered_kid <- case[["registered_kid"]] %||% "trusted-key"
        wrong_key <- isTRUE(case[["wrong_key"]])
        rejects <- wrong_key || !identical(kid, registered_kid)
        provider <- make_test_provider()
        provider@issuer <- "https://issuer.example.com"
        provider@jwks_uri <- "https://issuer.example.com/jwks"
        provider@response_modes_supported <- c("query", "query.jwt")
        provider@jarm_signing_alg_values_supported <- "RS256"
        if (!identical(jwt_context, "JARM")) {
          provider@userinfo_url <- "https://issuer.example.com/userinfo"
          provider@userinfo_required <- TRUE
        }
        if (identical(jwt_context, "ID token")) {
          provider@id_token_required <- TRUE
          provider@id_token_validation <- TRUE
          provider@userinfo_id_token_match <- TRUE
        } else if (identical(jwt_context, "UserInfo")) {
          provider@userinfo_signed_jwt_required <- TRUE
          provider@userinfo_allowed_algs <- "RS256"
        }
        client <- oauth_client(
          provider,
          client_id = "locator-client",
          client_secret = "",
          redirect_uri = "http://localhost:8100",
          scopes = "openid",
          response_mode = if (identical(jwt_context, "JARM")) {
            "query.jwt"
          } else {
            "query"
          },
          jarm_signed_response_alg = if (identical(jwt_context, "JARM")) {
            "RS256"
          } else {
            NULL
          },
          state_key = openssl::rand_bytes(32)
        )
        requested_urls <- character()
        wire <- new.env(parent = emptyenv())
        wire[["jwt"]] <- NULL
        trusted_jwks <- list(
          keys = list(public_key(signing_key, registered_kid))
        )
        attacker_jwks <- list(keys = list(public_key(attacker_key, kid)))
        response <- function(url, body, type = "application/json") {
          httr2::response(
            url = url,
            headers = list("content-type" = type),
            body = charToRaw(
              if (identical(type, "application/jwt")) {
                body
              } else {
                jsonlite::toJSON(body, auto_unbox = TRUE)
              }
            )
          )
        }
        # Keep key fetching, refresh, parsing and verification unchanged, and
        # observe every HTTP attempt, including any header-selected destination.
        local_mocked_bindings(
          req_perform = function(req, ...) {
            url <- req[["url"]]
            requested_urls <<- c(requested_urls, url)
            if (identical(url, provider@jwks_uri)) {
              return(response(url, trusted_jwks))
            }
            if (url %in% unlist(locators, use.names = FALSE)) {
              return(response(url, attacker_jwks))
            }
            if (identical(url, provider@token_url)) {
              return(response(
                url,
                compact_list(list(
                  access_token = "locator-access-token",
                  token_type = "Bearer",
                  expires_in = 3600,
                  id_token = if (identical(jwt_context, "ID token")) {
                    wire[["jwt"]]
                  } else {
                    NULL
                  }
                ))
              ))
            }
            if (identical(url, provider@userinfo_url)) {
              if (identical(jwt_context, "UserInfo")) {
                return(response(url, wire[["jwt"]], "application/jwt"))
              }
              return(response(url, list(sub = "locator-subject")))
            }
            stop("Unexpected request in JWT locator regression")
          },
          .package = "httr2"
        )
        issue <- function(state = NULL) {
          now <- floor(as.numeric(Sys.time()))
          claims <- list(
            iss = provider@issuer,
            aud = client@client_id,
            exp = now + 300
          )
          if (identical(jwt_context, "JARM")) {
            claims[["code"]] <- "legitimate-code"
            claims[["state"]] <- state
          } else {
            claims[["sub"]] <- "locator-subject"
            claims[["iat"]] <- now
          }
          jose::jwt_encode_sig(
            do.call(jose::jwt_claim, claims),
            key = if (wrong_key) attacker_key else signing_key,
            header = c(list(kid = kid), case[["headers"]] %||% list())
          )
        }
        expected_error <- if (wrong_key) {
          switch(
            jwt_context,
            "ID token" = "ID token signature invalid",
            JARM = "JARM signature is invalid",
            UserInfo = "UserInfo JWT signature is invalid"
          )
        } else {
          switch(
            jwt_context,
            "ID token" = "No JWKS key matches kid",
            JARM = "No provider JWKS key matches JARM kid",
            UserInfo = "no compatible keys in provider JWKS"
          )
        }
        if (identical(jwt_context, "UserInfo")) {
          wire[["jwt"]] <- issue()
          if (rejects) {
            expect_error(
              get_userinfo(client, token = "locator-access-token"),
              regexp = expected_error,
              class = "shinyOAuth_userinfo_error",
              info = case[["label"]]
            )
          } else {
            claims <- get_userinfo(client, token = "locator-access-token")
            expect_identical(
              claims[["sub"]],
              "locator-subject",
              info = case[["label"]]
            )
          }
          expect_identical(sum(requested_urls == provider@token_url), 0L)
        } else {
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
              pending <- client@state_store[["get"]](state_keys[[1L]])
              jwt <- issue(state)
              wire[["jwt"]] <- jwt
              callback <- if (identical(jwt_context, "JARM")) {
                list(response = jwt)
              } else {
                list(code = "legitimate-code", state = state)
              }
              values[[".process_query"]](paste0(
                "?",
                httr2::url_query_build(callback)
              ))
              session[["flushReact"]]()
              if (rejects) {
                expect_false(
                  isTRUE(values[["authenticated"]]),
                  info = case[["label"]]
                )
                expect_null(values[["token"]], info = case[["label"]])
                expect_match(
                  values[["error_description"]],
                  expected_error,
                  fixed = TRUE,
                  info = case[["label"]]
                )
                if (identical(jwt_context, "ID token")) {
                  expect_identical(
                    sum(requested_urls == provider@token_url),
                    1L
                  )
                  expect_identical(
                    sum(requested_urls == provider@userinfo_url),
                    0L
                  )
                }
                if (identical(jwt_context, "JARM")) {
                  expect_identical(
                    sum(requested_urls == provider@token_url),
                    0L
                  )
                  expect_identical(client@state_store[["keys"]](), state_keys)
                  expect_identical(
                    client@state_store[["get"]](state_keys[[1L]]),
                    pending
                  )
                }
              } else {
                expect_true(
                  isTRUE(values[["authenticated"]]),
                  info = case[["label"]]
                )
                expect_null(values[["error"]], info = case[["label"]])
                expect_identical(sum(requested_urls == provider@token_url), 1L)
                if (identical(jwt_context, "ID token")) {
                  expect_true(isTRUE(values[["token"]]@id_token_validated))
                  expect_identical(
                    sum(requested_urls == provider@userinfo_url),
                    1L
                  )
                }
                expect_length(client@state_store[["keys"]](), 0L)
              }
            }
          )
        }
        expect_true(
          sum(requested_urls == provider@jwks_uri) > 0L,
          info = case[["label"]]
        )
        expect_false(
          any(requested_urls %in% unlist(locators, use.names = FALSE)),
          info = case[["label"]]
        )
        expect_true(
          all(
            requested_urls %in%
              c(provider@jwks_uri, provider@token_url, provider@userinfo_url)
          ),
          info = case[["label"]]
        )
      }
    }
  )
}
