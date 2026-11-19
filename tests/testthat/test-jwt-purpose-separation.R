make_jwt_purpose_fixture <- function() {
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  jwk[["kid"]] <- "shared-purpose-key"
  jwk[["alg"]] <- "RS256"
  jwk[["use"]] <- "sig"
  issuer <- "https://issuer.example.com"
  audience <- "shared-purpose-client"
  now <- floor(as.numeric(Sys.time()))
  wire <- new.env(parent = emptyenv())
  wire[["urls"]] <- character()
  wire[["id_token"]] <- NULL
  wire[["userinfo"]] <- NULL
  client <- function(context, use_nonce = FALSE, bind_subject = FALSE) {
    provider <- oauth_provider(
      name = "jwt-purpose-fixture",
      auth_url = paste0(issuer, "/authorize"),
      token_url = paste0(issuer, "/token"),
      issuer = issuer,
      jwks_uri = paste0(issuer, "/jwks"),
      userinfo_url = if (!identical(context, "JARM")) {
        paste0(issuer, "/userinfo")
      } else {
        NA_character_
      },
      token_auth_style = "public",
      use_pkce = TRUE,
      use_nonce = use_nonce,
      id_token_required = identical(context, "ID token"),
      id_token_validation = identical(context, "ID token") || bind_subject,
      id_token_allowed_algs = "RS256",
      userinfo_required = !identical(context, "JARM"),
      userinfo_signed_jwt_required = !identical(context, "JARM"),
      userinfo_allowed_algs = "RS256",
      userinfo_id_token_match = bind_subject,
      response_modes_supported = c("query", "query.jwt"),
      jarm_signing_alg_values_supported = "RS256"
    )
    oauth_client(
      provider,
      client_id = audience,
      client_secret = "",
      redirect_uri = "http://localhost:8100",
      scopes = "openid",
      response_mode = if (identical(context, "JARM")) "query.jwt" else "query",
      jarm_signed_response_alg = if (identical(context, "JARM")) {
        "RS256"
      } else {
        NULL
      },
      state_key = openssl::rand_bytes(32)
    )
  }
  claims <- function(
    purpose,
    state = "corpus-state",
    nonce = NULL,
    subject = "same-subject"
  ) {
    value <- list(iss = issuer, aud = audience)
    if (identical(purpose, "JARM")) {
      value[["iat"]] <- now
      value[["exp"]] <- now + 300
      value[["code"]] <- "corpus-code"
      value[["state"]] <- state
    } else {
      value[["sub"]] <- subject
      if (!identical(purpose, "minimal UserInfo")) {
        value[["iat"]] <- now
        value[["exp"]] <- now + 300
      }
      if (grepl("UserInfo", purpose, fixed = TRUE)) {
        value[["name"]] <- "UserInfo fixture subject"
      }
      if (!is.null(nonce)) value[["nonce"]] <- nonce
    }
    value
  }
  sign <- function(claims, typ = NULL) {
    header <- list(alg = "RS256", kid = jwk[["kid"]])
    if (!is.null(typ)) {
      header[["typ"]] <- typ
    }
    encode <- function(value) {
      shinyOAuth:::base64url_encode(charToRaw(enc2utf8(
        jsonlite::toJSON(value, auto_unbox = TRUE)
      )))
    }
    input <- paste(encode(header), encode(claims), sep = ".")
    signature <- openssl::signature_create(
      charToRaw(input),
      hash = openssl::sha256,
      key = key
    )
    paste(input, shinyOAuth:::base64url_encode(signature), sep = ".")
  }
  perform <- function(req, ...) {
    url <- req[["url"]]
    wire[["urls"]] <- c(wire[["urls"]], url)
    if (identical(url, paste0(issuer, "/jwks"))) {
      return(httr2::response(
        url = url,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(keys = list(jwk)),
          auto_unbox = TRUE
        ))
      ))
    }
    if (identical(url, paste0(issuer, "/token"))) {
      return(httr2::response(
        url = url,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          compact_list(list(
            access_token = "purpose-access-token",
            token_type = "Bearer",
            expires_in = 3600,
            id_token = wire[["id_token"]]
          )),
          auto_unbox = TRUE
        ))
      ))
    }
    if (identical(url, paste0(issuer, "/userinfo"))) {
      stopifnot(
        is.character(wire[["userinfo"]]),
        length(wire[["userinfo"]]) == 1L
      )
      return(httr2::response(
        url = url,
        headers = list("content-type" = "application/jwt"),
        body = charToRaw(wire[["userinfo"]])
      ))
    }
    stop("Unexpected HTTP request in JWT-purpose corpus")
  }
  list(
    client = client,
    claims = claims,
    sign = sign,
    perform = perform,
    wire = wire,
    issuer = issuer
  )
}

test_that("signed JWT corpus records native checks and nonce-free purpose overlap", {
  withr::local_options(list(shinyOAuth.skip_id_sig = FALSE))
  fixture <- make_jwt_purpose_fixture()
  local_mocked_bindings(req_perform = fixture[["perform"]], .package = "httr2")
  clients <- lapply(c("ID token", "JARM", "UserInfo"), fixture[["client"]])
  names(clients) <- c("ID token", "JARM", "UserInfo")
  purposes <- c("ID token", "JARM", "minimal UserInfo", "timed UserInfo")
  for (typ in list(
    NULL,
    "JWT",
    "oauth-authz-resp+jwt",
    "oauth-authz-req+jwt"
  )) {
    corpus <- lapply(purposes, function(purpose) {
      fixture[["sign"]](fixture[["claims"]](purpose), typ)
    })
    names(corpus) <- purposes
    for (target in names(clients)) {
      client <- clients[[target]]
      for (purpose in purposes) {
        client@provider@jwks_cache[["reset"]]()
        fixture[["wire"]][["urls"]] <- character()
        fixture[["wire"]][["userinfo"]] <- corpus[[purpose]]
        label <- paste(purpose, "to", target, "typ", typ %||% "absent")
        type_ok <- is.null(typ) ||
          identical(typ, "JWT") ||
          (identical(target, "JARM") && identical(typ, "oauth-authz-resp+jwt"))
        accepted <- type_ok &&
          switch(
            target,
            "ID token" = purpose %in% c("ID token", "timed UserInfo"),
            JARM = identical(purpose, "JARM"),
            UserInfo = !identical(purpose, "JARM")
          )
        receive <- function() {
          switch(
            target,
            "ID token" = shinyOAuth:::validate_id_token(
              client,
              corpus[[purpose]]
            ),
            JARM = shinyOAuth:::validate_jarm_response(
              client,
              corpus[[purpose]]
            ),
            UserInfo = get_userinfo(client, token = "purpose-access-token")
          )
        }
        if (accepted) {
          result <- receive()
          if (identical(target, "JARM")) {
            expect_identical(result[["code"]], "corpus-code", info = label)
            expect_identical(result[["state"]], "corpus-state", info = label)
          } else {
            expect_identical(result[["sub"]], "same-subject", info = label)
            if (identical(target, "ID token")) {
              expect_true(
                isTRUE(attr(result, "signature_verified")),
                info = label
              )
            }
          }
          expect_true(
            any(
              fixture[["wire"]][["urls"]] ==
                paste0(fixture[["issuer"]], "/jwks")
            ),
            info = label
          )
        } else {
          reason <- if (!type_ok) {
            "JWT typ header invalid"
          } else if (identical(target, "ID token")) {
            if (identical(purpose, "JARM")) {
              "sub claim"
            } else {
              "missing (exp|iat) claim"
            }
          } else if (identical(target, "JARM")) {
            if (identical(purpose, "minimal UserInfo")) {
              "missing required exp"
            } else {
              "missing required state"
            }
          } else {
            "missing or invalid 'sub' claim"
          }
          error_class <- switch(
            target,
            "ID token" = "shinyOAuth_id_token_error",
            JARM = "shinyOAuth_state_error",
            UserInfo = "shinyOAuth_userinfo_error"
          )
          expect_error(
            receive(),
            regexp = reason,
            class = error_class,
            info = label
          )
          if (!type_ok) {
            expect_false(
              any(
                fixture[["wire"]][["urls"]] ==
                  paste0(fixture[["issuer"]], "/jwks")
              ),
              info = label
            )
          }
        }
        expect_false(
          any(
            fixture[["wire"]][["urls"]] == paste0(fixture[["issuer"]], "/token")
          ),
          info = label
        )
      }
    }
  }
})

test_that("nonce-bound ID-token callbacks reject timed UserInfo and another transaction's ID token", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = TRUE
  ))
  fixture <- make_jwt_purpose_fixture()
  local_mocked_bindings(req_perform = fixture[["perform"]], .package = "httr2")
  for (typ in list(NULL, "JWT")) {
    for (source in c(
      "native ID token",
      "timed UserInfo",
      "other transaction ID token"
    )) {
      client <- fixture[["client"]](
        "ID token",
        use_nonce = TRUE,
        bind_subject = TRUE
      )
      fixture[["wire"]][["urls"]] <- character()
      fixture[["wire"]][["userinfo"]] <- fixture[["sign"]](
        fixture[["claims"]]("minimal UserInfo"),
        typ
      )
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
          url <- values[["build_auth_url"]]()
          nonce <- parse_query_param(url, "nonce", decode = TRUE)
          state <- parse_query_param(url, "state", decode = TRUE)
          expect_match(nonce, "^[A-Za-z0-9_-]{32}$")
          payload <- if (identical(source, "timed UserInfo")) {
            fixture[["claims"]]("timed UserInfo")
          } else {
            fixture[["claims"]](
              "ID token",
              nonce = if (identical(source, "native ID token")) {
                nonce
              } else {
                "other-transaction-nonce"
              }
            )
          }
          fixture[["wire"]][["id_token"]] <- fixture[["sign"]](payload, typ)
          values[[".process_query"]](paste0(
            "?",
            httr2::url_query_build(list(code = "corpus-code", state = state))
          ))
          session[["flushReact"]]()
          expect_identical(
            sum(fixture[["wire"]][["urls"]] == client@provider@token_url),
            1L
          )
          if (identical(source, "native ID token")) {
            expect_true(isTRUE(values[["authenticated"]]))
            expect_true(isTRUE(values[["token"]]@id_token_validated))
            expect_identical(
              sum(fixture[["wire"]][["urls"]] == client@provider@userinfo_url),
              1L
            )
          } else {
            expect_false(isTRUE(values[["authenticated"]]))
            expect_null(values[["token"]])
            expect_match(
              values[["error_description"]],
              if (identical(source, "timed UserInfo")) {
                "ID token missing nonce claim"
              } else {
                "ID token nonce mismatch"
              },
              fixed = TRUE
            )
            expect_identical(
              sum(fixture[["wire"]][["urls"]] == client@provider@userinfo_url),
              0L
            )
          }
        }
      )
    }
  }
})

test_that("JARM callbacks reject ordinary ID-token and UserInfo shapes before state consumption", {
  withr::local_options(list(
    shinyOAuth.skip_browser_token = TRUE,
    shinyOAuth.skip_id_sig = FALSE,
    shinyOAuth.expose_error_body = TRUE
  ))
  fixture <- make_jwt_purpose_fixture()
  local_mocked_bindings(req_perform = fixture[["perform"]], .package = "httr2")
  for (typ in list(NULL, "JWT", "oauth-authz-resp+jwt")) {
    for (source in c("JARM", "ID token", "timed UserInfo")) {
      client <- fixture[["client"]]("JARM")
      fixture[["wire"]][["urls"]] <- character()
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
          url <- values[["build_auth_url"]]()
          state <- parse_query_param(url, "state", decode = TRUE)
          keys <- client@state_store[["keys"]]()
          pending <- client@state_store[["get"]](keys[[1L]])
          jwt <- fixture[["sign"]](
            fixture[["claims"]](source, state = state),
            typ
          )
          values[[".process_query"]](paste0(
            "?",
            httr2::url_query_build(list(response = jwt))
          ))
          session[["flushReact"]]()
          if (identical(source, "JARM")) {
            expect_true(isTRUE(values[["authenticated"]]))
            expect_null(values[["error"]])
            expect_identical(
              sum(fixture[["wire"]][["urls"]] == client@provider@token_url),
              1L
            )
            expect_length(client@state_store[["keys"]](), 0L)
          } else {
            expect_false(isTRUE(values[["authenticated"]]))
            expect_null(values[["token"]])
            expect_match(
              values[["error_description"]],
              "JARM payload missing required state",
              fixed = TRUE
            )
            expect_identical(
              sum(fixture[["wire"]][["urls"]] == client@provider@token_url),
              0L
            )
            expect_identical(client@state_store[["keys"]](), keys)
            expect_identical(client@state_store[["get"]](keys[[1L]]), pending)
          }
        }
      )
    }
  }
})

test_that("UserInfo subject binding rejects identity swaps but does not classify JWT purpose", {
  withr::local_options(list(shinyOAuth.skip_id_sig = FALSE))
  fixture <- make_jwt_purpose_fixture()
  local_mocked_bindings(req_perform = fixture[["perform"]], .package = "httr2")
  for (typ in list(NULL, "JWT")) {
    baseline_client <- fixture[["client"]]("ID token")
    baseline_jwt <- fixture[["sign"]](fixture[["claims"]]("ID token"), typ)
    baseline_claims <- shinyOAuth:::validate_id_token(
      baseline_client,
      baseline_jwt
    )
    expect_true(isTRUE(attr(baseline_claims, "signature_verified")))
    token <- OAuthToken(
      access_token = "purpose-access-token",
      token_type = "Bearer",
      id_token = baseline_jwt,
      id_token_validated = isTRUE(attr(baseline_claims, "signature_verified"))
    )
    client <- fixture[["client"]]("UserInfo", bind_subject = TRUE)
    for (source in c(
      "minimal UserInfo",
      "same-subject ID token",
      "different-subject ID token"
    )) {
      fixture[["wire"]][["urls"]] <- character()
      fixture[["wire"]][["userinfo"]] <- if (
        identical(source, "minimal UserInfo")
      ) {
        fixture[["sign"]](fixture[["claims"]]("minimal UserInfo"), typ)
      } else if (identical(source, "same-subject ID token")) {
        baseline_jwt
      } else {
        fixture[["sign"]](
          fixture[["claims"]]("ID token", subject = "other-subject"),
          typ
        )
      }
      if (identical(source, "different-subject ID token")) {
        expect_error(
          get_userinfo(client, token),
          class = "shinyOAuth_userinfo_mismatch",
          regexp = "userinfo subject does not match id_token subject"
        )
      } else {
        result <- get_userinfo(client, token)
        expect_identical(result[["sub"]], baseline_claims[["sub"]])
      }
      expect_identical(
        sum(fixture[["wire"]][["urls"]] == client@provider@userinfo_url),
        1L
      )
      expect_identical(
        sum(fixture[["wire"]][["urls"]] == client@provider@token_url),
        0L
      )
    }
  }
})
