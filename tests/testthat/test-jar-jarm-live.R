# 1. Live JAR + JARM interop -----------------------------------------------

test_that(
  paste(
    "oauth_module_server completes a live request plus query.jwt flow",
    "against a local JAR/JARM server"
  ),
  {
    testthat::skip_if_not_installed("webfakes")
    testthat::skip_on_cran()
    withr::local_options(list(shinyOAuth.skip_browser_token = TRUE))

    client_secret <- "hs256-request-object-secret-32b!"
    server_key <- openssl::rsa_keygen()
    server_jwk <- jsonlite::fromJSON(
      jose::write_jwk(server_key$pubkey),
      simplifyVector = FALSE
    )
    server_jwk[["kid"]] <- "jarm-sig-1"
    server_jwk[["use"]] <- "sig"
    server_jwk[["alg"]] <- "RS256"

    server_state <- new.env(parent = emptyenv())
    server_state$last_auth <- NULL
    server_state$token_requests <- 0L

    app <- webfakes::new_app()

    app$get("/auth", function(req, res) {
      query <- req$query
      if (is.null(query)) {
        query <- list()
      }
      request_jwt <- query[["request"]] %||% NA_character_
      if (!is_valid_string(request_jwt)) {
        res$set_status(400)$send("missing request object")
        return(invisible(NULL))
      }

      header <- shinyOAuth:::parse_jwt_header(request_jwt)
      if (
        !isTRUE(shinyOAuth:::verify_hmac_jws_signature_no_time(
          request_jwt,
          client_secret,
          "HS256"
        ))
      ) {
        res$set_status(400)$send("invalid request object signature")
        return(invisible(NULL))
      }

      payload <- shinyOAuth:::parse_jwt_payload(request_jwt)
      server_state$last_auth <- list(
        outer_query = as.list(query),
        header = header,
        payload = payload
      )

      code <- paste0("code-", shinyOAuth:::random_urlsafe(12))
      claims <- list(
        iss = paste0(
          sub(
            "/+$",
            "",
            sub("/auth$", "", sub("\\?.*$", "", req$url))
          ),
          "/"
        ),
        aud = payload[["client_id"]],
        exp = floor(as.numeric(Sys.time())) + 300,
        code = code,
        state = payload[["state"]]
      )
      response_jwt <- jose::jwt_encode_sig(
        do.call(jose::jwt_claim, claims),
        key = server_key,
        header = list(alg = "RS256", kid = "jarm-sig-1")
      )
      location <- paste0(
        payload[["redirect_uri"]],
        "?response=",
        utils::URLencode(response_jwt, reserved = TRUE)
      )

      res$set_status(302)
      res$set_header("Location", location)
      res$send("")
      invisible(NULL)
    })

    app$post("/token", function(req, res) {
      server_state$token_requests <- server_state$token_requests + 1L
      res$send_json(
        object = list(
          access_token = "access-token",
          token_type = "Bearer",
          expires_in = 3600
        ),
        auto_unbox = TRUE
      )
      invisible(NULL)
    })

    app$get("/jwks", function(req, res) {
      res$send_json(
        object = list(keys = list(server_jwk)),
        auto_unbox = TRUE,
        null = "null"
      )
      invisible(NULL)
    })

    app$get("/debug/state", function(req, res) {
      res$send_json(
        object = list(
          last_auth = server_state$last_auth,
          token_requests = server_state$token_requests
        ),
        auto_unbox = TRUE,
        null = "null"
      )
      invisible(NULL)
    })

    srv <- webfakes::local_app_process(app)
    on.exit(srv$stop(), add = TRUE)
    base <- srv$url()

    provider <- oauth_provider(
      name = "local-jar-jarm",
      auth_url = paste0(base, "/auth"),
      token_url = paste0(base, "/token"),
      jwks_uri = paste0(base, "/jwks"),
      issuer = base,
      response_modes_supported = c("query.jwt", "jwt"),
      authorization_signing_alg_values_supported = "RS256",
      request_object_signing_alg_values_supported = "HS256",
      use_nonce = FALSE,
      use_pkce = TRUE,
      pkce_method = "S256",
      userinfo_required = FALSE,
      id_token_required = FALSE,
      id_token_validation = FALSE,
      userinfo_id_token_match = FALSE,
      token_auth_style = "body",
      allowed_token_types = character()
    )
    client <- oauth_client(
      provider = provider,
      client_id = "abc",
      client_secret = client_secret,
      redirect_uri = "http://localhost:8100/callback",
      scopes = "openid",
      response_mode = "query.jwt",
      authorization_signed_response_alg = "RS256",
      authorization_request_mode = "request",
      authorization_request_signing_alg = "HS256",
      state_store = cachem::cache_mem(max_age = 60),
      state_payload_max_age = 300,
      state_entropy = 64,
      state_key = paste0(
        "0123456789abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      )
    )
    browser_token <- valid_browser_token()

    shiny::testServer(
      app = oauth_module_server,
      args = list(
        id = "auth",
        client = client,
        auto_redirect = FALSE,
        indefinite_session = TRUE
      ),
      expr = {
        values$browser_token <- browser_token
        auth_url <- values$build_auth_url()
        auth_query_names <- names(shiny::parseQueryString(sub(
          "^[^?]*\\?",
          "",
          auth_url
        )))
        request_jwt <- parse_query_param(auth_url, "request", decode = TRUE)
        request_header <- shinyOAuth:::parse_jwt_header(request_jwt)
        request_payload <- shinyOAuth:::parse_jwt_payload(request_jwt)

        testthat::expect_setequal(
          auth_query_names,
          c("client_id", "response_type", "scope", "request")
        )
        testthat::expect_false(grepl(
          "[?&]response_mode=",
          auth_url
        ))
        testthat::expect_identical(
          request_header[["typ"]],
          "oauth-authz-req+jwt"
        )
        testthat::expect_identical(request_header[["alg"]], "HS256")
        testthat::expect_identical(
          request_payload[["response_mode"]],
          "query.jwt"
        )

        auth_resp <- httr2::request(auth_url) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_options(followlocation = FALSE) |>
          httr2::req_perform()
        callback_url <- httr2::resp_header(auth_resp, "location") %||%
          NA_character_
        response_jwt <- parse_query_param(
          callback_url,
          "response",
          decode = TRUE
        )
        response_payload <- shinyOAuth:::parse_jwt_payload(response_jwt)
        debug_before <- httr2::request(paste0(base, "/debug/state")) |>
          httr2::req_perform() |>
          httr2::resp_body_json(simplifyVector = FALSE)

        testthat::expect_identical(httr2::resp_status(auth_resp), 302L)
        testthat::expect_true(is_valid_string(callback_url))
        testthat::expect_match(callback_url, "[?&]response=")
        testthat::expect_false(grepl("[?&]code=", callback_url))
        testthat::expect_false(grepl("[?&]state=", callback_url))
        testthat::expect_identical(
          shinyOAuth:::parse_jwt_header(response_jwt)[["alg"]],
          "RS256"
        )
        testthat::expect_identical(
          response_payload[["iss"]],
          client@provider@issuer
        )
        testthat::expect_identical(
          debug_before[["last_auth"]][["header"]][["alg"]],
          "HS256"
        )
        testthat::expect_identical(
          debug_before[["last_auth"]][["payload"]][["response_mode"]],
          "query.jwt"
        )
        testthat::expect_identical(
          debug_before[["last_auth"]][["payload"]][["client_id"]],
          client@client_id
        )
        testthat::expect_null(
          debug_before[["last_auth"]][["outer_query"]][["response_mode"]]
        )

        values$.process_query(sub("^[^?]*", "", callback_url))
        session$flushReact()

        debug_after <- httr2::request(paste0(base, "/debug/state")) |>
          httr2::req_perform() |>
          httr2::resp_body_json(simplifyVector = FALSE)

        testthat::expect_true(isTRUE(values$authenticated))
        testthat::expect_identical(values$error, NULL)
        testthat::expect_identical(values$error_description, NULL)
        testthat::expect_true(!is.null(values$token))
        testthat::expect_identical(
          values$token@access_token,
          "access-token"
        )
        testthat::expect_identical(
          as.integer(debug_after[["token_requests"]]),
          1L
        )
      }
    )
  }
)
