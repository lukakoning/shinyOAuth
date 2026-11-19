for (state_transport in c("encrypted", "reference")) {
  test_that(
    paste(
      "repeated PAR preparation retains fresh transactions with",
      state_transport,
      "state"
    ),
    {
      provider <- oauth_provider(
        name = "par-freshness",
        auth_url = "https://issuer.example/authorize",
        token_url = "https://issuer.example/token",
        par_url = "https://issuer.example/par",
        issuer = "https://issuer.example",
        jwks_uri = "https://issuer.example/jwks",
        token_auth_style = "public",
        use_pkce = TRUE,
        pkce_method = "S256",
        use_nonce = TRUE,
        id_token_validation = TRUE,
        id_token_required = TRUE,
        userinfo_required = FALSE,
        userinfo_id_token_match = FALSE,
        authorization_request_front_channel_mode = "minimal",
        extra_auth_params = list(
          login_hint = "fixture-user",
          prompt = "consent"
        )
      )
      client <- oauth_client(
        provider,
        client_id = "par-client",
        redirect_uri = "https://app.example/callback",
        scopes = c("openid", "profile"),
        resource = "https://api.example/accounts",
        state_transport = state_transport
      )
      browser <- valid_browser_token()
      references <- paste0("urn:ietf:params:oauth:request_uri:fresh-", 1:2)
      requests <- list()
      # Mock only HTTP responses; normal PAR construction, validation and state
      # storage run for both successful public preparations.
      local_mocked_bindings(
        req_perform = function(req, ...) {
          requests[[length(requests) + 1L]] <<- req
          expect_identical(req[["url"]], provider@par_url)
          expect_identical(req[["method"]], "POST")
          expect_lte(length(requests), length(references))
          httr2::response(
            url = req[["url"]],
            status = 201L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(jsonlite::toJSON(
              list(
                request_uri = references[[length(requests)]],
                expires_in = 90L
              ),
              auto_unbox = TRUE
            ))
          )
        },
        .package = "httr2"
      )
      urls <- list()
      payloads <- list()
      records <- list()
      keys <- character()
      forms <- list()
      for (i in seq_along(references)) {
        urls[[i]] <- prepare_call(client, browser_token = browser)
        expect_length(requests, i)
        request <- requests[[i]]
        expect_identical(request[["body"]][["type"]], "form")
        forms[[i]] <- lapply(request[["body"]][["data"]], function(value) {
          utils::URLdecode(as.character(value))
        })
        form <- forms[[i]]
        expect_identical(form[["client_id"]], client@client_id)
        expect_identical(form[["response_type"]], "code")
        expect_identical(form[["redirect_uri"]], client@redirect_uri)
        expect_identical(form[["scope"]], "openid profile")
        expect_identical(form[["resource"]], client@resource)
        expect_identical(form[["login_hint"]], "fixture-user")
        expect_identical(form[["prompt"]], "consent")
        expect_false(any(
          c("client_secret", "client_assertion", "request_uri") %in% names(form)
        ))
        expect_false("authorization" %in% tolower(names(request[["headers"]])))

        query <- httr2::url_parse(urls[[i]])[["query"]]
        expect_identical(sort(names(query)), c("client_id", "request_uri"))
        expect_identical(query[["client_id"]], client@client_id)
        expect_identical(query[["request_uri"]], references[[i]])
        expect_identical(
          attr(urls[[i]], "shinyOAuth.par_request_uri", exact = TRUE),
          references[[i]]
        )
        expect_identical(
          attr(urls[[i]], "shinyOAuth.par_expires_in", exact = TRUE),
          90
        )
        payloads[[i]] <- state_payload_decrypt_validate(client, form[["state"]])
        payload <- payloads[[i]]
        keys[[i]] <- state_cache_key(payload[["state"]])
        expect_length(unique(keys), i)
        expect_setequal(client@state_store[["keys"]](), keys)
        records[[i]] <- client@state_store[["get"]](keys[[i]])
        record <- state_store_get(client, payload[["state"]])
        expect_identical(record[["browser_token"]], browser)
        expect_identical(record[["nonce"]], form[["nonce"]])
        expect_match(record[["nonce"]], "^[A-Za-z0-9_-]{32}$")
        expect_identical(payload[["client_id"]], client@client_id)
        expect_identical(payload[["redirect_uri"]], client@redirect_uri)
        expect_match(record[["pkce_code_verifier"]], "^[A-Za-z0-9_-]{64}$")
        challenge <- openssl::base64_encode(openssl::sha256(charToRaw(
          record[["pkce_code_verifier"]]
        )))
        challenge <- sub("=+$", "", chartr("+/", "-_", challenge))
        expect_identical(form[["code_challenge_method"]], "S256")
        expect_identical(form[["code_challenge"]], challenge)
        for (j in seq_len(i)) {
          expect_identical(client@state_store[["get"]](keys[[j]]), records[[j]])
        }
      }
      expect_false(identical(forms[[1L]][["state"]], forms[[2L]][["state"]]))
      expect_false(identical(
        payloads[[1L]][["state"]],
        payloads[[2L]][["state"]]
      ))
      expect_false(identical(forms[[1L]][["nonce"]], forms[[2L]][["nonce"]]))
      expect_false(identical(
        forms[[1L]][["code_challenge"]],
        forms[[2L]][["code_challenge"]]
      ))
      expect_false(identical(
        records[[1L]][["pkce_code_verifier"]],
        records[[2L]][["pkce_code_verifier"]]
      ))
      expect_length(requests, 2L)
      expect_length(client@state_store[["keys"]](), 2L)
    }
  )
}
