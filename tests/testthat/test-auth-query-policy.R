test_that("authorization endpoint queries cannot carry unbound policy fields", {
  for (query in c(
    "prompt=login&max_age=0",
    "pr%6fmpt=login&max%5fage=0",
    "max_age=bad",
    "scope=openid",
    "resource=https%3A%2F%2Fapi.example",
    "response_mode=form_post",
    "claims=%7B%7D",
    "acr_values=strong",
    "login_hint=user",
    "id_token_hint=jwt",
    "display=popup",
    "ui_locales=en"
  )) {
    url <- paste0("https://example.com/auth?", query)
    expect_error(
      oauth_provider(
        "test",
        auth_url = url,
        token_url = "https://example.com/token"
      ),
      "query must not contain policy parameters"
    )
    client <- make_test_client()
    # Model a provider serialized before this validation was introduced.
    provider <- client@provider
    attr(provider, "auth_url") <- url
    expect_error(
      provider_auth_max_age(provider),
      "query must not contain policy parameters"
    )
    attr(client, "provider") <- provider
    expect_error(
      prepare_call(client, valid_browser_token()),
      "query must not contain policy parameters"
    )
    expect_length(client@state_store[["keys"]](), 0L)
  }
})

test_that("fixed protocol fields cannot enable disabled client features", {
  for (query in c(
    "nonce=fixed",
    "dpop_jkt=fixed",
    "request_uri=urn:example:request"
  )) {
    client <- make_test_client(use_nonce = FALSE)
    client@provider@auth_url <- paste0("https://example.com/auth?", query)
    expect_error(
      prepare_call(client, valid_browser_token()),
      "not enabled in the client"
    )
  }
})

test_that("configured freshness is signed, pushed and enforced in complete callbacks", {
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  jwk[["kid"]] <- "freshness"
  provider <- oauth_provider(
    "test",
    auth_url = "https://example.com/auth?routing=a%2Bb",
    token_url = "https://example.com/token",
    issuer = "https://example.com",
    use_nonce = TRUE,
    id_token_required = TRUE,
    id_token_validation = TRUE,
    userinfo_required = FALSE,
    userinfo_id_token_match = FALSE,
    extra_auth_params = list(prompt = "login", max_age = 0)
  )
  client <- oauth_client(
    provider,
    "client",
    client_secret = strrep("s", 32),
    redirect_uri = "http://localhost:8100",
    scopes = "openid"
  )
  pushed <- NULL
  id_token <- NULL
  local_mocked_bindings(
    fetch_jwks = function(...) list(keys = list(jwk)),
    req_with_dpop_retry = function(req, ...) {
      httr2::response(
        url = req[["url"]],
        status_code = 200L,
        headers = list(`content-type` = "application/json"),
        body = charToRaw(jsonlite::toJSON(
          list(
            access_token = "synthetic-access",
            token_type = "Bearer",
            expires_in = 60,
            id_token = id_token,
            scope = "openid"
          ),
          auto_unbox = TRUE
        ))
      )
    },
    push_authorization_request = function(client, params, ...) {
      pushed <<- params
      list(request_uri = "urn:example:pushed", expires_in = 60)
    }
  )
  for (mode in c("direct", "jar", "par", "jar_par")) {
    client@request_object_mode <- if (mode %in% c("jar", "jar_par")) {
      "request"
    } else {
      "parameters"
    }
    client@provider@par_url <- if (mode %in% c("par", "jar_par")) {
      "https://example.com/par"
    } else {
      NA_character_
    }
    for (age in list(NULL, 3600, 0)) {
      browser <- valid_browser_token()
      url <- prepare_call(client, browser)
      expect_match(url, "routing=a%2Bb", fixed = TRUE)
      params <- if (mode %in% c("par", "jar_par")) {
        pushed
      } else {
        decode_form_pairs(url_raw_query(url))
      }
      if (mode %in% c("jar", "jar_par")) {
        parts <- strsplit(params[["request"]], ".", fixed = TRUE)[[1L]]
        expect_identical(
          parts[[3L]],
          base64url_encode(openssl::sha256(
            charToRaw(paste(parts[1:2], collapse = ".")),
            key = charToRaw(client@client_secret)
          ))
        )
        params <- parse_jwt_payload(params[["request"]])
        expect_true(is.numeric(params[["max_age"]]))
      }
      expect_identical(params[["prompt"]], "login")
      expect_equal(as.numeric(params[["max_age"]]), 0)
      state <- params[["state"]]
      expect_equal(
        state_decrypt_gcm(state, key = client@state_key)[["max_age"]],
        0
      )
      now <- as.numeric(Sys.time())
      claims <- list(
        iss = provider@issuer,
        sub = "subject",
        aud = client@client_id,
        iat = now,
        exp = now + 300,
        nonce = params[["nonce"]]
      )
      if (!is.null(age)) {
        claims[["auth_time"]] <- now - age
      }
      id_token <- jose::jwt_encode_sig(
        do.call(jose::jwt_claim, claims),
        key,
        header = list(kid = jwk[["kid"]])
      )
      if (is.null(age) || age > 0) {
        expect_error(
          handle_callback(client, "code", state, browser_token = browser),
          "auth_time"
        )
      } else {
        token <- handle_callback(client, "code", state, browser_token = browser)
        expect_true(token@id_token_validated)
      }
    }
  }
})
