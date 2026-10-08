test_that("enforced UserInfo claims require an enabled fetch path", {
  provider <- make_test_provider(use_nonce = TRUE)
  provider@userinfo_url <- "https://example.com/userinfo"
  args <- list(
    provider = provider, client_id = "abc", client_secret = "",
    redirect_uri = "http://localhost:8100", scopes = "openid",
    state_key = strrep("a", 64)
  )
  requests <- list(
    list(userinfo = list(email = list(essential = TRUE))),
    list(userinfo = list(email_verified = list(value = TRUE))),
    '{"userinfo":{"email":{"values":["verified@example.com"]}}}'
  )
  for (mode in c("warn", "strict")) {
    for (claims in requests) {
      args[["claims"]] <- claims
      args[["claims_validation"]] <- mode
      expect_error(do.call(oauth_client, args), "requires the provider to fetch UserInfo")
      expect_error(do.call(OAuthClient, args), "requires the provider to fetch UserInfo")
    }
  }
  args[["claims_validation"]] <- "none"
  expect_no_error(do.call(oauth_client, args))
  args[["claims"]] <- list(userinfo = list(email = NULL))
  args[["claims_validation"]] <- "strict"
  expect_no_error(do.call(oauth_client, args))
})

test_that("property changes cannot disable enforced UserInfo validation", {
  claims <- list(userinfo = list(email_verified = list(value = TRUE)))
  client <- make_test_client(claims = claims, claims_validation = "strict")
  disabled <- client@provider
  disabled@userinfo_required <- FALSE
  expect_error(client@provider <- disabled, "requires the provider to fetch UserInfo")

  client <- make_test_client(claims = claims, claims_validation = "none")
  expect_error(client@claims_validation <- "strict", "requires the provider to fetch UserInfo")
  client <- make_test_client(claims_validation = "strict")
  expect_error(client@claims <- claims, "requires the provider to fetch UserInfo")
})

test_that("signed OIDC login and refresh enforce the requested UserInfo value", {
  client <- make_test_client(
    use_nonce = TRUE,
    claims = list(userinfo = list(email_verified = list(value = TRUE))),
    claims_validation = "strict"
  )
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(write_test_jwk(key[["pubkey"]]), simplifyVector = FALSE)
  profile_verified <- TRUE
  id_token <- NULL
  response <- function(req, ...) {
      body <- if (identical(req[["url"]], client@provider@userinfo_url)) {
        list(sub = "user1", email_verified = profile_verified)
      } else {
        token_set <- list(
          access_token = "new-access", refresh_token = "new-refresh",
          token_type = "Bearer", expires_in = 3600
        )
        token_set[["id_token"]] <- id_token
        token_set
      }
      httr2::response(
        url = req[["url"]], status = 200,
        headers = list("content-type" = "application/json"),
        body = charToRaw(jsonlite::toJSON(body, auto_unbox = TRUE))
      )
  }
  local_mocked_bindings(
    fetch_client_jwks = function(...) list(keys = list(jwk)),
    req_with_dpop_retry = response,
    req_with_retry = response,
    .package = "shinyOAuth"
  )
  login <- function() {
    browser_token <- valid_browser_token()
    query <- httr2::url_parse(prepare_call(client, browser_token))[["query"]]
    now <- floor(as.numeric(Sys.time()))
    id_token <<- jose::jwt_encode_sig(
      jose::jwt_claim(
        iss = client@provider@issuer, sub = "user1", aud = client@client_id,
        nonce = query[["nonce"]], iat = now, exp = now + 3600
      ), key = key
    )
    handle_callback(client, "code", query[["state"]], browser_token)
  }
  token <- login()
  expect_true(token@id_token_validated)
  expect_true(token@userinfo[["email_verified"]])
  profile_verified <- FALSE
  expect_error(login(), class = "shinyOAuth_userinfo_error")
  id_token <- NULL
  expect_error(refresh_token(client, token), class = "shinyOAuth_userinfo_error")
})
