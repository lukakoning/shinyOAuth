make_dpop_test_client <- function(
  provider,
  dpop_require_access_token = FALSE
) {
  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ),
    dpop_private_key = openssl::rsa_keygen(),
    dpop_require_access_token = dpop_require_access_token
  )
}

decode_dpop_payload <- function(proof) {
  parts <- strsplit(proof, ".", fixed = TRUE)[[1]]
  jsonlite::fromJSON(shinyOAuth:::base64url_decode(parts[[2]]))
}

test_that("client_bearer_req builds DPoP authorization and proof headers", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  cli <- make_dpop_test_client(prov)
  tok <- OAuthToken(
    access_token = "access-token",
    token_type = "DPoP",
    userinfo = list()
  )

  req <- client_bearer_req(
    token = tok,
    url = "https://resource.example.com/api",
    oauth_client = cli
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_identical(dry$headers$authorization, "DPoP access-token")
  expect_true(nzchar(dry$headers$dpop))

  payload <- decode_dpop_payload(dry$headers$dpop)
  expect_identical(payload$htm, "GET")
  expect_identical(payload$htu, "https://resource.example.com/api")
  expect_true(nzchar(payload$ath))
})

test_that("verify_token_type_allowlist enforces DPoP client requirements", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  prov@allowed_token_types <- c("Bearer", "DPoP")

  cli_no_dpop <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = cachem::cache_mem(max_age = 600),
    state_key = paste0(
      "0123456789abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
  )

  expect_error(
    shinyOAuth:::verify_token_type_allowlist(
      cli_no_dpop,
      list(access_token = "t", token_type = "DPoP")
    ),
    regexp = "dpop_private_key",
    class = "shinyOAuth_token_error"
  )

  cli_strict <- make_dpop_test_client(
    prov,
    dpop_require_access_token = TRUE
  )

  expect_error(
    shinyOAuth:::verify_token_type_allowlist(
      cli_strict,
      list(access_token = "t", token_type = "Bearer")
    ),
    regexp = "Expected token_type = DPoP",
    class = "shinyOAuth_token_error"
  )
})

test_that("swap_code_for_token_set retries once on DPoP nonce challenge", {
  testthat::skip_if_not_installed("webfakes")

  state <- new.env(parent = emptyenv())
  state$count <- 0L
  state$first_has_nonce <- NA
  state$second_nonce <- NA_character_

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    state$count <- state$count + 1L
    payload <- decode_dpop_payload(req$get_header("dpop"))
    if (state$count == 1L) {
      state$first_has_nonce <- "nonce" %in% names(payload)
      res$set_status(400)
      res$set_header("DPoP-Nonce", "nonce-1")
      res$set_type("application/json")
      res$send(jsonlite::toJSON(
        list(error = "use_dpop_nonce"),
        auto_unbox = TRUE
      ))
      return()
    }

    state$second_nonce <- payload$nonce %||% NA_character_

    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        access_token = "at-1",
        token_type = "DPoP",
        expires_in = 60,
        request_count = state$count,
        first_has_nonce = isTRUE(state$first_has_nonce),
        second_nonce = state$second_nonce
      ),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = paste0(srv$url(), "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    revocation_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- make_dpop_test_client(prov)

  token_set <- shinyOAuth:::swap_code_for_token_set(
    cli,
    code = "code-1",
    code_verifier = "verifier-1"
  )

  expect_identical(token_set$access_token, "at-1")
  expect_identical(token_set$token_type, "DPoP")
  expect_identical(token_set$request_count, 2L)
  expect_false(isTRUE(token_set$first_has_nonce))
  expect_identical(token_set$second_nonce, "nonce-1")
})

test_that("refresh_token sends DPoP proof and preserves DPoP token_type", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    proof <- req$get_header("dpop")
    if (!nzchar(proof %||% "")) {
      res$set_status(400)
      res$set_type("application/json")
      res$send(jsonlite::toJSON(
        list(error = "missing_dpop"),
        auto_unbox = TRUE
      ))
      return()
    }

    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        access_token = proof,
        token_type = "DPoP",
        refresh_token = "new-refresh",
        expires_in = 60
      ),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = paste0(srv$url(), "/token"),
    userinfo_url = NA_character_,
    introspection_url = NA_character_,
    revocation_url = NA_character_,
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- make_dpop_test_client(prov)
  tok <- OAuthToken(
    access_token = "old-access",
    token_type = "DPoP",
    refresh_token = "refresh-1",
    userinfo = list()
  )

  refreshed <- refresh_token(cli, tok)
  payload <- decode_dpop_payload(refreshed@access_token)

  expect_identical(refreshed@refresh_token, "new-refresh")
  expect_identical(refreshed@token_type, "DPoP")
  expect_identical(payload$htm, "POST")
  expect_identical(payload$htu, paste0(sub("/+$", "", srv$url()), "/token"))
})

test_that("revoke_token, introspect_token, and get_userinfo send DPoP proofs", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/revoke", function(req, res) {
    if (!nzchar(req$get_header("dpop") %||% "")) {
      res$set_status(400)
      res$send("")
      return()
    }
    res$set_status(200)
    res$send("")
  })
  app$post("/introspect", function(req, res) {
    if (!nzchar(req$get_header("dpop") %||% "")) {
      res$set_status(400)
      res$set_type("application/json")
      res$send(jsonlite::toJSON(
        list(active = FALSE),
        auto_unbox = TRUE
      ))
      return()
    }
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(active = TRUE),
      auto_unbox = TRUE
    ))
  })
  app$get("/userinfo", function(req, res) {
    auth <- req$get_header("authorization") %||% ""
    proof <- req$get_header("dpop") %||% ""
    if (!identical(auth, "DPoP at-1") || !nzchar(proof)) {
      res$set_status(401)
      res$set_type("application/json")
      res$send(jsonlite::toJSON(
        list(error = "missing_dpop"),
        auto_unbox = TRUE
      ))
      return()
    }
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(sub = "user-1"),
      auto_unbox = TRUE
    ))
  })
  srv <- webfakes::local_app_process(app)

  prov <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    userinfo_url = paste0(srv$url(), "/userinfo"),
    introspection_url = paste0(srv$url(), "/introspect"),
    revocation_url = paste0(srv$url(), "/revoke"),
    issuer = NA_character_,
    use_nonce = FALSE,
    use_pkce = TRUE,
    pkce_method = "S256",
    userinfo_required = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_id_token_match = FALSE,
    token_auth_style = "body"
  )
  cli <- make_dpop_test_client(prov)
  tok <- OAuthToken(
    access_token = "at-1",
    token_type = "DPoP",
    refresh_token = "rt-1",
    userinfo = list()
  )

  revoke_res <- revoke_token(cli, tok, which = "access")
  intro_res <- introspect_token(cli, tok, which = "access")
  userinfo <- get_userinfo(cli, token = "at-1", token_type = "DPoP")

  expect_true(isTRUE(revoke_res$supported))
  expect_true(isTRUE(intro_res$active))
  expect_identical(userinfo$sub, "user-1")
})
