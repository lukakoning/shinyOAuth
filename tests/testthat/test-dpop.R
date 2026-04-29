make_dpop_test_client <- function(
  provider,
  dpop_require_access_token = FALSE,
  dpop_private_key = openssl::rsa_keygen(),
  dpop_private_key_kid = NULL,
  dpop_signing_alg = NULL
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
    dpop_private_key = dpop_private_key,
    dpop_private_key_kid = dpop_private_key_kid,
    dpop_signing_alg = dpop_signing_alg,
    dpop_require_access_token = dpop_require_access_token
  )
}

decode_dpop_header <- function(proof) {
  parts <- strsplit(proof, ".", fixed = TRUE)[[1]]
  jsonlite::fromJSON(shinyOAuth:::base64url_decode(parts[[1]]))
}

decode_dpop_payload <- function(proof) {
  parts <- strsplit(proof, ".", fixed = TRUE)[[1]]
  jsonlite::fromJSON(shinyOAuth:::base64url_decode(parts[[2]]))
}

verify_dpop_rs256_signature <- function(proof, pubkey) {
  parts <- strsplit(proof, ".", fixed = TRUE)[[1]]
  sig <- shinyOAuth:::base64url_decode_raw(parts[[3]])
  signed_data <- charToRaw(paste(parts[1:2], collapse = "."))
  digest <- openssl::sha2(signed_data, size = 256)
  openssl::signature_verify(
    digest,
    sig,
    hash = NULL,
    pubkey = pubkey
  )
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

test_that("client_bearer_req requires a DPoP-capable client for DPoP tokens", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  tok <- OAuthToken(
    access_token = "access-token",
    token_type = "DPoP",
    userinfo = list()
  )

  expect_error(
    client_bearer_req(
      token = tok,
      url = "https://resource.example.com/api"
    ),
    regexp = "oauth_client must be an OAuthClient",
    class = "shinyOAuth_input_error"
  )

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
    client_bearer_req(
      token = tok,
      url = "https://resource.example.com/api",
      oauth_client = cli_no_dpop
    ),
    regexp = "dpop_private_key",
    class = "shinyOAuth_input_error"
  )
})

test_that("client_bearer_req ignores custom Authorization and DPoP headers", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  cli <- make_dpop_test_client(prov)
  tok <- OAuthToken(
    access_token = "access-token",
    token_type = "DPoP",
    userinfo = list()
  )

  expect_warning(
    req <- client_bearer_req(
      token = tok,
      url = "https://resource.example.com/api",
      oauth_client = cli,
      headers = list(
        Authorization = "Bearer attacker-token",
        DPoP = "attacker-proof",
        `X-Test` = "ok"
      )
    ),
    regexp = "Ignoring custom 'Authorization' or 'DPoP' header",
    fixed = TRUE
  )

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  expect_identical(dry$headers$authorization, "DPoP access-token")
  expect_true(nzchar(dry$headers$dpop))
  expect_false(identical(dry$headers$dpop, "attacker-proof"))
  expect_identical(dry$headers$`x-test`, "ok")

  payload <- decode_dpop_payload(dry$headers$dpop)
  expect_identical(
    payload$ath,
    shinyOAuth:::dpop_access_token_hash(
      "access-token"
    )
  )
})

test_that("client_bearer_req signs DPoP proof with method and target URI", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  cli <- make_dpop_test_client(prov)
  tok <- OAuthToken(
    access_token = "access-token",
    token_type = "DPoP",
    userinfo = list()
  )

  req <- client_bearer_req(
    token = tok,
    url = "https://resource.example.com/api?from=url",
    method = "patch",
    query = list(a = 1),
    oauth_client = cli
  )

  expect_identical(req$method, "PATCH")
  expect_match(req$url, "from=url", fixed = TRUE)
  expect_match(req$url, "a=1", fixed = TRUE)

  dry <- httr2::req_dry_run(req, quiet = TRUE, redact_headers = FALSE)
  payload <- decode_dpop_payload(dry$headers$dpop)

  expect_identical(payload$htm, "PATCH")
  expect_identical(payload$htu, "https://resource.example.com/api")
  expect_identical(
    payload$ath,
    shinyOAuth:::dpop_access_token_hash(
      "access-token"
    )
  )
})

test_that("build_dpop_proof creates a signed proof with bound claims", {
  key <- openssl::rsa_keygen()
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  cli <- make_dpop_test_client(
    prov,
    dpop_private_key = key,
    dpop_private_key_kid = "dpop-kid-1"
  )

  proof <- shinyOAuth:::build_dpop_proof(
    cli,
    method = "post",
    url = "https://resource.example.com/api?ignored=true#frag",
    access_token = "access-token",
    nonce = "nonce-1"
  )
  proof2 <- shinyOAuth:::build_dpop_proof(
    cli,
    method = "POST",
    url = "https://resource.example.com/api",
    access_token = "access-token"
  )

  header <- decode_dpop_header(proof)
  payload <- decode_dpop_payload(proof)
  payload2 <- decode_dpop_payload(proof2)

  expect_identical(header$typ, "dpop+jwt")
  expect_identical(header$alg, "RS256")
  expect_identical(header$kid, "dpop-kid-1")
  expect_true(is.list(header$jwk))
  expect_length(
    intersect(
      names(header$jwk),
      c("d", "p", "q", "dp", "dq", "qi", "oth", "k")
    ),
    0L
  )

  pub <- openssl::read_pubkey(openssl::write_pem(key))
  expect_true(verify_dpop_rs256_signature(proof, pub))

  expect_identical(payload$htm, "POST")
  expect_identical(payload$htu, "https://resource.example.com/api")
  expect_identical(
    payload$ath,
    shinyOAuth:::dpop_access_token_hash("access-token")
  )
  expect_identical(payload$nonce, "nonce-1")
  expect_true(nzchar(payload$jti))
  expect_false(identical(payload$jti, payload2$jti))
  expect_lte(abs(as.numeric(Sys.time()) - as.numeric(payload$iat)), 5)
})

test_that("oauth_client rejects incompatible explicit DPoP signing algs", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)

  expect_error(
    make_dpop_test_client(
      prov,
      dpop_signing_alg = "eddsa"
    ),
    regexp = paste0(
      "dpop_signing_alg 'EdDSA' is incompatible with DPoP"
    )
  )

  key_ec <- try(openssl::ec_keygen(curve = "P-256"), silent = TRUE)
  if (inherits(key_ec, "try-error")) {
    testthat::skip("EC key generation not supported on this platform")
  }

  expect_error(
    make_dpop_test_client(
      prov,
      dpop_private_key = key_ec,
      dpop_signing_alg = "ES512"
    ),
    regexp = paste(
      "dpop_signing_alg 'ES512' is incompatible",
      "with the provided dpop_private_key"
    )
  )

  key_ed <- try(openssl::ed25519_keygen(), silent = TRUE)
  if (inherits(key_ed, "try-error")) {
    testthat::skip("Ed25519 key generation not supported on this platform")
  }

  expect_error(
    make_dpop_test_client(
      prov,
      dpop_private_key = key_ed
    ),
    regexp = paste(
      "outbound DPoP proofs currently support RSA and ECDSA",
      "private keys only"
    )
  )
})

test_that("build_dpop_proof rejects incompatible resolved algs", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  cli <- make_dpop_test_client(prov)

  testthat::local_mocked_bindings(
    resolve_dpop_alg = function(client) {
      "EdDSA"
    },
    .package = "shinyOAuth"
  )

  expect_error(
    shinyOAuth:::build_dpop_proof(
      cli,
      method = "GET",
      url = "https://resource.example.com/api"
    ),
    regexp = paste(
      "dpop_signing_alg 'EdDSA' is incompatible",
      "with the configured dpop_private_key"
    )
  )
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

test_that("verify_token_type_allowlist accepts DPoP when client enables it", {
  prov <- make_test_provider(use_pkce = TRUE, use_nonce = FALSE)
  expect_false(any(tolower(prov@allowed_token_types) == "dpop"))

  cli <- make_dpop_test_client(prov)

  expect_silent(
    shinyOAuth:::verify_token_type_allowlist(
      cli,
      list(access_token = "t", token_type = "DPoP")
    )
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

test_that("req_with_dpop_retry retries a nonce challenge only once", {
  testthat::skip_if_not_installed("webfakes")

  state <- new.env(parent = emptyenv())
  state$count <- 0L

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    state$count <- state$count + 1L
    payload <- decode_dpop_payload(req$get_header("dpop"))
    res$set_status(400)
    res$set_header("DPoP-Nonce", paste0("nonce-", state$count))
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        error = "use_dpop_nonce",
        request_count = state$count,
        proof_nonce = payload$nonce %||% NA_character_
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
  req <- httr2::request(prov@token_url) |>
    httr2::req_method("POST") |>
    httr2::req_body_form(grant_type = "authorization_code")

  resp <- shinyOAuth:::req_with_dpop_retry(req, cli, idempotent = FALSE)
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)

  expect_identical(httr2::resp_status(resp), 400L)
  expect_equal(body$request_count, 2L)
  expect_identical(body$proof_nonce, "nonce-1")
})

test_that("handle_callback enforces strict DPoP token_type after exchange", {
  testthat::skip_if_not_installed("webfakes")

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    if (!nzchar(req$get_header("dpop") %||% "")) {
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
        access_token = "at-1",
        token_type = "Bearer",
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
  cli <- make_dpop_test_client(prov, dpop_require_access_token = TRUE)
  browser_token <- paste(rep("a", 128), collapse = "")
  auth_url <- prepare_call(cli, browser_token = browser_token)
  payload <- utils::URLdecode(sub(".*[?&]state=([^&]+).*", "\\1", auth_url))

  expect_error(
    shinyOAuth:::handle_callback(
      oauth_client = cli,
      code = "code-1",
      payload = payload,
      browser_token = browser_token
    ),
    regexp = "Expected token_type = DPoP",
    class = "shinyOAuth_token_error"
  )
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

test_that("refresh_token retries once on DPoP nonce challenge", {
  testthat::skip_if_not_installed("webfakes")

  state <- new.env(parent = emptyenv())
  state$count <- 0L

  app <- webfakes::new_app()
  app$post("/token", function(req, res) {
    state$count <- state$count + 1L
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

    if (state$count == 1L) {
      res$set_status(400)
      res$set_header("DPoP-Nonce", "refresh-nonce-1")
      res$set_type("application/json")
      res$send(jsonlite::toJSON(
        list(error = "use_dpop_nonce"),
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
  expect_identical(payload$nonce, "refresh-nonce-1")
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

test_that("get_userinfo retries a resource DPoP nonce challenge", {
  testthat::skip_if_not_installed("webfakes")

  state <- new.env(parent = emptyenv())
  state$count <- 0L
  state$first_has_nonce <- NA
  state$second_nonce <- NA_character_

  app <- webfakes::new_app()
  app$get("/userinfo", function(req, res) {
    state$count <- state$count + 1L
    payload <- decode_dpop_payload(req$get_header("dpop"))
    if (state$count == 1L) {
      state$first_has_nonce <- "nonce" %in% names(payload)
      res$set_status(401)
      res$set_header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
      res$set_header("DPoP-Nonce", "resource-nonce-1")
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
        sub = "user-1",
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
    token_url = "https://example.com/token",
    userinfo_url = paste0(srv$url(), "/userinfo"),
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

  userinfo <- get_userinfo(cli, token = "at-1", token_type = "DPoP")

  expect_identical(userinfo$sub, "user-1")
  expect_identical(userinfo$request_count, 2L)
  expect_false(isTRUE(userinfo$first_has_nonce))
  expect_identical(userinfo$second_nonce, "resource-nonce-1")
})
