test_that("authentication challenge parsing preserves long quoted parameters", {
  realm <- paste0(strrep("a", 60000L), ',quoted\\"text')
  header <- paste0(
    'Bearer realm="other", DPoP realm="', realm,
    '", error="use_dpop_nonce"'
  )
  parsed <- parse_http_auth_challenges(header)
  expect_length(parsed, 2L)
  expect_identical(parsed[[2L]][["scheme"]], "DPoP")
  expect_identical(parsed[[2L]][["params"]][["realm"]], sub('\\"', '"', realm, fixed = TRUE))
  expect_identical(parsed[[2L]][["params"]][["error"]], "use_dpop_nonce")
})

test_that("authentication challenge byte and part budgets fail explicitly", {
  expect_error(
    parse_http_auth_challenges(strrep("a", 65537L)),
    "WWW-Authenticate.*65536 bytes",
    class = "shinyOAuth_token_error"
  )
  at_limit <- paste(c("DPoP", rep('p="x"', 255L)), collapse = ", ")
  expect_length(parse_http_auth_challenges(at_limit), 1L)
  expect_error(
    parse_http_auth_challenges(paste0(at_limit, ', p="x"')),
    "WWW-Authenticate.*256 challenge/parameter parts",
    class = "shinyOAuth_token_error"
  )
  expect_identical(parse_http_auth_challenges(", DPoP realm=\"x\", ")[[1L]][["scheme"]], "DPoP")
})

test_that("resource requests reject oversized DPoP challenges before retrying", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app[["use"]](function(req, res) {
    res[["set_status"]](401L)
    res[["set_header"]]("DPoP-Nonce", "synthetic-nonce")
    res[["set_header"]](
      "WWW-Authenticate",
      paste0('DPoP realm="', strrep("a", 100000L), '", error="use_dpop_nonce"')
    )
    res[["send"]]("")
  })
  server <- webfakes::new_app_process(app)
  on.exit(server[["stop"]](), add = TRUE)
  client <- oauth_client(
    make_test_provider(), client_id = "challenge-test",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  local_options(shinyOAuth.timeout = 1, shinyOAuth.retry_max_tries = 1)
  expect_error(
    perform_resource_req(
      "synthetic-token", server[["url"]]("/resource"),
      client = client, token_type = "DPoP"
    ),
    "WWW-Authenticate.*65536 bytes",
    class = "shinyOAuth_token_error"
  )
})
