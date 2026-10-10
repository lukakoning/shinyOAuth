test_that("DPoP target normalization removes literal dot segments and preserves escapes", {
  paths <- c(
    "/a/../target" = "/target",
    "/a/./target" = "/a/target",
    "/a/b/c/./../../g" = "/a/g",
    "/a/b/c/g/." = "/a/b/c/g/",
    "/a/b/c/g/.." = "/a/b/c/",
    "/../../g" = "/g",
    "/a//b/../" = "/a//",
    "/a//../b" = "/a/b",
    "/a/..//g" = "//g",
    "/a%2Fb/./target" = "/a%2Fb/target",
    "/a%2fb/../target" = "/target",
    "/a/%2e%2e/target" = "/a/%2e%2e/target",
    "/a/%2E/target" = "/a/%2E/target",
    "/a/.%2e/target" = "/a/.%2e/target",
    "/a/%252e%252e/target" = "/a/%252e%252e/target",
    "/a%3Ab/./c%3Bd" = "/a%3Ab/c%3Bd",
    "/a/.../target" = "/a/.../target",
    "/caf%C3%A9" = "/caf%C3%A9",
    "/caf%c3%a9" = "/caf%c3%a9"
  )
  # Build Unicode names at runtime: symbol names are native-encoded by R's parser.
  paths <- c(
    paths,
    stats::setNames(
      c("/caf%C3%A9", "/%E6%97%A5%E6%9C%AC%2F%F0%9F%98%80"),
      c("/caf\u00e9", "/caf\u00e9/../\u65e5\u672c%2F\U0001f600")
    )
  )
  for (path in names(paths)) {
    url <- paste0("HTTPS://API.EXAMPLE.COM:443", path, "?x=%2F..%2F#frag")
    expect_identical(
      shinyOAuth:::normalize_dpop_request_url(url),
      paste0("HTTPS://API.EXAMPLE.COM:443", paths[[path]], "?x=%2F..%2F#frag")
    )
    expect_identical(
      shinyOAuth:::dpop_target_uri(url),
      paste0("https://api.example.com", paths[[path]])
    )
  }
})

test_that("DPoP resource and provider proofs agree with transmitted paths", {
  skip_if_not_installed("webfakes")
  app <- webfakes::new_app()
  app[["use"]](function(req, res) {
    # webfakes can mix raw UTF-8 bytes and percent escapes in req$url on macOS.
    # Echo bytes so JSON serialization does not require a valid UTF-8 string.
    res[["send_json"]](list(
      url = as.integer(charToRaw(req[["url"]])),
      proof = req[["get_header"]]("dpop")
    ))
  })
  server <- webfakes::local_app_process(app)
  origin <- sub("/+$", "", server[["url"]]())
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-path-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  paths <- c(
    "/a/../target" = "/target",
    "/a/./target" = "/a/target",
    "/a/b/." = "/a/b/",
    "/a/..//target" = "//target",
    "/a%2Fb/./target" = "/a%2Fb/target",
    "/a/%2e%2e/target" = "/a/%2e%2e/target",
    "/a%3Ab/../c%3Bd" = "/c%3Bd",
    "/caf%C3%A9" = "/caf%C3%A9",
    "/caf%c3%a9" = "/caf%c3%a9"
  )
  paths <- c(
    paths,
    stats::setNames(
      c("/caf%C3%A9", "/%E6%97%A5%E6%9C%AC%2F%F0%9F%98%80"),
      c("/caf\u00e9", "/caf\u00e9/../\u65e5\u672c%2F\U0001f600")
    )
  )
  for (path in names(paths)) {
    expected <- paths[[path]]
    for (as_is in c(FALSE, TRUE)) {
      sent <- character()
      request <- httr2::request(paste0(origin, path, "?existing=a%2Fb#frag")) |>
        httr2::req_options(
          path_as_is = as_is,
          verbose = TRUE,
          debugfunction = function(type, data) {
            if (type == 2L) {
              sent <<- c(sent, rawToChar(data))
            }
          }
        )
      response <- perform_resource_req(
        "access-token",
        request,
        token_type = "DPoP",
        client = client,
        query = list(page = 1L),
        idempotent = FALSE
      )
      body <- httr2::resp_body_json(response)
      payload <- shinyOAuth:::parse_jwt_payload(as.character(body[["proof"]]))
      expect_identical(payload[["htu"]], paste0(origin, expected))
      expect_identical(
        charToRaw(utils::URLdecode(sub(
          "[?].*$",
          "",
          rawToChar(as.raw(body[["url"]])),
          useBytes = TRUE
        ))),
        charToRaw(utils::URLdecode(paste0(origin, expected)))
      )
      # webfakes decodes paths; curl's request line preserves the actual escapes.
      expect_length(sent, 1L)
      expect_true(startsWith(sent[[1L]], paste0("GET ", expected, "?")))
      expect_match(sent[[1L]], "existing=a%2Fb", fixed = TRUE)
      expect_match(sent[[1L]], "page=1", fixed = TRUE)
      expect_false(grepl("#frag", sent[[1L]], fixed = TRUE))
    }
  }

  request <- httr2::request(paste0(
    origin,
    "/a/../caf\u00e9/token?resource=api"
  )) |>
    httr2::req_method("POST") |>
    httr2::req_options(path_as_is = TRUE, followlocation = FALSE)
  response <- shinyOAuth:::req_with_dpop_retry(
    request,
    client,
    idempotent = FALSE
  )
  body <- httr2::resp_body_json(response)
  payload <- shinyOAuth:::parse_jwt_payload(as.character(body[["proof"]]))
  expect_identical(payload[["htu"]], paste0(origin, "/caf%C3%A9/token"))
  expect_identical(payload[["htm"]], "POST")
  expect_identical(
    charToRaw(utils::URLdecode(sub(
      "[?].*$",
      "",
      rawToChar(as.raw(body[["url"]])),
      useBytes = TRUE
    ))),
    charToRaw(enc2utf8(paste0(origin, "/caf\u00e9/token")))
  )
})

test_that("DPoP nonce cache scope follows normalized literal paths", {
  client <- oauth_client(
    provider = make_test_provider(),
    client_id = "dpop-path-test",
    client_secret = "secret",
    redirect_uri = "http://localhost:8100",
    dpop_private_key = openssl::ec_keygen()
  )
  expect_identical(
    shinyOAuth:::dpop_nonce_cache_key(client, "https://example.com/a/../token"),
    shinyOAuth:::dpop_nonce_cache_key(client, "https://example.com/token")
  )
  expect_false(identical(
    shinyOAuth:::dpop_nonce_cache_key(
      client,
      "https://example.com/a/%2e%2e/token"
    ),
    shinyOAuth:::dpop_nonce_cache_key(client, "https://example.com/token")
  ))
  expect_identical(
    shinyOAuth:::dpop_nonce_cache_key(client, "https://example.com/caf\u00e9"),
    shinyOAuth:::dpop_nonce_cache_key(client, "https://example.com/caf%C3%A9")
  )
})
