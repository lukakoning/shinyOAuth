test_that("rejected GET and POST callbacks clean URLs without consuming pending authorization", {
  for (post in c(FALSE, TRUE)) {
    for (transport in c("encrypted", "reference")) {
      client <- make_test_client(
        response_mode = if (post) "form_post" else "query"
      )
      client@state_transport <- transport
      client@redirect_uri <- "http://localhost:8100/callback?tenant=one"
      browser <- valid_browser_token()
      state <- parse_query_param(
        prepare_call(client, browser),
        "state",
        decode = TRUE
      )
      rendered <- 0L
      ui <- (if (post) oauth_form_post_ui else oauth_ui)(
        function(req) {
          rendered <<- rendered + 1L
          shiny::fluidPage("App")
        },
        "auth",
        client
      )
      request <- function(fields) {
        encoded <- httr2::url_query_build(fields)
        if (post) {
          callback_rejection_request("tenant=one", encoded)
        } else {
          callback_rejection_request(paste0("tenant=one&", encoded))
        }
      }
      good <- ui(request(list(code = "RIGHTFUL-CODE", state = state)))
      expect_identical(good[["status"]], 303L)
      good_handle <- parse_query_param(
        good[["headers"]][["Location"]],
        "shinyOAuth_form_post",
        decode = TRUE
      )
      keys <- client@state_store[["keys"]]()
      records <- lapply(keys, function(key) client@state_store[["get"]](key))
      requests <- 0L
      local_mocked_bindings(
        req_perform = function(req, ...) {
          requests <<- requests + 1L
          expect_identical(req[["url"]], client@provider@token_url)
          httr2::response(
            status = 200L,
            headers = list("content-type" = "application/json"),
            body = charToRaw(
              '{"access_token":"RIGHTFUL-TOKEN","token_type":"Bearer","expires_in":3600}'
            )
          )
        },
        .package = "httr2"
      )
      rejected_req <- request(list(
        code = "SECRET-CODE",
        error = "access_denied",
        state = state
      ))
      rejected <- ui(rejected_req)
      expect_identical(rejected[["status"]], 303L)
      location <- rejected[["headers"]][["Location"]]
      expect_match(
        location,
        "^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$"
      )
      expect_false(grepl("SECRET|tenant|[?&](state|code|error)=", location))
      expect_identical(rejected[["content"]], "")
      expect_identical(
        rejected[["headers"]][["Referrer-Policy"]],
        "no-referrer"
      )
      expect_identical(rejected[["headers"]][["Cache-Control"]], "no-store")
      mixed <- callback_rejection_request(paste0(
        sub("#$", "", sub("^\\?", "", location)),
        "&",
        sub("^\\?", "", good[["headers"]][["Location"]])
      ))
      mixed_response <- ui(mixed)
      expect_identical(mixed_response[["status"]], 303L)
      expect_identical(
        callback_rejection_terminal(ui, mixed, mixed_response)[["status"]],
        400L
      )
      expect_identical(requests, 0L)
      expect_identical(
        lapply(keys, function(key) client@state_store[["get"]](key)),
        records
      )
      final <- callback_rejection_terminal(ui, rejected_req, rejected)
      expect_identical(final[["status"]], 400L)
      expect_identical(
        final[["content"]],
        "OAuth form_post callback must not contain both code and error."
      )
      expect_false(grepl("SECRET|RIGHTFUL|state=", final[["content"]]))
      expect_identical(final[["headers"]][["Cache-Control"]], "no-store")
      expect_identical(final[["headers"]][["Referrer-Policy"]], "no-referrer")
      expect_identical(rendered, 0L)
      expect_identical(requests, 0L)
      expect_identical(client@state_store[["keys"]](), keys)
      expect_identical(
        lapply(keys, function(key) client@state_store[["get"]](key)),
        records
      )
      replay <- callback_rejection_terminal(ui, rejected_req, rejected)
      expect_identical(replay[["status"]], 400L)
      expect_match(replay[["content"]], "unavailable or already consumed")
      accepted <- oauth_form_post_store_take(client, "auth", good_handle)
      expect_identical(accepted[["code"]], "RIGHTFUL-CODE")
      token <- handle_callback(
        client,
        accepted[["code"]],
        accepted[["state"]],
        browser
      )
      expect_identical(token@access_token, "RIGHTFUL-TOKEN")
      expect_identical(requests, 1L)
    }
  }
})

test_that("rejection diagnostics retain the actual JARM category without received values", {
  withr::local_options(
    shinyOAuth.expose_error_body = TRUE,
    cli.num_colors = 256
  )
  expect_true(cli::ansi_has_any(cli::format_inline("{.pkg shinyOAuth}")))
  client <- make_test_client(scopes = "openid")
  client@redirect_uri <- "http://localhost:8100/callback"
  client@provider@issuer <- "https://issuer.example"
  client@client_secret <- strrep("s", 64)
  client@response_mode <- "query.jwt"
  client@jarm_signed_response_alg <- "HS256"
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  claims <- jose::jwt_claim(
    iss = client@provider@issuer,
    aud = client@client_id,
    exp = as.numeric(Sys.time()) + 60,
    state = state,
    code = "SECRET-JARM-CODE"
  )
  signed <- jose::jwt_encode_hmac(claims, client@client_secret)
  expect_identical(
    jose::jwt_decode_hmac(signed, client@client_secret)[["code"]],
    "SECRET-JARM-CODE"
  )
  ui <- oauth_ui(function(...) stop("app must not render"), "auth", client)
  parts <- strsplit(signed, ".", fixed = TRUE)[[1L]]
  header <- base64url_encode(charToRaw(
    '{"alg":"JARM payload expired SECRET-ALG","typ":"oauth-authz-resp+jwt"}'
  ))
  cases <- list(
    list(
      jwt = paste(c(header, parts[2:3]), collapse = "."),
      reason = "JARM signing alg mismatch"
    ),
    list(
      jwt = jose::jwt_encode_hmac(
        within(claims, {
          aud <- "SECRET-AUDIENCE"
        }),
        client@client_secret
      ),
      reason = "JARM aud claim does not include client_id"
    ),
    list(
      jwt = jose::jwt_encode_hmac(
        within(claims, {
          iss <- NULL
        }),
        client@client_secret
      ),
      reason = "JARM payload missing required iss claim"
    )
  )
  requests <- 0L
  local_mocked_bindings(
    req_perform = function(...) {
      requests <<- requests + 1L
      stop("unexpected HTTP")
    },
    .package = "httr2"
  )
  keys <- client@state_store[["keys"]]()
  records <- lapply(keys, function(key) client@state_store[["get"]](key))
  for (case in cases) {
    req <- callback_rejection_request(httr2::url_query_build(list(
      response = case[["jwt"]]
    )))
    response <- ui(req)
    expect_identical(response[["status"]], 303L)
    final <- callback_rejection_terminal(ui, req, response)
    expect_identical(final[["status"]], 400L)
    expect_identical(final[["content"]], case[["reason"]])
    expect_false(grepl(
      "SECRET|Expected:|Got:|Received:",
      paste(
        response[["content"]],
        response[["headers"]][["Location"]],
        final[["content"]]
      )
    ))
  }
  expect_identical(requests, 0L)
  expect_identical(
    lapply(keys, function(key) client@state_store[["get"]](key)),
    records
  )
})

test_that("mixed, encoded and duplicate rejection locators preserve a genuine rejection", {
  ui <- oauth_ui(function(...) stop("app must not render"))
  req <- callback_rejection_request("code=SECRET-CODE&state=SECRET-STATE")
  original <- ui(req)
  clean_query <- sub(
    "#$",
    "",
    sub("^\\?", "", original[["headers"]][["Location"]])
  )
  for (query in c(
    paste0(clean_query, "&code=SECRET-CODE"),
    paste0(clean_query, "&", clean_query),
    paste0(clean_query, "&", sub("^s", "%73", clean_query)),
    sub("^s", "%73", clean_query),
    "shinyOAuth_callback_error=SECRET-RAW-CREDENTIAL",
    paste0(
      clean_query,
      "&shinyOAuth_form_post=VALID-HANDLE&shinyOAuth_form_post_id=auth"
    )
  )) {
    mixed <- callback_rejection_request(query)
    response <- ui(mixed)
    expect_identical(response[["status"]], 303L)
    expect_false(grepl(
      "SECRET|VALID-HANDLE",
      response[["headers"]][["Location"]]
    ))
    expect_identical(
      callback_rejection_terminal(ui, mixed, response)[["status"]],
      400L
    )
  }
  for (path in c("/other", "//evil")) {
    wrong <- callback_rejection_request(clean_query, path = path)
    expect_identical(ui(wrong)[["status"]], 400L)
  }
  final <- callback_rejection_terminal(ui, req, original)
  expect_identical(final[["status"]], 400L)
  expect_match(final[["content"]], "requires oauth_ui")
})

test_that("a missing reference record retains its typed rejection through public JARM callbacks", {
  withr::local_options(
    cli.num_colors = 256,
    shinyOAuth.allowed_hosts = c("issuer.example", "localhost")
  )
  for (post in c(FALSE, TRUE)) {
    key <- openssl::ec_keygen("P-256")
    jwk <- jsonlite::fromJSON(
      write_test_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    )
    jwk[["kid"]] <- "reference-signing-key"
    jwk[["alg"]] <- "ES256"
    jwk[["use"]] <- "sig"
    provider <- oauth_provider(
      "reference-rejection",
      "https://issuer.example/authorize",
      "https://issuer.example/token",
      issuer = "https://issuer.example",
      jwks_uri = "https://issuer.example/jwks",
      token_auth_style = "public",
      use_nonce = FALSE,
      id_token_validation = FALSE,
      id_token_required = FALSE
    )
    client <- oauth_client(
      provider,
      "reference-client",
      redirect_uri = "http://localhost:8100/callback",
      scopes = "openid",
      state_transport = "reference",
      response_mode = if (post) "form_post.jwt" else "query.jwt",
      jarm_signed_response_alg = "ES256"
    )
    browser <- valid_browser_token()
    prepare <- function() {
      parse_query_param(prepare_call(client, browser), "state", decode = TRUE)
    }
    rightful <- prepare()
    missing <- prepare()
    expect_false(identical(rightful, missing))
    rightful_key <- state_cache_key(rightful)
    missing_key <- state_cache_key(missing)
    record <- client@state_store[["get"]](rightful_key)
    client@state_store[["remove"]](missing_key)
    expect_null(client@state_store[["get"]](missing_key, missing = NULL))
    expect_identical(client@state_store[["keys"]](), rightful_key)
    requests <- character()
    local_mocked_bindings(
      req_perform = function(req, ...) {
        requests <<- c(requests, req[["url"]])
        if (!identical(req[["url"]], provider@jwks_uri)) {
          stop("Unexpected token, UserInfo or resource request")
        }
        httr2::response(
          url = req[["url"]],
          status = 200L,
          headers = list(
            "content-type" = "application/json",
            "cache-control" = "public, max-age=600"
          ),
          body = charToRaw(jsonlite::toJSON(
            list(keys = list(jwk)),
            auto_unbox = TRUE
          ))
        )
      },
      .package = "httr2"
    )
    rendered <- 0L
    ui <- (if (post) oauth_form_post_ui else oauth_ui)(
      function(req) {
        rendered <<- rendered + 1L
        shiny::fluidPage("Application")
      },
      "auth",
      client
    )
    sign <- function(state) {
      jose::jwt_encode_sig(
        jose::jwt_claim(
          iss = provider@issuer,
          aud = client@client_id,
          exp = as.numeric(Sys.time()) + 60,
          state = state,
          code = "SECRET-REFERENCE-CODE"
        ),
        key,
        header = list(kid = "reference-signing-key")
      )
    }
    request <- function(jwt) {
      encoded <- httr2::url_query_build(list(response = jwt))
      if (post) {
        callback_rejection_request(body = encoded)
      } else {
        callback_rejection_request(encoded)
      }
    }
    jwt <- sign(missing)
    expect_identical(parse_jwt_header(jwt)[["alg"]], "ES256")
    expect_identical(
      jose::jwt_decode_sig(jwt, key[["pubkey"]])[["state"]],
      missing
    )
    req <- request(jwt)
    rejected <- ui(req)
    expect_identical(rejected[["status"]], 303L)
    expect_match(
      rejected[["headers"]][["Location"]],
      "^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$"
    )
    final <- callback_rejection_terminal(ui, req, rejected)
    expect_identical(final[["status"]], 400L)
    expect_identical(
      final[["content"]],
      "State store entry is missing or malformed"
    )
    expect_false(grepl(
      "SECRET|reference-client|Trace ID|issuer.example",
      paste(
        rejected[["content"]],
        rejected[["headers"]][["Location"]],
        final[["content"]]
      )
    ))
    # Authenticating missing state precedes any issuer-key refresh. No code
    # exchange or other HTTP request is possible for the rejected response.
    expect_length(requests, 0L)
    expect_identical(rendered, 0L)
    expect_identical(client@state_store[["keys"]](), rightful_key)
    expect_identical(client@state_store[["get"]](rightful_key), record)
    good <- ui(request(sign(rightful)))
    expect_identical(good[["status"]], 303L)
    expect_match(good[["headers"]][["Location"]], "shinyOAuth_form_post=")
    expect_identical(requests, provider@jwks_uri)
    handle <- parse_query_param(
      good[["headers"]][["Location"]],
      "shinyOAuth_form_post",
      decode = TRUE
    )
    accepted <- oauth_form_post_store_take(client, "auth", handle)
    expect_identical(
      accepted[["normalized_response"]][["claims"]][["state"]],
      rightful
    )
    expect_identical(client@state_store[["get"]](rightful_key), record)
    expect_identical(rendered, 0L)
  }
})

test_that("rejection classification trusts only exact approved namespace headers", {
  withr::local_options(
    shinyOAuth.expose_error_body = TRUE,
    cli.num_colors = 256
  )
  reason <- "State store entry is missing or malformed"
  header <- paste0("[shinyOAuth] - ", reason)
  condition <- function(title, body = NULL) {
    tryCatch(
      abort_pkg(
        title,
        body,
        class = c("shinyOAuth_state_error", "shinyOAuth_error")
      ),
      error = identity
    )
  }
  expect_identical(
    oauth_callback_rejection_message(condition(reason), 400L),
    reason
  )
  nested <- tryCatch(err_invalid_state(header), error = identity)
  expect_identical(oauth_callback_rejection_message(nested, 400L), reason)
  for (title in c(
    "Unapproved SECRET header",
    paste0(reason, " SECRET-SUFFIX")
  )) {
    e <- condition(title, c(i = header))
    expect_identical(
      oauth_callback_rejection_message(e, 400L),
      "OAuth callback could not be processed."
    )
  }
  suffixed <- tryCatch(
    err_invalid_state(paste0(header, " SECRET-SUFFIX")),
    error = identity
  )
  expect_identical(
    oauth_callback_rejection_message(suffixed, 400L),
    "OAuth callback could not be processed."
  )
  received <- tryCatch(
    err_claim_validation(
      "JARM signing alg mismatch",
      "alg",
      "ES256",
      header,
      err_invalid_state
    ),
    error = identity
  )
  expect_match(
    cli::ansi_strip(conditionMessage(received)),
    header,
    fixed = TRUE
  )
  expect_identical(
    oauth_callback_rejection_message(received, 400L),
    "JARM signing alg mismatch"
  )
})

test_that("query budget, cache expiry, cache failure and pressure remain fail closed", {
  cache <- oauth_callback_rejection_cache()
  client <- make_test_client()
  ui <- oauth_ui_impl(
    function(...) stop("app must not render"),
    "auth",
    client,
    rejection_cache = cache
  )
  browser <- valid_browser_token()
  state <- parse_query_param(
    prepare_call(client, browser),
    "state",
    decode = TRUE
  )
  logical <- state_payload_decrypt_validate(client, state)[["state"]]
  pending <- state_store_get(client, logical)
  good_req <- callback_rejection_request(
    httr2::url_query_build(list(
      code = "RIGHTFUL-PRESSURE",
      state = state
    )),
    path = "/"
  )
  good <- ui(good_req)
  good_handle <- parse_query_param(
    good[["headers"]][["Location"]],
    "shinyOAuth_form_post",
    decode = TRUE
  )
  req <- callback_rejection_request("code=SECRET&state=invalid", path = "/")
  first <- ui(req)
  for (i in seq_len(140L)) {
    expect_identical(ui(req)[["status"]], 303L)
  }
  expect_lte(length(cache[["keys"]]()), 128L)
  expect_identical(state_store_get(client, logical), pending)
  expect_identical(
    oauth_form_post_store_take(client, "auth", good_handle)[["code"]],
    "RIGHTFUL-PRESSURE"
  )
  expect_identical(
    callback_rejection_terminal(ui, req, first)[["status"]],
    400L
  )
  current <- ui(req)
  handle <- sub("#$", "", sub("^.*=", "", current[["headers"]][["Location"]]))
  key <- oauth_callback_rejection_key(handle)
  entry <- cache[["get"]](key)
  expect_identical(
    sort(names(entry)),
    c("message", "path_digest", "status", "stored_at")
  )
  expect_false(grepl(
    "SECRET|invalid|state=",
    paste(unlist(entry), collapse = " ")
  ))
  entry[["stored_at"]] <- as.numeric(Sys.time()) - 121
  cache[["set"]](key, entry)
  expired <- callback_rejection_terminal(ui, req, current)
  expect_match(expired[["content"]], "unavailable or already consumed")
  withr::with_options(list(shinyOAuth.callback_max_query_bytes = 32), {
    oversized <- callback_rejection_request(paste0("code=", strrep("S", 100)))
    response <- ui(oversized)
    expect_identical(response[["status"]], 303L)
    expect_match(
      callback_rejection_terminal(ui, oversized, response)[["content"]],
      "Invalid or oversized HTTP query"
    )
  })
  failed <- oauth_callback_rejection_wrap(
    function(req) oauth_get_setup_error("Invalid or oversized HTTP query."),
    list(
      set = function(...) stop("SECRET-BACKEND"),
      get = function(..., missing = NULL) missing
    )
  )
  response <- failed(req)
  expect_identical(response[["status"]], 303L)
  expect_match(
    callback_rejection_terminal(failed, req, response)[["content"]],
    "unavailable or already consumed"
  )
  other_worker <- oauth_ui(function(...) stop("app must not render"))
  expect_identical(
    callback_rejection_terminal(other_worker, req, ui(req))[["status"]],
    400L
  )
})

test_that("package rejection cleanup preserves status and leaves application responses alone", {
  client <- make_test_client(response_mode = "form_post")
  client@redirect_uri <- "http://localhost:8100/callback"
  ui <- oauth_form_post_ui(
    function(...) stop("app must not render"),
    "auth",
    client
  )
  req <- callback_rejection_request(body = "code=SECRET&state=invalid")
  req[["CONTENT_TYPE"]] <- "text/plain"
  response <- ui(req)
  expect_identical(response[["status"]], 303L)
  expect_identical(
    callback_rejection_terminal(ui, req, response)[["status"]],
    415L
  )
  head <- callback_rejection_request("shinyOAuth_callback_error=SECRET")
  head[["REQUEST_METHOD"]] <- "HEAD"
  expect_identical(ui(head)[["status"]], 400L)
  expect_identical(ui(head)[["content"]], "")
  app <- shiny::httpResponse(400L, "text/plain", "Application-owned response")
  ordinary <- oauth_ui(function(req) app)
  ordinary_response <- ordinary(callback_rejection_request("theme=dark"))
  expect_identical(ordinary_response[["status"]], app[["status"]])
  expect_identical(ordinary_response[["content"]], app[["content"]])
  expect_null(ordinary_response[["headers"]][["Location"]])
  for (name in c("shinyOAuth_callback_error", "%73hinyOAuth_callback_error")) {
    expect_error(
      {
        client@redirect_uri <- paste0(
          "http://localhost:8100/callback?",
          name,
          "=x"
        )
      },
      "callback-reserved"
    )
  }
})

test_that("manager rejection continuations bypass SMART and owner work", {
  f <- manager_test_fixture()
  rendered <- 0L
  ui <- oauth_connections_ui(
    function(req) {
      rendered <<- rendered + 1L
      shiny::fluidPage("App")
    },
    "health",
    f[["manager"]]
  )
  req <- manager_test_request(
    path = "/callback/a",
    query = "code=SECRET&error=access_denied&state=invalid"
  )
  response <- ui(req)
  expect_identical(response[["status"]], 303L)
  local_mocked_bindings(
    smart_launch_http = function(...) stop("SMART must not run"),
    connection_owner_cookie_read = function(...) stop("owner must not run"),
    .package = "shinyOAuth"
  )
  final <- callback_rejection_terminal(ui, req, response)
  expect_identical(final[["status"]], 400L)
  expect_match(final[["content"]], "must not contain both code and error")
  expect_identical(rendered, 0L)
  expect_null(final[["headers"]][["Set-Cookie"]])
})
