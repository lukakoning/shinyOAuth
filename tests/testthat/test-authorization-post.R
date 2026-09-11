post_fields <- function(request) {
  stats::setNames(lapply(request$fields, `[[`, "value"),
    vapply(request$fields, `[[`, "", "name"))
}

test_that("authorization POST preserves fields, fixed query and browser transaction", {
  browser <- valid_browser_token()
  client <- make_test_client(use_nonce = TRUE, scopes = c("openid", paste0("permission:", seq_len(40))),
    resource = c("https://api.example/one", "https://api.example/two"))
  client@authorization_method <- "POST"
  client@provider@auth_url <- paste0(client@provider@auth_url, "?fixed=a%2Bb&client_id=abc")
  client@provider@extra_auth_params <- list(login_hint = 'A+B & <literal> "quote"', submit = "extension")
  request <- prepare_authorization_request(client, browser)
  fields <- post_fields(request)
  expect_identical(request$method, "POST")
  expect_identical(request$url, client@provider@auth_url)
  expect_false("client_id" %in% names(fields))
  expect_identical(unlist(fields[names(fields) == "resource"], use.names = FALSE), client@resource)
  expect_identical(fields$login_hint, client@provider@extra_auth_params$login_hint)
  expect_identical(fields$submit, "extension")
  expect_identical(fields$scope, paste(client@scopes, collapse = " "))
  payload <- state_payload_decrypt_validate(client, fields$state)
  stored <- state_store_get(client, payload$state)
  expect_identical(stored$browser_token, browser)
  expect_identical(stored$nonce, fields$nonce)
  expect_identical(fields$code_challenge_method, "S256")
  expect_identical(fields$code_challenge,
    base64url_encode(openssl::sha256(charToRaw(stored$pkce_code_verifier))))
  changed <- client
  changed@authorization_method <- "GET"
  expect_error(state_payload_decrypt_validate(changed, fields$state), "client policy")
  worker <- prepare_client_for_worker(client)
  expect_identical(worker@authorization_method, "POST")
  expect_identical(state_client_policy_fingerprint(worker), state_client_policy_fingerprint(client))
})

test_that("GET remains a URL and URL-only helpers reject POST before storing state", {
  client <- make_test_client()
  browser <- valid_browser_token()
  expect_type(prepare_call(client, browser), "character")
  request <- prepare_authorization_request(client, browser)
  expect_identical(request$method, "GET")
  expect_length(request$fields, 0L)
  expect_match(request$url, "state=")
  client@authorization_method <- "POST"
  before <- client@state_store$keys()
  expect_error(prepare_call(client, browser), "prepare_authorization")
  expect_setequal(client@state_store$keys(), before)
  for (method in c("post", "PUT", "")) expect_error(client@authorization_method <- method, "GET or POST")
})

test_that("SMART POST requires advertised support and binds its selected method", {
  site <- smart_client_fixture()
  create <- function(site) smart_client(site, "example", "https://app.example/callback",
    scopes = c("launch/patient", "patient/Patient.r"), authorization_method = "POST")
  expect_error(create(site), "authorize-post")
  site$metadata$capabilities <- c(site$metadata$capabilities, list("authorize-post"))
  client <- create(site)
  expect_identical(client@authorization_method, "POST")
  request <- prepare_authorization_request(client, valid_browser_token())
  expect_identical(post_fields(request)$aud, site$fhir_base)
  client <- client
  expect_error(client@authorization_method <- "GET", "SMART policy")
})

test_that("POST keeps PAR requirements and expiry metadata", {
  client <- make_test_client()
  client@authorization_method <- "POST"
  client@provider@par_url <- "https://example.com/par"
  client@provider@par_required <- TRUE
  pushed <- NULL
  local_mocked_bindings(push_authorization_request = function(client, params) {
    pushed <<- params
    list(request_uri = "urn:ietf:params:oauth:request_uri:fixture", expires_in = 60)
  })
  request <- prepare_authorization_request(client, valid_browser_token())
  fields <- post_fields(request)
  expect_identical(fields$request_uri, "urn:ietf:params:oauth:request_uri:fixture")
  expect_false("state" %in% names(fields))
  expect_true(is_valid_string(pushed$state))
  expect_identical(pushed$code_challenge_method, "S256")
  expect_identical(attr(request, "shinyOAuth.par_expires_in"), 60)
  expect_gt(attr(request, "shinyOAuth.par_expires_at"), Sys.time())
  local_mocked_bindings(push_authorization_request = function(...) stop("PAR refused"))
  before <- client@state_store$keys()
  expect_error(prepare_authorization_request(client, valid_browser_token()), "PAR refused")
  expect_setequal(client@state_store$keys(), before)
})

test_that("POST preserves signed Request Object and published reference composition", {
  client <- make_test_client()
  client@authorization_method <- "POST"
  client@client_secret <- strrep("s", 32)
  client@request_object_audience <- "https://example.com"
  client@request_object_mode <- "request"
  request <- prepare_authorization_request(client, valid_browser_token())
  fields <- post_fields(request)
  parts <- strsplit(fields$request, ".", fixed = TRUE)[[1L]]
  expect_identical(parts[[3L]], base64url_encode(openssl::sha256(
    charToRaw(paste(parts[1:2], collapse = ".")), key = charToRaw(client@client_secret))))
  claims <- parse_jwt_payload(fields$request)
  expect_identical(claims$client_id, client@client_id)
  expect_true(is_valid_string(claims$state))
  expect_false("state" %in% names(fields))
  client@request_object_mode <- "request_uri"
  published <- NULL
  request <- prepare_authorization_request(client, valid_browser_token(), function(request_object, ...) {
    published <<- request_object
    "https://app.example/request/fixture"
  })
  expect_identical(post_fields(request)$request_uri, "https://app.example/request/fixture")
  expect_true(is_valid_string(published))
})

test_that("POST fails cleanly on conflicting fixed fields and form limits", {
  client <- make_test_client()
  client@authorization_method <- "POST"
  for (extra in list(list(login_hint = "line\nbreak"), list(`_charset_` = "provider-value"),
      list(login_hint = strrep("x", 131073)), list(login_hint = strrep("~", 44000)),
      as.list(stats::setNames(rep("x", 257), paste0("extra", 1:257))))) {
    client@provider@extra_auth_params <- extra
    expect_error(prepare_authorization_request(client, valid_browser_token()), "form limits")
    expect_length(client@state_store$keys(), 0L)
  }
  client@provider@extra_auth_params <- list()
  client@provider@auth_url <- paste0(client@provider@auth_url, "?client_id=other")
  expect_error(prepare_authorization_request(client, valid_browser_token()), "conflicts with managed")
  expect_length(client@state_store$keys(), 0L)
})

test_that("ordinary Shiny login submits POST and completes the same callback", {
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  client <- make_test_client()
  client@authorization_method <- "POST"
  sent <- list()
  local_mocked_bindings(send_oauth_module_redirect = function(session, url) {
    sent[[length(sent) + 1L]] <<- url
  }, swap_code_for_token_set = function(...) {
    list(access_token = "synthetic-token", token_type = "Bearer", expires_in = 3600)
  })
  shiny::testServer(oauth_module_server,
    args = list(id = "auth", client = client, auto_redirect = FALSE, async = FALSE), {
      expect_error(values$build_auth_url(), "request_login")
      expect_length(client@state_store$keys(), 0L)
      values$request_login()
      expect_length(sent, 1L)
      expect_identical(sent[[1L]]$method, "POST")
      fields <- post_fields(sent[[1L]])
      values$.process_query(paste0("?code=synthetic&state=", fields$state))
      session$flushReact()
      expect_true(values$authenticated)
      expect_null(values$error)
      expect_length(client@state_store$keys(), 0L)
    })
})

test_that("POST browser handler preserves literal fields and validates form messages", {
  skip_if(Sys.which("node") == "")
  output <- system2(Sys.which("node"), c(shQuote(test_path("..", "browser-authorization-post.cjs")),
    shQuote(system.file("www", "shinyOAuth.js", package = "shinyOAuth"))), stdout = TRUE, stderr = TRUE)
  expect_null(attr(output, "status"), info = paste(output, collapse = "\n"))
})

test_that("prepared POST work requires live state and an unexpired PAR reference", {
  client <- make_test_client()
  client@authorization_method <- "POST"
  prepared <- prepare_call(client, valid_browser_token(), .defer_build = TRUE)
  worker <- prepare_client_for_worker(client)
  result <- build_prepared_authorization(worker, prepared)
  expect_identical(result$method, "POST")
  expect_identical(finish_prepared_authorization(result, client, prepared), result)
  attr(result, "shinyOAuth.par_expires_at") <- Sys.time() - 1
  expect_error(finish_prepared_authorization(result, client, prepared), "PAR request expired")
  client@state_store$remove(prepared$state_key)
  expect_error(finish_prepared_authorization(result, client, prepared), class = "shinyOAuth_state_error")
})

test_that("async POST sends only the current authorization after worker completion", {
  withr::local_options(shinyOAuth.skip_browser_token = TRUE)
  for (action in c("success", "logout", "failure", "replacement")) {
    client <- make_test_client()
    client@authorization_method <- "POST"
    client@provider@par_url <- "https://example.com/par"
    work <- new.env(parent = emptyenv())
    work$promise <- promises::promise(function(resolve, reject) {
      work$resolve <- resolve
      work$reject <- reject
    })
    sent <- list()
    local_mocked_bindings(async_dispatch = function(expr, args, ...) {
      work$args <- args
      work$promise
    }, send_oauth_module_redirect = function(session, url) {
      sent[[length(sent) + 1L]] <<- url
    })
    shiny::testServer(oauth_module_server,
      args = list(id = "auth", client = client, auto_redirect = FALSE, async = TRUE), {
        values$request_login()
        expect_length(sent, 0L)
        expect_identical(work$args$worker@authorization_method, "POST")
        key <- work$args$prepared$state_key
        expect_true(client@state_store$exists(key))
        if (action == "logout") values$logout()
        if (action == "replacement") .begin_auth_operation("login", values$token, new_epoch = TRUE)
        if (action == "failure") work$reject(simpleError("provider unavailable")) else {
          work$resolve(list(method = "POST", url = client@provider@auth_url,
            fields = list(list(name = "client_id", value = client@client_id),
              list(name = "request_uri", value = "urn:fixture:par"))))
        }
        poll_for_async(function() if (action == "success") length(sent) == 1L else !client@state_store$exists(key), session)
        if (action == "success") {
          expect_identical(sent[[1L]]$method, "POST")
          expect_identical(post_fields(sent[[1L]])$request_uri, "urn:fixture:par")
        } else expect_length(sent, 0L)
      })
  }
})
