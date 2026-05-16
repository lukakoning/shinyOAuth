## Integration tests: live Keycloak currently rejects dynamic mTLS + JAR

if (!exists("make_mtls_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

query_param_names <- function(url) {
  q <- sub("^[^?]*\\?", "", url)
  if (identical(q, url) || !nzchar(q)) {
    return(character(0))
  }

  parts <- strsplit(q, "&", fixed = TRUE)[[1]]
  kv <- strsplit(parts, "=", fixed = TRUE)
  unique(vapply(kv, function(p) utils::URLdecode(p[1]), ""))
}

create_mtls_jar_fixture <- function(encrypted = FALSE) {
  admin_token <- keycloak_admin_token()
  fixture <- keycloak_create_temp_mtls_jar_client(
    token = admin_token,
    client_id = keycloak_temp_client_id(
      if (isTRUE(encrypted)) {
        "shiny-mtls-jar-pjwt-jwe"
      } else {
        "shiny-mtls-jar-pjwt"
      }
    ),
    encrypted = encrypted
  )

  list(admin_token = admin_token, fixture = fixture)
}

make_mtls_jar_provider <- function(use_par = FALSE, encrypted = FALSE) {
  provider_args <- list(
    token_auth_style = "tls_client_auth",
    use_par = use_par
  )

  if (isTRUE(encrypted)) {
    provider_args$request_object_encryption_alg_values_supported <- c(
      "RSA-OAEP"
    )
    provider_args$request_object_encryption_enc_values_supported <- c(
      "A256CBC-HS512"
    )
  }

  do.call(make_mtls_provider, provider_args)
}

make_dynamic_mtls_jar_client <- function(
  provider,
  client_id,
  encrypted = FALSE
) {
  if (isTRUE(encrypted)) {
    make_mtls_private_key_jar_jwe_client(
      prov = provider,
      client_id = client_id
    )
  } else {
    make_mtls_private_key_jar_client(
      prov = provider,
      client_id = client_id
    )
  }
}

valid_browser_token <- function() {
  paste(rep("ab", 64), collapse = "")
}

perform_auth_url_request <- function(auth_url) {
  httr2::request(auth_url) |>
    req_apply_keycloak_ca() |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Accept = "text/html") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_perform()
}

expect_keycloak_invalid_request_page <- function(resp) {
  testthat::expect_identical(httr2::resp_status(resp), 400L)

  body <- httr2::resp_body_string(resp)
  testthat::expect_match(body, 'data-page-id="login-error"', fixed = TRUE)
  testthat::expect_match(body, "Invalid Request", fixed = TRUE)

  invisible(resp)
}

testthat::test_that("Keycloak currently rejects dynamic signed mTLS plus JAR at the authorization endpoint", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_mtls_jar_fixture(encrypted = FALSE)
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_mtls_jar_provider(use_par = FALSE, encrypted = FALSE)
  client <- make_dynamic_mtls_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id,
    encrypted = FALSE
  )
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = valid_browser_token()
  )

  testthat::expect_setequal(
    query_param_names(auth_url),
    c("client_id", "response_type", "scope", "request")
  )
  testthat::expect_match(auth_url, "[?&]response_type=code")
  testthat::expect_match(auth_url, "[?&]scope=openid(?:%20|&|$)")

  resp <- perform_auth_url_request(auth_url)

  expect_keycloak_invalid_request_page(resp)
})

testthat::test_that("Keycloak currently rejects dynamic encrypted mTLS plus JAR at the authorization endpoint", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_mtls_jar_fixture(encrypted = TRUE)
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_mtls_jar_provider(use_par = FALSE, encrypted = TRUE)
  client <- make_dynamic_mtls_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id,
    encrypted = TRUE
  )
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  auth_url <- shinyOAuth::prepare_call(
    client,
    browser_token = valid_browser_token()
  )

  testthat::expect_setequal(
    query_param_names(auth_url),
    c("client_id", "response_type", "scope", "request")
  )
  testthat::expect_match(auth_url, "[?&]response_type=code")
  testthat::expect_match(auth_url, "[?&]scope=openid(?:%20|&|$)")

  resp <- perform_auth_url_request(auth_url)

  expect_keycloak_invalid_request_page(resp)
})

testthat::test_that("Keycloak currently rejects dynamic signed mTLS plus JAR through PAR", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_mtls_jar_fixture(encrypted = FALSE)
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_mtls_jar_provider(use_par = TRUE, encrypted = FALSE)
  client <- make_dynamic_mtls_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id,
    encrypted = FALSE
  )
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  testthat::expect_error(
    shinyOAuth::prepare_call(
      client,
      browser_token = valid_browser_token()
    ),
    regexp = paste(
      "Pushed authorization request failed|",
      "invalid_request_object|invalidRequestMessage"
    ),
    ignore.case = TRUE
  )
})

testthat::test_that("Keycloak currently rejects dynamic encrypted mTLS plus JAR through PAR", {
  skip_mtls_common()
  local_test_options()

  fixture <- create_mtls_jar_fixture(encrypted = TRUE)
  on.exit(
    keycloak_delete_client(
      fixture$admin_token,
      id = fixture$fixture$id
    ),
    add = TRUE
  )

  provider <- make_mtls_jar_provider(use_par = TRUE, encrypted = TRUE)
  client <- make_dynamic_mtls_jar_client(
    provider = provider,
    client_id = fixture$fixture$client_id,
    encrypted = TRUE
  )
  testthat::skip_if(is.null(client), "private_key_jwt test key not available")

  testthat::expect_error(
    shinyOAuth::prepare_call(
      client,
      browser_token = valid_browser_token()
    ),
    regexp = paste(
      "Pushed authorization request failed|",
      "invalid_request_object|invalidRequestMessage"
    ),
    ignore.case = TRUE
  )
})
