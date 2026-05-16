## Integration tests: live Keycloak RFC 8707 resource-indicator behavior

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}

make_resource_indicator_client <- function(prov, resource) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid", "profile", "email"),
    introspect = TRUE,
    resource = resource
  )
}

make_resource_indicator_enforced_client <- function(prov, resource) {
  shinyOAuth::oauth_client(
    provider = prov,
    client_id = "shiny-resource-confidential",
    client_secret = "secret",
    redirect_uri = "http://localhost:3000/callback",
    scopes = c("openid", "profile", "email"),
    introspect = TRUE,
    resource = resource
  )
}

resource_indicator_login_via_module <- function(client) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- try(
        perform_login_form(auth_url, redirect_uri = client@redirect_uri),
        silent = TRUE
      )

      if (inherits(login, "try-error")) {
        result <<- list(
          auth_url = auth_url,
          login_error = conditionMessage(attr(login, "condition")),
          authenticated = FALSE,
          error = values$error,
          error_description = values$error_description,
          token = values$token
        )
      } else {
        values$.process_query(callback_query(login))
        session$flushReact()

        result <<- list(
          auth_url = auth_url,
          login = login,
          callback_url = login$callback_url,
          authenticated = isTRUE(values$authenticated),
          error = values$error,
          error_description = values$error_description,
          token = values$token
        )
      }
    }
  )

  result
}

resource_failure_text <- function(result) {
  paste(
    result$error %||% "",
    result$error_description %||% "",
    result$callback_url %||% "",
    result$login_error %||% ""
  )
}

normalize_resource_audience <- function(audience) {
  if (is.null(audience)) {
    return(character(0))
  }

  values <- unlist(audience, use.names = FALSE)
  values <- as.character(values)
  values <- values[!is.na(values)]
  values[nzchar(values)]
}

access_token_audience <- function(token) {
  payload <- shinyOAuth:::parse_jwt_payload(token@access_token)
  normalize_resource_audience(payload$aud %||% NULL)
}

start_resource_audience_server <- function(
  expected_audience,
  .local_envir = parent.frame()
) {
  send_problem <- function(res, status, error_code) {
    res$set_status(status)
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(ok = FALSE, error = error_code),
      auto_unbox = TRUE,
      null = "null"
    ))
  }

  app <- webfakes::new_app()
  app$get("/", function(req, res) {
    auth <- req$get_header("authorization") %||% ""
    if (!grepl("^Bearer\\s+", auth, ignore.case = TRUE)) {
      send_problem(res, 401L, "missing_bearer_authorization")
      return()
    }

    access_token <- sub("^[Bb]earer\\s+", "", auth, perl = TRUE)
    aud <- try(
      normalize_resource_audience(
        shinyOAuth:::parse_jwt_payload(access_token)$aud %||% NULL
      ),
      silent = TRUE
    )
    if (inherits(aud, "try-error")) {
      send_problem(res, 401L, "token_parse_failed")
      return()
    }
    if (!(expected_audience %in% aud)) {
      send_problem(res, 401L, "missing_or_wrong_audience")
      return()
    }

    payload <- shinyOAuth:::parse_jwt_payload(access_token)
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(
        ok = TRUE,
        audience = expected_audience,
        sub = payload$sub %||% NA_character_
      ),
      auto_unbox = TRUE,
      null = "null"
    ))
  })

  srv <- webfakes::local_app_process(app, .local_envir = .local_envir)
  url <- paste0(sub("/+$", "", srv$url()), "/")
  deadline <- Sys.time() + 5

  repeat {
    ready <- tryCatch(
      {
        httr2::request(url) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_perform()
        TRUE
      },
      error = function(...) FALSE
    )
    if (isTRUE(ready)) {
      break
    }
    if (Sys.time() > deadline) {
      stop("Resource audience server did not start in time", call. = FALSE)
    }
    Sys.sleep(0.1)
  }

  list(server = srv, url = url)
}

perform_resource_audience_request <- function(url, access_token) {
  httr2::request(url) |>
    httr2::req_error(is_error = function(resp) FALSE) |>
    httr2::req_headers(Authorization = paste("Bearer", access_token)) |>
    httr2::req_perform()
}

testthat::test_that("Keycloak code flow accepts RFC 8707 resource indicators", {
  skip_common()
  local_test_options()

  resource <- "https://api.shinyoauth.test"
  prov <- make_provider()
  client <- make_resource_indicator_client(prov, resource = resource)

  result <- resource_indicator_login_via_module(client)

  testthat::expect_match(
    result$auth_url,
    "resource=https%3A%2F%2Fapi\\.shinyoauth\\.test"
  )
  testthat::expect_true(
    isTRUE(result$authenticated),
    info = resource_failure_text(result)
  )
  testthat::expect_null(result$error)
  testthat::expect_false(is.null(result$token))
  testthat::expect_true(isTRUE(result$token@id_token_validated))

  intros <- shinyOAuth::introspect_token(client, result$token, which = "access")
  testthat::expect_true(isTRUE(intros$supported))
  testthat::expect_true(isTRUE(intros$active))

  testthat::expect_length(access_token_audience(result$token), 0L)
  testthat::expect_length(
    normalize_resource_audience(intros$raw$aud %||% NULL),
    0L
  )
})

testthat::test_that("audience-mapped Keycloak resource token is usable at an audience-checking resource", {
  skip_common()
  local_test_options()
  testthat::skip_if_not_installed("webfakes")

  resource <- "https://api.shinyoauth.test"
  prov <- make_provider()

  control_client <- make_resource_indicator_client(prov, resource = resource)
  control <- resource_indicator_login_via_module(control_client)
  testthat::expect_true(
    isTRUE(control$authenticated),
    info = resource_failure_text(control)
  )

  client <- make_resource_indicator_enforced_client(prov, resource = resource)
  result <- resource_indicator_login_via_module(client)
  testthat::expect_true(
    isTRUE(result$authenticated),
    info = resource_failure_text(result)
  )
  testthat::expect_null(result$error)
  testthat::expect_false(is.null(result$token))

  intros <- shinyOAuth::introspect_token(client, result$token, which = "access")
  aud <- access_token_audience(result$token)
  intros_aud <- normalize_resource_audience(intros$raw$aud %||% NULL)

  testthat::expect_true(resource %in% aud)
  testthat::expect_true(resource %in% intros_aud)

  protected <- start_resource_audience_server(resource)
  on.exit(try(protected$server$stop(), silent = TRUE), add = TRUE)

  ok_resp <- perform_resource_audience_request(
    protected$url,
    result$token@access_token
  )
  ok_body <- httr2::resp_body_json(ok_resp, simplifyVector = TRUE)
  testthat::expect_identical(httr2::resp_status(ok_resp), 200L)
  testthat::expect_true(isTRUE(ok_body$ok))
  testthat::expect_identical(ok_body$audience, resource)
  testthat::expect_identical(ok_body$sub, result$token@userinfo$sub)

  bad_resp <- perform_resource_audience_request(
    protected$url,
    control$token@access_token
  )
  bad_body <- httr2::resp_body_json(bad_resp, simplifyVector = TRUE)
  testthat::expect_identical(httr2::resp_status(bad_resp), 401L)
  testthat::expect_identical(bad_body$error, "missing_or_wrong_audience")
})
