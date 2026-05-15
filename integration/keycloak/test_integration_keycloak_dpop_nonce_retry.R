## Integration tests: DPoP resource nonce retry with a real Keycloak token

if (!exists("make_provider", mode = "function")) {
  source(file.path(dirname(sys.frame(1)$ofile %||% "."), "helper-keycloak.R"))
}
if (!exists("verify_signed_access_token", mode = "function")) {
  source(file.path(
    dirname(sys.frame(1)$ofile %||% "."),
    "helper-dpop-resource.R"
  ))
}

perform_dpop_nonce_login <- function(client) {
  result <- NULL

  shiny::testServer(
    app = shinyOAuth::oauth_module_server,
    args = default_module_args(client),
    expr = {
      auth_url <- values$build_auth_url()
      login <- perform_login_form(auth_url, redirect_uri = client@redirect_uri)
      values$.process_query(callback_query(login))
      session$flushReact()

      result <<- list(
        authenticated = isTRUE(values$authenticated),
        error = values$error,
        error_description = values$error_description,
        token = values$token
      )
    }
  )

  result
}

start_dpop_nonce_challenge_resource <- function(
  resource_path = "/nonce-resource",
  issuer = get_issuer(),
  jwks = get_jwks(force = TRUE),
  nonce = "resource-nonce-1",
  .local_envir = parent.frame()
) {
  testthat::skip_if_not_installed("webfakes")

  coalesce <- `%||%`
  verify_access_token <- verify_signed_access_token
  verify_proof <- verify_dpop_proof
  jti_cache <- new.env(parent = emptyenv())
  state <- new.env(parent = emptyenv())
  state$count <- 0L
  state$first <- NULL

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
  app$get(resource_path, function(req, res) {
    tryCatch(
      {
        auth <- coalesce(req$get_header("authorization"), "")
        proof <- coalesce(req$get_header("dpop"), "")
        access_token <- sub("^[Dd][Pp][Oo][Pp]\\s+", "", auth, perl = TRUE)
        if (!grepl("^DPoP\\s+", auth, ignore.case = TRUE) || !nzchar(proof)) {
          send_problem(res, 401L, "missing_dpop")
          return()
        }

        access_payload <- verify_access_token(access_token, issuer, jwks)
        proof_info <- verify_proof(
          proof = proof,
          req_method = req$method,
          req_url = as.character(req$url),
          access_token = access_token,
          enforce_jti_replay = TRUE,
          jti_cache = jti_cache
        )

        bound_jkt <- coalesce(
          coalesce(access_payload$cnf, list())$jkt,
          NA_character_
        )
        if (!identical(bound_jkt, proof_info$jwk_thumbprint)) {
          send_problem(res, 401L, "dpop_key_mismatch")
          return()
        }

        state$count <- state$count + 1L
        if (identical(state$count, 1L)) {
          state$first <- proof_info$payload
          res$set_status(401L)
          res$set_type("application/json")
          res$set_header(
            "WWW-Authenticate",
            'DPoP error="use_dpop_nonce", error_description="nonce required"'
          )
          res$set_header("DPoP-Nonce", nonce)
          res$send(jsonlite::toJSON(
            list(error = "use_dpop_nonce"),
            auto_unbox = TRUE
          ))
          return()
        }

        retry_payload <- proof_info$payload
        expected_ath <- shinyOAuth:::dpop_access_token_hash(access_token)
        expected_htu <- shinyOAuth:::dpop_target_uri(as.character(req$url))

        if (!identical(retry_payload$nonce %||% NA_character_, nonce)) {
          send_problem(res, 401L, "dpop_nonce_mismatch")
          return()
        }

        res$set_type("application/json")
        res$send(jsonlite::toJSON(
          list(
            ok = TRUE,
            count = state$count,
            first_jti = state$first$jti %||% NA_character_,
            retry_jti = retry_payload$jti %||% NA_character_,
            first_nonce_present = "nonce" %in% names(state$first),
            retry_nonce = retry_payload$nonce %||% NA_character_,
            retry_ath = retry_payload$ath %||% NA_character_,
            expected_ath = expected_ath,
            retry_htm = retry_payload$htm %||% NA_character_,
            retry_htu = retry_payload$htu %||% NA_character_,
            expected_htu = expected_htu
          ),
          auto_unbox = TRUE,
          null = "null"
        ))
      },
      error = function(err) {
        send_problem(
          res,
          500L,
          paste0("resource_internal_error:", conditionMessage(err))
        )
      }
    )
  })

  srv <- webfakes::local_app_process(app, .local_envir = .local_envir)
  url <- paste0(sub("/+$", "", srv$url()), resource_path)
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
      stop("DPoP nonce resource did not start in time", call. = FALSE)
    }
    Sys.sleep(0.1)
  }

  list(server = srv, url = url, nonce = nonce)
}

testthat::test_that("perform_resource_req retries DPoP nonce challenge with fresh proof", {
  skip_common()
  local_test_options()
  testthat::skip_if_not_installed("webfakes")

  try(shinyOAuth:::dpop_nonce_cache$reset(), silent = TRUE)

  prov <- make_provider(allowed_token_types = c("Bearer", "DPoP"))
  client <- make_dpop_public_client(prov)
  login <- perform_dpop_nonce_login(client)

  testthat::expect_true(isTRUE(login$authenticated))
  testthat::expect_identical(login$token@token_type, "DPoP")

  resource <- start_dpop_nonce_challenge_resource()
  on.exit(try(resource$server$stop(), silent = TRUE), add = TRUE)

  resp <- shinyOAuth::perform_resource_req(
    login$token,
    resource$url,
    oauth_client = client
  )
  body <- httr2::resp_body_json(resp, simplifyVector = TRUE)

  testthat::expect_identical(httr2::resp_status(resp), 200L)
  testthat::expect_true(isTRUE(body$ok))
  testthat::expect_identical(as.integer(body$count), 2L)
  testthat::expect_false(isTRUE(body$first_nonce_present))
  testthat::expect_identical(body$retry_nonce, resource$nonce)
  testthat::expect_false(identical(body$first_jti, body$retry_jti))
  testthat::expect_identical(body$retry_htm, "GET")
  testthat::expect_identical(body$retry_htu, body$expected_htu)
  testthat::expect_identical(
    body$retry_htu,
    shinyOAuth:::dpop_target_uri(resource$url)
  )
  testthat::expect_identical(body$retry_ath, body$expected_ath)
  testthat::expect_identical(
    body$retry_ath,
    shinyOAuth:::dpop_access_token_hash(login$token@access_token)
  )
})
