mtls_resource_client <- function(
  fixture,
  alg,
  certificate,
  par,
  confirmation,
  bound = TRUE
) {
  issuer <- fixture[["issuer"]]
  root <- fixture[["root"]]
  provider <- shinyOAuth::oauth_provider(
    name = "strict-resource",
    issuer = issuer,
    auth_url = paste0(issuer, "/authorize"),
    token_url = paste0(issuer, "/token"),
    token_auth_style = "private_key_jwt",
    infer_oidc_from_issuer = FALSE,
    use_nonce = FALSE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    userinfo_required = FALSE,
    signed_request_object_required = TRUE,
    request_parameter_supported = TRUE,
    request_object_signing_alg_values_supported = alg,
    token_endpoint_auth_signing_alg_values_supported = alg,
    mtls_client_certificate_bound_access_tokens = TRUE,
    par_url = if (par) paste0(issuer, "/par") else NA_character_
  )
  shinyOAuth::oauth_client(
    provider,
    "client",
    redirect_uri = "https://app.example.com/callback",
    scopes = c(
      "jwt-oauth21",
      if (bound) "mtls",
      if (bound && !confirmation) "opaque-cnf"
    ),
    client_assertion_private_key = fixture[["signing_key"]],
    client_assertion_alg = alg,
    client_assertion_audience = issuer,
    client_assertion_typ = "client-authentication+jwt",
    request_object_mode = "request",
    request_object_signing_alg = alg,
    state_transport = "reference",
    resource_bases = c(api = paste0(issuer, "/resource/")),
    mtls_client_cert_file = file.path(root, paste0(certificate, ".pem")),
    mtls_client_key_file = file.path(root, paste0(certificate, "-key.pem")),
    mtls_client_ca_file = file.path(root, "ca.pem"),
    mtls_certificate_bound_access_tokens = bound,
    mtls_require_observed_cnf = confirmation
  )
}

mtls_resource_login <- function(
  client,
  async,
  audit_path,
  request_resource = TRUE
) {
  browser <- strrep("ab", 64)
  expected_package <- normalizePath(
    getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
    winslash = "/"
  )
  hook <- function(event) {
    if (identical(event[["type"]], "audit_token_exchange")) {
      matches <- identical(
        normalizePath(
          getNamespaceInfo(asNamespace("shinyOAuth"), "path"),
          winslash = "/"
        ),
        expected_package
      )
      cat(Sys.getpid(), matches, "\n", file = audit_path, append = TRUE)
    }
  }
  environment(hook) <- list2env(
    list(audit_path = audit_path, expected_package = expected_package),
    parent = baseenv()
  )
  withr::local_options(shinyOAuth.audit_hook = hook)
  response <- httr2::request(shinyOAuth::prepare_call(
    client,
    browser_token = browser
  )) |>
    httr2::req_options(
      cainfo = client@mtls_client_ca_file,
      followlocation = FALSE
    ) |>
    httr2::req_perform()
  testthat::expect_identical(httr2::resp_status(response), 302L)
  callback <- httr2::url_parse(httr2::resp_header(response, "location"))[[
    "query"
  ]]
  token <- NULL
  shiny::testServer(
    shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      async = async,
      refresh_proactively = FALSE,
      indefinite_session = TRUE
    ),
    {
      session[["setInputs"]](shinyOAuth_sid = browser)
      session[["flushReact"]]()
      values[[".process_query"]](paste0("?", httr2::url_query_build(callback)))
      deadline <- Sys.time() + 30
      repeat {
        later::run_now(0.02)
        session[["flushReact"]]()
        if (!is.null(values[["token"]]) || !is.null(values[["error"]])) {
          break
        }
        if (Sys.time() > deadline) stop("Resource fixture callback timed out")
      }
      testthat::expect_null(values[["error"]])
      token <<- values[["token"]]
      testthat::expect_true(S7::S7_inherits(token, shinyOAuth::OAuthToken))
      connection <- values[["connection"]]()
      testthat::expect_true(connection[["is_usable"]]())
      if (request_resource) {
        resource <- connection[["request"]](
          "api",
          "records",
          required_scopes = "mtls"
        )
        testthat::expect_identical(httr2::resp_status(resource), 200L)
        testthat::expect_identical(
          httr2::resp_body_json(resource),
          list(resource = "certificate-bound-content")
        )
      }
    }
  )
  observed <- utils::read.table(
    audit_path,
    colClasses = c("numeric", "logical")
  )
  testthat::expect_identical(nrow(observed), 1L)
  testthat::expect_true(observed[[2L]][[1L]])
  pids <- observed[[1L]]
  testthat::expect_identical(
    identical(pids[[1L]], as.numeric(Sys.getpid())),
    !async
  )
  token
}

mtls_resource_attack <- function(
  fixture,
  token,
  certificate = NULL,
  forwarded = NULL
) {
  request <- httr2::request(paste0(fixture[["issuer"]], "/resource/records")) |>
    httr2::req_options(
      cainfo = file.path(fixture[["root"]], "ca.pem"),
      followlocation = FALSE
    ) |>
    httr2::req_headers(Authorization = paste("Bearer", token@access_token)) |>
    httr2::req_error(is_error = function(...) FALSE) |>
    httr2::req_timeout(5)
  if (!is.null(certificate)) {
    request <- request |>
      httr2::req_options(
        sslcert = file.path(fixture[["root"]], paste0(certificate, ".pem")),
        sslkey = file.path(fixture[["root"]], paste0(certificate, "-key.pem"))
      )
  }
  if (!is.null(forwarded)) {
    request <- request |>
      httr2::req_headers(
        `X-Ssl-Cert` = paste(
          readLines(file.path(fixture[["root"]], paste0(forwarded, ".pem"))),
          collapse = "\t"
        )
      )
  }
  httr2::req_perform(request)
}

expect_mtls_resource_denied <- function(
  response,
  reason = "resource_certificate"
) {
  testthat::expect_identical(httr2::resp_status(response), 401L)
  testthat::expect_identical(
    httr2::resp_header(response, "www-authenticate"),
    'Bearer error="invalid_token"'
  )
  testthat::expect_identical(
    httr2::resp_header(response, "cache-control"),
    "no-store"
  )
  testthat::expect_identical(
    httr2::resp_body_json(response),
    list(error = "invalid_token", reason = reason)
  )
}

run_mtls_resource <- function(alg) {
  fixture <- strict_as_fixture(alg)
  withr::local_envvar(
    R_LIBS = paste(.libPaths(), collapse = .Platform[["path.sep"]])
  )
  mirai::daemons(1L, rs = "--vanilla")
  withr::defer(mirai::daemons(0L))
  # The matching subject names and valid chains must not authorize a different
  # certificate to use an existing token.
  certificates <- lapply(c("client", "alternate"), function(name) {
    openssl::read_cert(file.path(fixture[["root"]], paste0(name, ".pem")))
  })
  testthat::expect_true(
    is.character(as.list(certificates[[1L]])[["subject"]]) &&
      length(as.list(certificates[[1L]])[["subject"]]) > 0L
  )
  testthat::expect_identical(
    as.list(certificates[[1L]])[["subject"]],
    as.list(certificates[[2L]])[["subject"]]
  )
  testthat::expect_false(identical(
    openssl::write_der(certificates[[1L]]),
    openssl::write_der(certificates[[2L]])
  ))
  for (async in c(FALSE, TRUE)) {
    for (par in c(FALSE, TRUE)) {
      for (confirmation in c(TRUE, FALSE)) {
        clients <- lapply(c("client", "alternate"), function(name) {
          mtls_resource_client(fixture, alg, name, par, confirmation)
        })
        tokens <- lapply(seq_along(clients), function(i) {
          mtls_resource_login(
            clients[[i]],
            async,
            tempfile("exchange-", tmpdir = fixture[["root"]])
          )
        })
        testthat::expect_false(identical(
          tokens[[1L]]@access_token,
          tokens[[2L]]@access_token
        ))
        for (i in seq_along(tokens)) {
          token <- tokens[[i]]
          certificate <- c("client", "alternate")[[i]]
          other <- c("alternate", "client")[[i]]
          if (confirmation) {
            thumbprint <- shinyOAuth:::base64url_encode(openssl::sha256(openssl::write_der(certificates[[
              i
            ]])))
            testthat::expect_identical(token@cnf[["x5t#S256"]], thumbprint)
          } else {
            testthat::expect_length(token@cnf, 0L)
          }
          expect_mtls_resource_denied(mtls_resource_attack(
            fixture,
            token,
            other
          ))
          expect_mtls_resource_denied(mtls_resource_attack(fixture, token))
          expect_mtls_resource_denied(mtls_resource_attack(
            fixture,
            token,
            other,
            certificate
          ))
          expect_mtls_resource_denied(mtls_resource_attack(
            fixture,
            token,
            forwarded = certificate
          ))
          accepted <- mtls_resource_attack(fixture, token, certificate, other)
          testthat::expect_identical(httr2::resp_status(accepted), 200L)
          testthat::expect_identical(
            httr2::resp_body_json(accepted),
            list(resource = "certificate-bound-content")
          )
          unknown <- token
          unknown@access_token <- "not-issued-by-the-fixture"
          expect_mtls_resource_denied(
            mtls_resource_attack(fixture, unknown, certificate),
            "resource_token"
          )
          # Rejected attempts leave the rightful grant usable through the API.
          client <- clients[[i]]
          shiny::testServer(
            function(input, output, session) {
              connection <- shinyOAuth::oauth_connection(
                client,
                shiny::reactive(token)
              )
            },
            {
              response <- connection[["request"]](
                "api",
                "records",
                required_scopes = "mtls"
              )
              testthat::expect_identical(httr2::resp_status(response), 200L)
              testthat::expect_identical(
                httr2::resp_body_json(response),
                list(resource = "certificate-bound-content")
              )
            }
          )
        }
      }
    }
  }
  unbound_client <- mtls_resource_client(
    fixture,
    alg,
    "client",
    FALSE,
    FALSE,
    bound = FALSE
  )
  unbound <- mtls_resource_login(
    unbound_client,
    FALSE,
    tempfile("exchange-unbound-", tmpdir = fixture[["root"]]),
    request_resource = FALSE
  )
  expect_mtls_resource_denied(
    mtls_resource_attack(fixture, unbound, "client"),
    "resource_unbound"
  )
}

for (alg in c("RS256", "RS384")) {
  testthat::test_that(
    paste(
      "independent resource enforces per-token TLS certificate binding with",
      alg
    ),
    run_mtls_resource(alg)
  )
}
