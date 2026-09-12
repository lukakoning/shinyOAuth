inferno_registration <- function(stack, style, algorithm, site) {
  registration <- list(fhir_base = stack$fhir_base, style = style, algorithm = algorithm,
    client_id = paste0("shinyoauth-", site, "-", paste(openssl::sha256(openssl::rand_bytes(16)))),
    patient = paste0("patient-", site), practitioner = paste0("practitioner-", site))
  # Upstream compares decoded Basic bytes without form-decoding the components.
  # Use a valid random unreserved secret; reserved-character credentials remain
  # covered by package wire-encoding tests, not by an independent server pass.
  if (style == "header") registration$secret <- paste(format(openssl::rand_bytes(32)), collapse = "")
  if (style == "private_key_jwt") {
    key <- if (algorithm == "ES384") openssl::ec_keygen("P-384") else openssl::rsa_keygen(2048)
    registration$private_pem <- openssl::write_pem(key)
    registration$kid <- paste0("client-", site)
    jwk <- jsonlite::fromJSON(jose::write_jwk(key$pubkey), simplifyVector = FALSE)
    # Some jose versions include ASN.1's sign byte. RSA JWK integers use the
    # minimum-length unsigned representation required by RFC 7518.
    for (field in intersect(c("n", "e"), names(jwk))) {
      encoded <- jwk[[field]]
      bytes <- openssl::base64_decode(paste0(chartr("-_", "+/", encoded),
        strrep("=", (4L - nchar(encoded) %% 4L) %% 4L)))
      while (length(bytes) > 1L && bytes[[1L]] == as.raw(0)) bytes <- bytes[-1L]
      jwk[[field]] <- sub("=+$", "", chartr("+/", "-_", openssl::base64_encode(bytes)))
    }
    jwk$kid <- registration$kid
    jwk$alg <- algorithm
    jwk$use <- "sig"
    registration$jwks <- jsonlite::toJSON(list(keys = list(jwk)), auto_unbox = TRUE)
  }
  registration
}

inferno_begin_session <- function(stack, registration, origin, site, launch) {
  type <- switch(registration$style, public = "public", header = "confidential_symmetric",
    private_key_jwt = "confidential_asymmetric")
  session <- inferno_api(stack, "/api/test_sessions", list(test_suite_id = inferno_suite,
    suite_options = list(list(id = "client_type", value = paste("SMART", "authorization_code", type, sep = ",")))))
  inputs <- list(client_id = registration$client_id,
    smart_redirect_uris = paste0(origin, "/callback/", site),
    launch_context = jsonlite::toJSON(list(patient = registration$patient), auto_unbox = TRUE),
    fhir_user_relative_reference = paste0("Practitioner/", registration$practitioner),
    echoed_fhir_response = jsonlite::toJSON(list(resourceType = "Bundle", type = "searchset",
      total = 0L, entry = list()), auto_unbox = TRUE),
    fhir_read_resources_bundle = jsonlite::toJSON(list(resourceType = "Bundle", type = "collection",
      entry = list(list(resource = list(resourceType = "Patient", id = registration$patient)),
        list(resource = list(resourceType = "Practitioner", id = registration$practitioner)))), auto_unbox = TRUE))
  if (launch == "ehr") inputs$smart_launch_urls <- paste0(origin, "/launch")
  if (registration$style == "header") inputs$smart_client_secret <- registration$secret
  if (registration$style == "private_key_jwt") inputs$smart_jwk_set <- registration$jwks
  run <- inferno_api(stack, "/api/test_runs", list(test_session_id = session$id,
    test_suite_id = inferno_suite,
    inputs = lapply(names(inputs), function(name) list(name = name, value = as.character(inputs[[name]])))))
  inferno_wait(function() {
    current <- inferno_api(stack, paste0("/api/test_runs/", run$id))
    if (current$status == "done") stop("Inferno finished before the application interaction")
    if (current$status == "waiting") current else NULL
  }, "Inferno client interaction")
  data <- inferno_api(stack, paste0("/api/test_sessions/", session$id, "/session_data"))
  get_input <- function(name) {
    rows <- Filter(function(row) identical(row$name, name), data)
    if (length(rows) == 1L) rows[[1L]]$value else NULL
  }
  list(id = session$id, run_id = run$id, expected_tests = inferno_expected_tests(registration$style),
    continuation = get_input("continuation_url"),
    launch_url = get_input("launch_urls"))
}

inferno_finish_session <- function(stack, session) {
  stopifnot(is.character(session$continuation), startsWith(session$continuation, paste0(stack$origin, "/")))
  inferno_api(stack, substring(session$continuation, nchar(stack$origin) + 1L), json = FALSE)
  inferno_wait(function() {
    current <- inferno_api(stack, paste0("/api/test_runs/", session$run_id))
    if (current$status == "done") current else NULL
  }, "Inferno request verification")
  results <- inferno_api(stack, paste0("/api/test_sessions/", session$id, "/results"))
  # One registration, one interaction and authorization/token/token-use checks.
  # A missing, skipped, waiting or failed test must never pass this gate.
  inferno_verification_summary(results, session$expected_tests)
}

inferno_start_app <- function(root, output, registrations, launch, async = FALSE,
  authorization_method = "GET", .env = parent.frame()) {
  port <- httpuv::randomPort()
  tls <- inferno_tls(root, port, .env)
  process <- callr::r_bg(function(root, origin, port, registrations, launch, async, authorization_method) {
    Sys.setenv(CURL_SSL_BACKEND = "openssl", CURL_CA_BUNDLE = file.path(root, "integration/keycloak/tls/ca-cert.pem"),
      R_LIBS = paste(.libPaths(), collapse = .Platform$path.sep))
    options(shinyOAuth.allowed_hosts = c("localhost", "127.0.0.1"),
      shinyOAuth.debug = identical(Sys.getenv("SHINYOAUTH_INFERNO_DEBUG"), "true"))
    source(file.path(root, "integration/smart/inferno-app.R"))
    inferno_browser_app(origin, port, registrations, launch, async, authorization_method)
  }, args = list(root, tls$origin, port, registrations, launch, async, authorization_method),
    libpath = .libPaths(), supervise = TRUE,
    stdout = file.path(output, "app.stdout"), stderr = file.path(output, "app.stderr"))
  withr::defer({ if (process$is_alive()) process$kill() }, envir = .env)
  list(origin = tls$origin, process = process,
    ca = file.path(root, "integration/keycloak/tls/ca-cert.pem"))
}

inferno_open_browser <- function(app, .env = parent.frame()) {
  last_error <- "not ready"
  inferno_wait(function() {
    if (!app$process$is_alive()) stop("Shiny app exited; inspect the private app.stderr log")
    tryCatch({ inferno_api(app, "/", json = FALSE); TRUE }, error = function(e) {
      last_error <<- conditionMessage(e)
      NULL
    })
  }, paste0("Shiny app readiness (", last_error, ")"))
  chrome <- chromote::Chromote$new()
  withr::defer(retention_chrome_close(chrome), envir = .env)
  context <- chrome$Target$createBrowserContext()$browserContextId
  target <- chrome$Target$createTarget("about:blank", browserContextId = context)$targetId
  browser <- chromote::ChromoteSession$new(parent = chrome, targetId = target)
  withr::defer(browser$close(), envir = .env)
  browser$Security$setIgnoreCertificateErrors(ignore = TRUE)
  tryCatch(retention_browser_value(browser, paste0("window.location.replace(",
    jsonlite::toJSON(app$origin, auto_unbox = TRUE), ")")), error = function(...) NULL)
  retention_browser_wait(browser, function() retention_browser_snapshot(browser), "Shiny ready")
  list(browser = browser, version = chrome$Browser$getVersion()$product)
}
