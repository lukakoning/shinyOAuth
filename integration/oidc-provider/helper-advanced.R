interop_client_certificates <- function(environment) {
  executable <- Sys.getenv("SHINYOAUTH_OPENSSL", unset = Sys.which("openssl"))
  if (!nzchar(executable) && .Platform[["OS.type"]] == "windows") {
    executable <- file.path(
      Sys.getenv("ProgramFiles"),
      "Git/usr/bin/openssl.exe"
    )
  }
  directory <- file.path(environment[["output"]], "clients")
  dir.create(directory)
  generate <- function(name) {
    cert <- file.path(directory, paste0(name, ".pem"))
    key <- file.path(directory, paste0(name, "-key.pem"))
    result <- processx::run(
      executable,
      c(
        "req",
        "-x509",
        "-nodes",
        "-days",
        "2",
        "-newkey",
        "rsa:2048",
        "-keyout",
        key,
        "-out",
        cert,
        "-subj",
        "/CN=fixture-client"
      ),
      stdout = file.path(directory, paste0(name, ".log")),
      stderr = file.path(directory, paste0(name, ".stderr")),
      error_on_status = FALSE
    )
    if (result[["status"]] != 0L) {
      stop("Temporary client certificate generation failed")
    }
    list(cert_file = cert, key_file = key)
  }
  result <- generate("legitimate")
  result[["wrong"]] <- generate("different")
  result[["thumbprint"]] <- sub(
    "=+$",
    "",
    chartr(
      "+/",
      "-_",
      as.character(openssl::base64_encode(
        openssl::sha256(openssl::write_der(openssl::read_cert(result[[
          "cert_file"
        ]])))
      ))
    )
  )
  result
}

interop_tamper_jarm <- function(tab, origin) {
  observed <- new.env(parent = emptyenv())
  observed[["tampered"]] <- FALSE
  tab[["Fetch"]][["requestPaused"]](function(params) {
    url <- params[["request"]][["url"]]
    query <- httr2::url_parse(url)[["query"]]
    value <- query[["response"]]
    if (
      !isTRUE(observed[["tampered"]]) &&
        startsWith(url, paste0(origin, "/")) &&
        openid_string(value)
    ) {
      parts <- strsplit(value, ".", fixed = TRUE)[[1L]]
      if (length(parts) != 3L) {
        stop("Expected signed JARM callback")
      }
      parts[[3L]] <- paste0(
        if (startsWith(parts[[3L]], "A")) "B" else "A",
        substring(parts[[3L]], 2L)
      )
      query[["response"]] <- paste(parts, collapse = ".")
      url <- paste0(sub("\\?.*$", "", url), "?", httr2::url_query_build(query))
      observed[["tampered"]] <- TRUE
    }
    tab[["Fetch"]][["continueRequest"]](
      requestId = params[["requestId"]],
      url = url
    )
  })
  tab[["Fetch"]][["enable"]](
    patterns = list(list(
      urlPattern = paste0(origin, "/?response=*"),
      requestStage = "Request"
    ))
  )
  observed
}

interop_run_advanced <- function(
  root,
  environment,
  transport,
  library,
  context,
  selection,
  tamper = FALSE
) {
  run_id <- paste(format(openssl::rand_bytes(16)), collapse = "")
  key <- openssl::rsa_keygen(2048)
  public <- jsonlite::fromJSON(
    jose::write_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  public[["kid"]] <- paste0("jar-", run_id)
  public[["alg"]] <- "RS256"
  public[["use"]] <- "sig"
  mode <- selection[c("sender", "par", "jarm")]
  config <- list(
    run_id = run_id,
    client_id = paste0("client-", run_id),
    client_auth_type = "client_secret_basic",
    client_secret = paste(format(openssl::rand_bytes(32)), collapse = ""),
    client_jwk = public,
    client_assertion_private_key = openssl::write_pem(key),
    client_assertion_private_key_kid = public[["kid"]],
    advanced = mode,
    sender_constraint = selection[["sender"]],
    mtls = if (identical(selection[["sender"]], "mtls")) {
      environment[["client_certificates"]]
    } else {
      NULL
    },
    mtls_thumbprint = if (identical(selection[["sender"]], "mtls")) {
      environment[["client_certificates"]][["thumbprint"]]
    } else {
      NULL
    },
    redirect_uri = paste0(transport[["origin"]], "/"),
    scopes = c("openid", "profile", "email", "offline_access"),
    response_mode = if (isTRUE(selection[["jarm"]])) "jwt" else "query",
    extra_auth_params = list(prompt = "consent"),
    callback_rejection = tamper,
    transport = context[["transport"]]
  )
  stack <- interop_start(environment, config)
  config[["issuer"]] <- config[["provider_origin"]] <- stack[["origin"]]
  config[["mtls_origin"]] <- stack[["mtls_origin"]]
  discovery <- interop_request(stack, "/.well-known/openid-configuration")
  required <- c(
    "request_object_signing_alg_values_supported",
    "userinfo_signing_alg_values_supported"
  )
  for (name in required) {
    if (!"RS256" %in% unlist(discovery[[name]])) {
      stop("Missing advanced signing discovery capability")
    }
  }
  if (
    !isTRUE(discovery[["require_signed_request_object"]]) ||
      (isTRUE(selection[["par"]]) &&
        !openid_string(discovery[["pushed_authorization_request_endpoint"]])) ||
      (isTRUE(selection[["jarm"]]) &&
        !"jwt" %in% unlist(discovery[["response_modes_supported"]]))
  ) {
    stop("Missing advanced discovery capability")
  }
  app <- openid_app_start(root, stack, transport, config, library)
  browser <- openid_browser(stack[["spki"]])
  tab <- browser[["new_session"]]()
  tab[["Page"]][["navigate"]](paste0(app[["origin"]], "/"))
  initial <- openid_wait_app(app, browser, tab)
  app[["worker_handles"]] <- lapply(
    initial[["transport"]][["probes"]],
    function(probe) ps::ps_handle(probe[["pid"]])
  )
  observation <- if (tamper) {
    openid_observe_http_callback(tab, app[["origin"]])
  } else {
    NULL
  }
  changed <- if (tamper) interop_tamper_jarm(tab, app[["origin"]]) else NULL
  openid_browser_value(tab, "document.querySelector('#login').click()")
  for (prompt in c("login", "consent")) {
    selector <- paste0("#fixture-", prompt)
    openid_wait(
      function() {
        isTRUE(openid_browser_value(
          tab,
          paste0("!!document.querySelector('", selector, "')")
        ))
      },
      paste("Advanced", prompt, "interaction"),
      30
    )
    openid_browser_value(
      tab,
      paste0("document.querySelector('", selector, "').click()")
    )
  }
  callback <- if (tamper) {
    openid_wait_http_callback(app, browser, tab, initial, observation)
  } else {
    NULL
  }
  before <- if (tamper) {
    callback[["app"]]
  } else {
    openid_wait_app(
      app,
      browser,
      tab,
      terminal = TRUE,
      after_session = initial[["session_number"]]
    )
  }
  after <- before
  resource <- probes <- lifecycle <- NULL
  if (!tamper) {
    if (
      !openid_app_matches(
        before,
        list(outcome = "authenticated"),
        run_id,
        context[["package_version"]]
      )
    ) {
      stop("Advanced login failed")
    }
    openid_browser_value(tab, "document.querySelector('#refresh').click()")
    after <- openid_wait(
      function() {
        value <- openid_wait_app(app, browser, tab)
        if (isTRUE(value[["refresh"]][["done"]])) value else NULL
      },
      "Advanced refresh",
      30
    )
    for (button in c("resource", "probes", "lifecycle")) {
      openid_browser_value(
        tab,
        paste0("document.querySelector('#", button, "').click()")
      )
      value <- openid_wait(
        function() {
          snapshot <- openid_wait_app(app, browser, tab)
          if (isTRUE(snapshot[["advanced"]][[button]][["done"]])) {
            snapshot
          } else {
            NULL
          }
        },
        paste("Advanced", button),
        30
      )
      if (button == "resource") {
        resource <- value[["advanced"]][[button]]
      }
      if (button == "probes") {
        probes <- value[["advanced"]][[button]]
      }
      if (button == "lifecycle") lifecycle <- value[["advanced"]][[button]]
    }
  }
  selected_metadata <- discovery[intersect(
    names(discovery),
    c(
      "issuer",
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri",
      "require_signed_request_object",
      "request_object_signing_alg_values_supported",
      "userinfo_signing_alg_values_supported",
      "pushed_authorization_request_endpoint",
      "require_pushed_authorization_requests",
      "response_modes_supported",
      "authorization_signing_alg_values_supported",
      "dpop_signing_alg_values_supported",
      "tls_client_certificate_bound_access_tokens",
      "mtls_endpoint_aliases",
      "introspection_endpoint",
      "revocation_endpoint"
    )
  )]
  row <- list(
    id = paste0(selection[["id"]], if (tamper) "-invalid-jarm" else ""),
    case_id = run_id,
    run_id = context[["run_id"]],
    checkout_revision = context[["checkout_revision"]],
    mode = mode,
    outcome = if (tamper) "callback_rejected" else "authenticated",
    initial = initial,
    before_refresh = before,
    app = after,
    steps = list(before),
    between_logins = list(),
    action = if (tamper) "login" else "refresh",
    provider_origin = stack[["origin"]],
    app_origin = app[["origin"]],
    discovery = selected_metadata,
    resource = resource,
    probes = probes,
    lifecycle = lifecycle,
    callback_http = callback[["http"]],
    tampered = if (tamper) isTRUE(changed[["tampered"]]) else FALSE,
    callback_cleaned = if (tamper) {
      isTRUE(callback[["http"]][["final_url_verified"]])
    } else {
      identical(openid_browser_value(tab, "location.search"), "")
    },
    provider = interop_request(stack, "/fixture/evidence", TRUE),
    browser_version = tab[["Browser"]][["getVersion"]]()[["product"]]
  )
  openid_stop_app(app)
  row[["worker_cleanup_verified"]] <- TRUE
  openid_close_browser(browser)
  interop_stop(stack)
  row[["cleanup_verified"]] <- TRUE
  cat("Advanced case", row[["id"]], context[["transport"]], "completed\n")
  row
}
