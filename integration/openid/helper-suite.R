openid_string <- function(value) {
  is.character(value) && length(value) == 1L && !is.na(value) && nzchar(value)
}

openid_variant_key <- function(variant) {
  # The pinned refresh plan has no forced per-module variants (JSON null).
  # Runtime evidence still has to match the full, non-null plan variant.
  if (is.null(variant)) {
    return("null")
  }
  if (
    !is.list(variant) ||
      is.null(names(variant)) ||
      anyDuplicated(names(variant)) ||
      !all(vapply(variant, openid_string, logical(1)))
  ) {
    stop("Invalid suite variant")
  }
  as.character(jsonlite::toJSON(
    variant[sort(names(variant))],
    auto_unbox = TRUE
  ))
}

openid_profiles <- function(root = ".") {
  manifest <- jsonlite::read_json(file.path(
    root,
    "integration/openid/profiles.json"
  ))
  if (
    !identical(manifest[["schema_version"]], 2L) ||
      !identical(
        manifest[["source_revision"]],
        openid_lock(root)[["source_revision"]]
      )
  ) {
    stop("OpenID profile manifest does not match the suite lock")
  }
  manifest
}

openid_plan_spec <- function(manifest, profile) {
  selection <- manifest[["profiles"]][[profile]]
  if (is.null(selection) || !openid_string(selection[["plan"]])) {
    stop("Unknown OpenID profile or missing plan selection")
  }
  spec <- manifest[["plans"]][[selection[["plan"]]]]
  if (is.null(spec) || !openid_string(spec[["plan"]])) {
    stop("Unknown OpenID plan specification")
  }
  spec
}

openid_suite_plan <- function(
  stack,
  manifest,
  redirect_uri,
  profile = "smoke",
  .spec = NULL,
  .request = openid_api
) {
  spec <- if (is.null(.spec)) openid_plan_spec(manifest, profile) else .spec
  random <- function() paste(format(openssl::rand_bytes(16)), collapse = "")
  registration <- list(
    client_id = paste0("shinyoauth-", random()),
    client_secret = paste(format(openssl::rand_bytes(32)), collapse = ""),
    redirect_uri = redirect_uri,
    scope = "openid profile email",
    request_type = "plain_http_request"
  )
  method <- utils::modifyList(
    spec[["plan_variant"]],
    as.list(spec[["module_variant"]])
  )[["client_auth_type"]]
  credentials <- list(client_secret = registration[["client_secret"]])
  if (
    spec[["plan"]] %in%
      c(
        "oidcc-client-test-plan",
        "fapi2-security-profile-final-client-test-plan"
      )
  ) {
    registration[["token_endpoint_auth_method"]] <- method
  }
  if (method %in% c("none", "private_key_jwt")) {
    registration[["client_secret"]] <- credentials[["client_secret"]] <- NULL
  }
  if (identical(method, "private_key_jwt")) {
    key <- if (identical(spec[["client_assertion_alg"]], "ES256")) {
      openssl::ec_keygen("P-256")
    } else {
      openssl::rsa_keygen(2048)
    }
    jwk <- jsonlite::fromJSON(
      jose::write_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    )
    jwk[["kid"]] <- paste0("key-", random())
    jwk[["alg"]] <- spec[["client_assertion_alg"]]
    jwk[["use"]] <- "sig"
    if (any(c("d", "p", "q", "dp", "dq", "qi") %in% names(jwk))) {
      stop("Private JWK cannot enter suite registration")
    }
    registration[["jwks"]] <- list(keys = list(jwk))
    credentials[["private_key"]] <- openssl::write_pem(key)
    credentials[["key_id"]] <- jwk[["kid"]]
  }
  if (method %in% c("client_secret_jwt", "private_key_jwt")) {
    registration[["token_endpoint_auth_signing_alg"]] <- spec[[
      "client_assertion_alg"
    ]]
  }
  config <- list(
    alias = paste0("shinyoauth-", random()),
    description = "shinyOAuth local client validation",
    publish = "nothing",
    client = registration
  )
  if (
    identical(spec[["plan"]], "fapi2-security-profile-final-client-test-plan")
  ) {
    server_key <- openssl::ec_keygen("P-256")
    server_jwk <- jsonlite::fromJSON(
      jose::write_jwk(server_key),
      simplifyVector = FALSE
    )
    server_jwk[["kid"]] <- paste0("server-", random())
    server_jwk[["alg"]] <- "ES256"
    server_jwk[["use"]] <- "sig"
    config[["server"]] <- list(jwks = list(keys = list(server_jwk)))
  }
  plan <- .request(
    stack,
    "/api/plan",
    data = config,
    query = list(
      planName = spec[["plan"]],
      variant = openid_variant_key(spec[["plan_variant"]])
    ),
    status = 201L
  )
  if (
    !openid_string(plan[["id"]]) ||
      !grepl("^[A-Za-z0-9]+$", plan[["id"]]) ||
      !identical(plan[["name"]], spec[["plan"]])
  ) {
    stop("Unexpected OpenID plan identity")
  }
  modules <- plan[["modules"]]
  ids <- vapply(modules, function(module) module[["testModule"]], character(1))
  if (
    anyDuplicated(ids) ||
      !setequal(ids, unlist(spec[["available_modules"]]))
  ) {
    stop("OpenID plan module list changed from the pinned manifest")
  }
  expected <- openid_variant_key(spec[["module_variant"]])
  if (
    !all(vapply(
      modules,
      function(module) {
        identical(openid_variant_key(module[["variant"]]), expected)
      },
      logical(1)
    ))
  ) {
    stop("OpenID module variants changed from the pinned manifest")
  }
  list(
    id = plan[["id"]],
    modules = modules,
    registration = registration,
    credentials = credentials,
    alias = config[["alias"]],
    spec = spec
  )
}

openid_suite_info <- function(stack, module, .request = openid_api) {
  info <- .request(stack, paste0("/api/info/", module[["id"]]))
  if (
    !identical(info[["testId"]], module[["id"]]) ||
      !identical(info[["testName"]], module[["name"]]) ||
      !identical(info[["planId"]], module[["plan_id"]]) ||
      !identical(
        openid_variant_key(info[["variant"]]),
        openid_variant_key(module[["variant"]])
      )
  ) {
    stop("OpenID module identity or variants do not match this attempt")
  }
  if (!openid_string(info[["status"]])) {
    stop("OpenID module has no lifecycle status")
  }
  info
}

openid_suite_wait <- function(
  stack,
  module,
  states,
  timeout = 60,
  .request = openid_api
) {
  openid_wait(
    function() {
      info <- openid_suite_info(stack, module, .request)
      if (info[["status"]] %in% states) {
        return(info)
      }
      if (info[["status"]] %in% c("INTERRUPTED", "FINISHED")) {
        stop("OpenID module ended before the expected lifecycle state")
      }
      if (
        !info[["status"]] %in% c("CREATED", "CONFIGURED", "RUNNING", "WAITING")
      ) {
        stop("Unknown OpenID module lifecycle state")
      }
      NULL
    },
    "OpenID module lifecycle",
    timeout
  )
}

openid_suite_module <- function(stack, plan, name, .env = parent.frame()) {
  entry <- Filter(
    function(value) identical(value[["testModule"]], name),
    plan[["modules"]]
  )
  if (length(entry) != 1L) {
    stop("Module is absent or ambiguous in this plan")
  }
  forced <- entry[[1L]][["variant"]]
  query <- list(test = name, plan = plan[["id"]])
  if (!is.null(forced)) {
    query[["variant"]] <- openid_variant_key(forced)
  }
  created <- openid_api(
    stack,
    "/api/runner",
    query = query,
    method = "POST",
    status = 201L
  )
  if (
    !openid_string(created[["id"]]) ||
      !grepl("^[A-Za-z0-9]+$", created[["id"]]) ||
      !identical(created[["name"]], name)
  ) {
    stop("Unexpected OpenID runner identity")
  }
  module <- list(
    id = created[["id"]],
    name = name,
    plan_id = plan[["id"]],
    variant = utils::modifyList(
      plan[["spec"]][["plan_variant"]],
      as.list(forced)
    )
  )
  withr::defer(openid_suite_cancel(stack, module), envir = .env)
  info <- openid_suite_wait(stack, module, c("CONFIGURED", "WAITING"))
  if (identical(info[["status"]], "CONFIGURED")) {
    openid_api(stack, paste0("/api/runner/", module[["id"]]), method = "POST")
    openid_suite_wait(stack, module, "WAITING")
  }
  runtime <- openid_api(stack, paste0("/api/runner/", module[["id"]]))
  if (
    !identical(runtime[["id"]], module[["id"]]) ||
      !identical(runtime[["name"]], name) ||
      !is.null(runtime[["error"]])
  ) {
    stop("OpenID runner identity or setup failed")
  }
  issuer <- runtime[["exposed"]][["issuer"]]
  discovery <- runtime[["exposed"]][["discoveryUrl"]]
  if (
    !openid_string(issuer) ||
      !startsWith(
        issuer,
        paste0(stack[["origin"]], "/test/a/", plan[["alias"]], "/")
      ) ||
      !identical(
        discovery,
        paste0(sub("/$", "", issuer), "/.well-known/openid-configuration")
      )
  ) {
    stop("OpenID exported issuer is missing or outside this local test")
  }
  module[["issuer"]] <- issuer
  if (
    identical(
      plan[["spec"]][["plan"]],
      "fapi2-security-profile-final-client-test-plan"
    )
  ) {
    resource <- runtime[["exposed"]][["accounts_endpoint"]]
    if (!identical(resource, paste0(issuer, "open-banking/v1.1/accounts"))) {
      stop("FAPI resource endpoint is missing or outside this local issuer")
    }
    module[["resource_endpoint"]] <- resource
  }
  module
}

openid_suite_cache_policy <- function(stack, manifest, redirect_uri) {
  plan <- openid_suite_plan(stack, manifest, redirect_uri, "config")
  module <- openid_suite_module(
    stack,
    plan,
    "oidcc-client-test-signing-key-rotation"
  )
  response <- httr2::request(paste0(module[["issuer"]], "jwks")) |>
    httr2::req_options(cainfo = stack[["ca"]], followlocation = FALSE) |>
    httr2::req_timeout(10) |>
    httr2::req_perform()
  cache_control <- httr2::resp_header(response, "cache-control")
  directives <- trimws(strsplit(
    tolower(if (is.null(cache_control)) "" else cache_control),
    ",",
    fixed = TRUE
  )[[1L]])
  if (
    !identical(httr2::resp_status(response), 200L) ||
      !"no-store" %in% directives
  ) {
    stop(
      "Pinned suite JWKS cache policy changed; review Configuration coverage"
    )
  }
  openid_suite_cancel(stack, module)
  list(
    no_store = TRUE,
    source_revision = manifest[["source_revision"]],
    suite_id = module[["id"]]
  )
}

openid_suite_cancel <- function(stack, module) {
  if (isTRUE(stack[["lifecycle"]][["stopped"]])) {
    return(invisible(NULL))
  }
  info <- openid_suite_info(stack, module)
  if (!info[["status"]] %in% c("FINISHED", "INTERRUPTED")) {
    openid_api(stack, paste0("/api/runner/", module[["id"]]), method = "DELETE")
    openid_suite_wait(stack, module, "INTERRUPTED", timeout = 15)
  }
  invisible(NULL)
}
