openid_string <- function(value) {
  is.character(value) && length(value) == 1L && !is.na(value) && nzchar(value)
}

openid_variant_key <- function(variant) {
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
    !identical(manifest[["schema_version"]], 1L) ||
      !identical(
        manifest[["source_revision"]],
        openid_lock(root)[["source_revision"]]
      )
  ) {
    stop("OpenID profile manifest does not match the suite lock")
  }
  manifest
}

openid_suite_plan <- function(stack, manifest, redirect_uri) {
  random <- function() paste(format(openssl::rand_bytes(16)), collapse = "")
  registration <- list(
    client_id = paste0("shinyoauth-", random()),
    client_secret = random(),
    redirect_uri = redirect_uri,
    scope = "openid profile email",
    request_type = "plain_http_request"
  )
  config <- list(
    alias = paste0("shinyoauth-", random()),
    description = "shinyOAuth local client validation",
    publish = "nothing",
    client = registration
  )
  plan <- openid_api(
    stack,
    "/api/plan",
    data = config,
    query = list(
      planName = manifest[["plan"]],
      variant = openid_variant_key(manifest[["plan_variant"]])
    ),
    status = 201L
  )
  if (
    !openid_string(plan[["id"]]) ||
      !grepl("^[A-Za-z0-9]+$", plan[["id"]]) ||
      !identical(plan[["name"]], manifest[["plan"]])
  ) {
    stop("Unexpected OpenID plan identity")
  }
  modules <- plan[["modules"]]
  ids <- vapply(modules, function(module) module[["testModule"]], character(1))
  if (
    anyDuplicated(ids) ||
      !setequal(ids, unlist(manifest[["available_modules"]]))
  ) {
    stop("OpenID plan module list changed from the pinned manifest")
  }
  expected <- openid_variant_key(manifest[["module_variant"]])
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
    alias = config[["alias"]],
    manifest = manifest
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
  created <- openid_api(
    stack,
    "/api/runner",
    query = list(
      test = name,
      plan = plan[["id"]],
      variant = openid_variant_key(entry[[1L]][["variant"]])
    ),
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
      plan[["manifest"]][["plan_variant"]],
      entry[[1L]][["variant"]]
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
  module
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
