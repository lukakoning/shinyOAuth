#' Register a SMART EHR launch entry route
#'
#' Declare which approved SMART targets an EHR launch URL may select. Pass the
#' result in `launch_routes` to [oauth_connections_ui()]. The route is separate
#' from OAuth callbacks: `iss` means the FHIR base only here. Both `iss` and
#' `launch` are required, and callback parameters are rejected on this route.
#'
#' Initial entry is untrusted. It selects an already configured target by exact
#' FHIR base, performs no discovery, and establishes no healthcare identity.
#' A short-lived encrypted record binds the opaque launch handle to the browser
#' owner and target. A clean continuation proves that owner before a fresh OAuth
#' state/PKCE transaction can begin. Consumed handles cannot be reused to reconnect.
#'
#' @param path Absolute application path, such as `"/smart/launch"`. Register
#'   `paste0(manager$app_origin, path)` with the EHR. It must be inside the UI's
#'   `app_base_path` and distinct from every callback and other launch route.
#' @param targets Character vector of target IDs in the manager. Each must be an
#'   EHR-mode [smart_target()]. A route cannot contain two registrations for the
#'   same exact FHIR base; give those registrations separate launch routes.
#' @param max_age Launch handoff lifetime in seconds, 30 to 300, default 120.
#'   Owner expiry and OAuth state expiry can shorten this lifetime.
#' @return A plain route configuration list, with no credentials or live state.
#' @details
#' The initial implementation supports top-level GET entry with browser retention
#' in one R process. Account/session-only retention and iframe deployments are
#' not supported for EHR entry yet. The ordinary standalone manager remains usable
#' with its existing retention choices. Up to 1,000 unconsumed launch records are
#' retained per manager. Raw query size is limited to 8 KiB, launch handles to
#' 2 KiB, and the only allowed initial parameters are `iss` and `launch`.
#'
#' The HTTP response uses no-store and no-referrer policy and redirects to an
#' opaque, owner-bound continuation. Its script removes that ticket from browser
#' history before Shiny connects. The ticket alone cannot authorize a connection.
#' Application access logs must also avoid recording raw launch query strings.
#' Normal callback issuer checks and single-use browser/state checks still apply.
#' @seealso [smart_target()], [oauth_connections_ui()]
#' @references
#' [SMART EHR launch](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html#launch-app-ehr-launch)
#' @examples
#' \dontrun{
#' # hospital is an EHR-mode SMART target; manager uses browser retention.
#' ui <- oauth_connections_ui(app_ui, "health", manager,
#'   launch_routes = list(smart_launch_route("/smart/launch", "hospital")))
#' }
#' @export
smart_launch_route <- function(path, targets, max_age = 120) {
  if (!is_valid_string(path) || !startsWith(path, "/") ||
      grepl("[?#]", path) ||
      !is.character(targets) || !length(targets) || length(targets) > 64L ||
      anyNA(targets) || anyDuplicated(targets) ||
      any(!grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", targets)) ||
      !is.numeric(max_age) || length(max_age) != 1L ||
      !is.finite(max_age) || max_age < 30 || max_age > 300) {
    err_config("Invalid SMART launch route configuration")
  }
  resource_binding_components(paste0("https://app.example", path))
  list(path = path, targets = targets, max_age = max_age)
}

smart_launch_parameter <- "shinyOAuth_smart_launch"

smart_launch_routes_validate <- function(routes, manager, app_base_path) {
  if (!is.list(routes) || length(routes) > 32L) err_config("Invalid SMART launch routes")
  if (!length(routes)) return(invisible(NULL))
  if (!identical(manager$retention, "browser")) {
    err_config("SMART EHR launch currently requires browser retention")
  }
  if (!identical(manager$owner$same_site, "Lax")) {
    err_config("SMART top-level launch requires a Lax browser owner cookie")
  }
  paths <- character()
  callbacks <- vapply(manager$targets, function(target) {
    resource_binding_components(target$client@redirect_uri)$path
  }, character(1))
  for (route in routes) {
    if (!is.list(route) || !setequal(names(route), c("path", "targets", "max_age"))) {
      err_config("Use smart_launch_route() to configure EHR entry")
    }
    do.call(smart_launch_route, route)
    if (!startsWith(route$path, app_base_path) || route$path %in% c(paths, callbacks, app_base_path)) {
      err_config("SMART launch paths must be distinct from callbacks and inside the app")
    }
    paths <- c(paths, route$path)
    bases <- vapply(route$targets, function(id) {
      target <- manager$targets[[id]]
      if (is.null(target) || !identical(target$smart$launch, "ehr")) {
        err_config("SMART launch routes require configured EHR targets")
      }
      target$smart$fhir_base
    }, character(1))
    if (anyDuplicated(bases)) err_config("SMART launch route has ambiguous FHIR-base registrations")
  }
  invisible(NULL)
}

smart_launch_query <- function(query, continuation = FALSE) {
  if (!is.character(query) || length(query) != 1L || is.na(query) ||
      nchar(query, type = "bytes") > 8192L ||
      grepl("%(?![0-9A-Fa-f]{2})", query, perl = TRUE)) {
    err_input("Invalid SMART launch query")
  }
  reject_duplicate_form_encoded_members(query, "SMART launch query")
  fields <- httr2::url_query_parse(gsub("+", "%20", query, fixed = TRUE))
  expected <- if (continuation) smart_launch_parameter else c("iss", "launch")
  if (!setequal(names(fields), expected) || length(fields) != length(expected) ||
      !all(vapply(fields, is_valid_string, logical(1)))) {
    err_input("SMART launch requires its exact scalar parameters")
  }
  if (continuation) {
    if (!grepl("^[A-Za-z0-9_-]{32}$", fields[[smart_launch_parameter]])) {
      err_input("Invalid SMART continuation")
    }
  } else if (nchar(fields$iss, type = "bytes") > 2048L ||
      nchar(fields$launch, type = "bytes") > 2048L ||
      !grepl("^[!-~]+$", fields$launch)) {
    err_input("Invalid SMART launch parameter size or syntax")
  }
  fields
}

smart_launch_key <- function(manager) {
  as.raw(openssl::sha256(charToRaw(paste0("shinyOAuth/smart-launch/v1/", manager$state$id)),
    key = manager$keys$credentials))
}

smart_launch_prune <- function(manager) {
  entries <- manager$state$launches
  now <- as.numeric(Sys.time())
  for (id in ls(entries, all.names = TRUE)) {
    if (entries[[id]]$expires_at <= now) rm(list = id, envir = entries)
  }
}

smart_launch_open <- function(manager, entry, owner, expected_id = NULL) {
  record <- state_decrypt_gcm(entry$sealed, smart_launch_key(manager))
  if (!identical(record$purpose, "smart-launch-v1") ||
      !identical(record$owner, owner$id) ||
      !identical(record$generation, owner$generation) ||
      (!is.null(expected_id) && !identical(record$id, expected_id)) ||
      !is.numeric(record$expires_at) || length(record$expires_at) != 1L ||
      record$expires_at <= as.numeric(Sys.time())) {
    err_token("SMART launch is unavailable")
  }
  target <- manager$targets[[record$target]]
  if (is.null(target) || !identical(target$smart$launch, "ehr") ||
      !identical(record$fhir_base, target$smart$fhir_base) ||
      !identical(record$fingerprint, connection_current_target_fingerprint(target))) {
    err_token("SMART launch target changed")
  }
  record
}

smart_launch_http <- function(req, uri, manager, routes, app_base, handler) {
  if (!length(routes)) return(NULL)
  path <- tryCatch(resource_binding_components(uri)$path, error = function(...) NULL)
  if (is.null(path)) return(oauth_get_setup_error("Invalid SMART application path."))
  matches <- Filter(function(route) identical(route$path, path), routes)
  query <- req[["QUERY_STRING"]] %||% ""
  continuation <- length(oauth_module_query_raw_values(query, smart_launch_parameter)) > 0L
  if (!length(matches) && !continuation) return(NULL)
  tryCatch({
    if (!identical(req[["REQUEST_METHOD"]], "GET") ||
        identical(req[["HTTP_SEC_FETCH_DEST"]], "iframe")) {
      err_input("SMART EHR entry requires top-level GET navigation")
    }
    smart_launch_prune(manager)
    owners <- manager$state$owners
    cookie <- connection_owner_cookie_read(req, owners$cookie_name)
    owner <- owners$resolve(cookie)
    if (length(matches)) {
      fields <- smart_launch_query(query)
      route <- matches[[1L]]
      ids <- Filter(function(id) identical(manager$targets[[id]]$smart$fhir_base, fields$iss),
        route$targets)
      if (length(ids) != 1L) err_input("SMART launch FHIR base is not approved")
      if (length(manager$state$launches) >= 1000L) err_token("SMART launch capacity reached")
      headers <- list("Cache-Control" = "no-store", "Referrer-Policy" = "no-referrer")
      if (is.null(owner)) {
        created <- owners$create()
        owner <- owners$resolve(created$cookie)
        headers[["Set-Cookie"]] <- connection_owner_cookie_header(owners$cookie_name,
          created$cookie, manager$app_origin, manager$owner)
      }
      id <- random_urlsafe(32)
      target <- manager$targets[[ids[[1L]]]]
      expires <- min(owner$expires_at, as.numeric(Sys.time()) + route$max_age)
      record <- list(purpose = "smart-launch-v1", id = id, owner = owner$id,
        generation = owner$generation, target = ids[[1L]], fhir_base = fields$iss,
        launch = fields$launch, fingerprint = connection_current_target_fingerprint(target),
        expires_at = expires)
      entries <- manager$state$launches
      entries[[id]] <- list(expires_at = expires, owner = owner$id,
        sealed = state_encrypt_gcm(record, smart_launch_key(manager)))
      headers$Location <- paste0(app_base, "?", smart_launch_parameter, "=", id)
      return(shiny::httpResponse(303L, "text/plain", "", headers = headers))
    }
    fields <- smart_launch_query(query, continuation = TRUE)
    id <- fields[[smart_launch_parameter]]
    if (is.null(owner) || !identical(path, resource_binding_components(app_base)$path)) {
      err_token("SMART launch owner is unavailable")
    }
    entry <- manager$state$launches[[id]]
    if (is.null(entry)) err_token("SMART launch is unavailable")
    smart_launch_open(manager, entry, owner, id)
    clean <- if (is.environment(req)) {
      list2env(as.list(req, all.names = TRUE), parent = parent.env(req))
    } else req
    clean[["QUERY_STRING"]] <- ""
    clean[["REQUEST_URI"]] <- resource_binding_components(app_base)$path
    response <- handler(clean)
    if (is.null(response) || !isTRUE(response$status == 200L) ||
        !grepl("^text/html", response$content_type, ignore.case = TRUE)) {
      err_token("SMART launch continuation requires application HTML")
    }
    json <- function(value) as.character(jsonlite::toJSON(value, auto_unbox = TRUE))
    script <- paste0("<script>history.replaceState(null,'',", json(app_base),
      ");jQuery(document).one('shiny:connected',function(){Shiny.setInputValue(",
      json(shiny::NS(manager$state$id)("smart_launch")), ",", json(id),
      ",{priority:'event'});});</script>")
    if (!is.character(response$content) || length(response$content) != 1L ||
        !grepl("</body>", response$content, fixed = TRUE)) {
      err_token("SMART continuation requires a complete HTML document")
    }
    response$content <- sub("</body>", paste0(script, "</body>"), response$content, fixed = TRUE)
    response$headers <- response$headers[!tolower(names(response$headers)) %in%
      c("content-length", "etag", "content-md5", "cache-control", "referrer-policy")]
    response$headers <- c(response$headers,
      list("Cache-Control" = "no-store", "Referrer-Policy" = "no-referrer",
        "Content-Security-Policy" = "frame-ancestors 'none'"))
    response
  }, error = function(...) oauth_get_setup_error("SMART launch could not be validated; start a fresh EHR launch."))
}

smart_prepare_launch <- function(client, context, launch) {
  if (!client_uses_smart(client)) {
    if (!is.null(launch)) err_config("Launch parameters require a SMART target")
    return(invisible(NULL))
  }
  if (identical(client@smart$launch, "standalone")) {
    if (!is.null(launch)) err_config("Standalone SMART targets cannot reuse EHR launch handles")
  } else if (!is_valid_string(launch) || nchar(launch, type = "bytes") > 2048L ||
      !grepl("^[!-~]+$", launch) ||
      !identical(context$smart$fhir_base, client@smart$fhir_base) ||
      !identical(context$smart$launch_digest, state_policy_value_digest(launch))) {
    err_config("SMART EHR targets require a fresh registered launch transaction")
  }
  invisible(NULL)
}
