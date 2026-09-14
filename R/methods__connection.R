#' Make API requests with a Shiny session's current OAuth credentials
#'
#' Combine one module's reactive token with its client and approved API addresses
#' configured on [oauth_client()]. Call `$request()` on the returned connection instead of
#' assembling a token, client and URL for each request. It reads the reactive token
#' again after refresh or logout and restricts requests to the configured APIs.
#' This optional wrapper expires with its Shiny session; it does not implement
#' refresh itself or retain credentials across redirects.
#'
#' @param client An [OAuthClient] with non-empty `resource_bases`, created by
#'   [oauth_client()] or [smart_client()].
#' @param token A Shiny reactive expression returning the current [OAuthToken]
#'   or `NULL`, usually `shiny::reactive(auth$token)`. It must come from the
#'   module using `client`. Supplying that association is trusted server
#'   application wiring; a resource policy cannot prove an opaque token's audience.
#' @param session The owning Shiny session; defaults to the current session.
#' @return An [OAuthConnection] with `$id`, `$is_usable()`, `$summary()` and
#'   `$request(resource_id, path = "", query = NULL, method = "GET",
#'   required_scopes = character(), configure = NULL)`. Requests return [httr2]
#'   responses. `configure` can add a body and application headers; see
#'   [OAuthConnection] for its contract.
#' @details
#' Create the reference once inside `server()`. Access it only in that session's
#' reactive context. `$summary()` excludes tokens, identity claims and extension
#' context. `$is_usable()` checks local presence, known expiry and required scopes;
#' it cannot guarantee remote authorization. Unknown token expiry is unusable.
#'
#' Paths are relative to the selected base directory. Absolute and root-relative
#' references (including pagination links) must stay within that same base.
#' Dot segments and ambiguous encodings are rejected; redirects are never followed.
#' Bearer, DPoP and mTLS use the existing transport and the configured client.
#'
#' Use request-level `required_scopes` for optional operations. They must be
#' included in the client's requested scopes and covered by the current grant.
#' The package cannot infer arbitrary API permissions from an HTTP method/path.
#' The legacy module continues to own refresh and logout. Retained connection
#' storage and its independent lifecycle are available through
#' [oauth_connections()] and [oauth_connections_server()].
#'
#' @examples
#' \dontrun{
#' # Configure outside server():
#' client <- oauth_client(provider, "registered-app",
#'   redirect_uri = "https://app.example/callback", scopes = "read",
#'   resource_bases = c(api = "https://api.example/v1"))
#' # Inside server():
#' auth <- oauth_module_server("auth", client)
#' connection <- oauth_connection(client, shiny::reactive(auth$token))
#' data <- shiny::reactive({
#'   shiny::req(connection$is_usable())
#'   connection$request("api", "records", required_scopes = "read")
#' })
#' }
#' @export
oauth_connection <- function(
  client,
  token,
  session = shiny::getDefaultReactiveDomain()
) {
  S7::check_is_S7(client, OAuthClient)
  connection_client_fingerprint(client)
  if (!shiny::is.reactive(token)) {
    err_input("token must be a Shiny reactive expression")
  }
  owner <- connection_session_root(session)
  current <- connection_session_root(shiny::getDefaultReactiveDomain())
  if (
    is.null(owner) || !identical(owner, current) || isTRUE(owner$isClosed())
  ) {
    err_config("Connections must be created in their owning Shiny session")
  }
  binding <- new.env(parent = emptyenv())
  binding$owner <- owner
  binding$source <- token
  binding$active <- TRUE
  owner$onSessionEnded(function() {
    binding$active <- FALSE
    binding$source <- NULL
    binding$owner <- NULL
  })
  # The resolver and end callback share this frame. Drop argument references so
  # clearing the binding also releases its token source and session references.
  token <- NULL
  session <- NULL
  owner <- NULL
  current <- NULL
  resolver <- function() {
    current <- connection_session_root(shiny::getDefaultReactiveDomain())
    if (
      !isTRUE(binding$active) ||
        is.null(current) ||
        !identical(current, binding$owner) ||
        isTRUE(binding$owner$isClosed())
    ) {
      err_token("Connection is unavailable")
    }
    list(client = client, token = binding$source())
  }
  OAuthConnection$new(random_urlsafe(32), client, resolver)
}

connection_session_root <- function(session) {
  if (is.null(session) || !is.function(session$rootScope)) {
    return(NULL)
  }
  session$rootScope()
}

connection_record_summary <- function(record, id) {
  list(
    connection_id = id,
    client_label = record$client@label,
    status = connection_record_status(record),
    expires_at = if (is.null(record$token)) NA_real_ else record$token@expires_at,
    resource_ids = names(record$client@resource_bases)
  )
}

connection_record_status <- function(record) {
  if (!is.null(record$status) && !identical(record$status, "active")) {
    return(record$status)
  }
  token <- record$token
  if (is.null(token)) {
    return("disconnected")
  }
  if (client_uses_smart_scopes(record$client) &&
    !isTRUE(token@granted_scopes_verified)) {
    return("insufficient_scope")
  }
  expires <- token@expires_at
  if (is.na(expires)) {
    return("expiry_unknown")
  }
  if (expires <= as.numeric(Sys.time())) {
    return("expired")
  }
  if (
    client_scope_coverage(
      record$client,
      record$client@required_scopes,
      token@granted_scopes
    )$status !=
      "covered"
  ) {
    return("insufficient_scope")
  }
  if (
    client_scope_coverage(
      record$client,
      effective_client_scopes(record$client),
      token@granted_scopes
    )$status !=
      "covered"
  ) {
    return("limited")
  }
  "active"
}

connection_record_request <- function(
  record,
  resource_id,
  path,
  query,
  method,
  required_scopes,
  configure = NULL
) {
  if (
    !is_valid_string(resource_id) ||
      !resource_id %in% names(record$client@resource_bases)
  ) {
    err_input("Unknown resource ID for this connection")
  }
  url <- resolve_bound_resource(
    record$client@resource_bases[[resource_id]],
    path
  )
  if (!connection_record_status(record) %in% c("active", "limited")) {
    err_token("Connection is not usable")
  }
  validate_scopes(required_scopes)
  required_scopes <- normalize_scope_tokens(required_scopes)
  if (
    client_scope_coverage(
      record$client,
      required_scopes,
      effective_client_scopes(record$client)
    )$status !=
      "covered"
  ) {
    err_input(
      "Operation scopes must be included in the client's requested scopes"
    )
  }
  if (
    client_scope_coverage(
      record$client,
      required_scopes,
      record$token@granted_scopes
    )$status !=
      "covered"
  ) {
    err_token("Current grant does not cover this operation")
  }
  tryCatch({
    if (!is.null(configure)) {
      if (!is.function(configure)) err_input("configure must be a function")
      template <- httr2::request(url)
      request <- configure(template)
      if (!inherits(request, "httr2_request")) {
        err_input("configure must return an httr2 request")
      }
      unchanged <- request
      unchanged[c("body", "headers")] <- template[c("body", "headers")]
      if (!identical(unchanged, template) || any(tolower(names(request$headers)) %in%
          c("authorization", "dpop", "host", "proxy-authorization"))) {
        err_input("configure may only change the body and application headers")
      }
      url <- request
    }
    perform_resource_req(
      record$token,
      url,
      method = method,
      query = query,
      oauth_client = record$client,
      check_url = TRUE,
      follow_redirect = FALSE
    )
  },
    error = function(e) {
      # Transport conditions can contain a resource path, query or response body.
      # Do not expose those details through the connection's public error surface.
      err_http("Connection resource request failed")
    }
  )
}
