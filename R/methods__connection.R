#' Reference a Shiny session's current token through an approved target
#'
#' Creates a server-side connection reference for one module's credentials.
#' Every request resolves the reactive token again, including after refresh or
#' logout, and selects its client's matching approved resource. The reference
#' expires with its Shiny session; it does not retain credentials across redirects.
#'
#' @param target Configuration created by [oauth_target()].
#' @param token A Shiny reactive expression returning the current [OAuthToken]
#'   or `NULL`, usually `shiny::reactive(auth$token)`. It must come from the
#'   module using `target$client`. Supplying that association is trusted server
#'   application wiring; a resource policy cannot prove an opaque token's audience.
#' @param session The owning Shiny session; defaults to the current session.
#' @return An [OAuthConnectionRef] with `$id`, `$is_usable()`, `$summary()` and
#'   `$request(resource_id, path = "", query = NULL, method = "GET",
#'   required_scopes = character())`. Requests return [httr2] responses.
#' @details
#' Create the reference once inside `server()`. Access it only in that session's
#' reactive context. `$summary()` excludes tokens, identity claims and extension
#' context. `$is_usable()` checks local presence, known expiry and required scopes;
#' it cannot guarantee remote authorization. Unknown token expiry is unusable.
#'
#' Paths are relative to the selected base directory. Absolute and root-relative
#' references (including pagination links) must stay within that same base.
#' Dot segments and ambiguous encodings are rejected; redirects are never followed.
#' Bearer, DPoP and mTLS use the existing transport and the target's client.
#'
#' Use request-level `required_scopes` for optional operations. They must be
#' included in the target's requested scopes and covered by the current grant.
#' The package cannot infer arbitrary API permissions from an HTTP method/path.
#' The legacy module continues to own refresh and logout. Retained connection
#' storage and its independent lifecycle will be supplied by the connection manager.
#'
#' @examples
#' \dontrun{
#' # Configure outside server():
#' target <- oauth_target(client, c(api = "https://api.example/v1"))
#' # Inside server():
#' auth <- oauth_module_server("auth", target$client)
#' connection <- oauth_connection(target, shiny::reactive(auth$token))
#' data <- shiny::reactive({
#'   shiny::req(connection$is_usable())
#'   connection$request("api", "records", required_scopes = "read")
#' })
#' }
#' @export
oauth_connection <- function(
  target,
  token,
  session = shiny::getDefaultReactiveDomain()
) {
  if (!inherits(target, "OAuthTarget")) {
    err_input("target must be an OAuthTarget")
  }
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
    list(target = target, token = binding$source())
  }
  OAuthConnectionRef$new(random_urlsafe(32), target, resolver)
}

connection_session_root <- function(session) {
  if (is.null(session) || !is.function(session$rootScope)) {
    return(NULL)
  }
  session$rootScope()
}

connection_record_status <- function(record) {
  token <- record$token
  if (is.null(token)) {
    return("disconnected")
  }
  expires <- token@expires_at
  if (is.na(expires)) {
    return("expiry_unknown")
  }
  if (expires <= as.numeric(Sys.time())) {
    return("expired")
  }
  if (
    evaluate_scope_coverage(
      record$target$required_scopes,
      token@granted_scopes
    )$status !=
      "covered"
  ) {
    return("insufficient_scope")
  }
  if (
    evaluate_scope_coverage(
      effective_client_scopes(record$target$client),
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
  required_scopes
) {
  if (
    !is_valid_string(resource_id) ||
      !resource_id %in% names(record$target$resource_bases)
  ) {
    err_input("Unknown resource ID for this connection")
  }
  url <- resolve_bound_resource(
    record$target$resource_bases[[resource_id]],
    path
  )
  if (!connection_record_status(record) %in% c("active", "limited")) {
    err_token("Connection is not usable")
  }
  validate_scopes(required_scopes)
  required_scopes <- normalize_scope_tokens(required_scopes)
  if (
    evaluate_scope_coverage(
      required_scopes,
      effective_client_scopes(record$target$client)
    )$status !=
      "covered"
  ) {
    err_input(
      "Operation scopes must be included in the target's requested scopes"
    )
  }
  if (
    evaluate_scope_coverage(
      required_scopes,
      record$token@granted_scopes
    )$status !=
      "covered"
  ) {
    err_token("Current grant does not cover this operation")
  }
  tryCatch(
    perform_resource_req(
      record$token,
      url,
      method = method,
      query = query,
      oauth_client = record$target$client,
      check_url = TRUE,
      follow_redirect = FALSE
    ),
    error = function(e) {
      # Transport conditions can contain a resource path, query or response body.
      # Do not expose those details through the connection's public error surface.
      err_http("Connection resource request failed")
    }
  )
}
