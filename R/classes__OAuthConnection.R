#' OAuthConnection R6 class
#'
#' @description
#' Make API requests using a Shiny session's current OAuth credentials and the
#' client/API configuration supplied by an [OAuthClient]. For example, a hospital
#' connection selects that hospital's API address and reads the session's current
#' token for each request. Create it inside `server()` with [oauth_connection()]
#' or the `connection(id)` method of [oauth_connections_server()].
#' Use `$request()` to call an approved API, `$is_usable()`
#' to check local availability and `$summary()` for status without credentials.
#'
#' @details
#' The existing reactive token already updates on refresh; this object
#' combines that lookup with client selection, API-address restrictions and
#' session checks. With [oauth_connection()], the application supplies the
#' matching module's token source; the manager resolves its own stored records.
#' These are optional shinyOAuth conveniences, not SMART on FHIR protocol objects.
#'
#' Each operation resolves the current credentials, so refresh and logout are
#' reflected without replacing the reference. [oauth_module_server()] owns the
#' lifecycle of ordinary references; [oauth_connections_server()] owns managed
#' references and supplies `$refresh()`. Every reference expires when its Shiny
#' session closes. A manager can retain the underlying grant across redirects;
#' a new session obtains a new reference after verifying the local owner.
#'
#' Call `$is_usable()`, `$summary()` and `$request()` in the owning session's
#' reactive context. If the connection cannot be resolved, `$is_usable()` returns
#' `FALSE`; `$summary()` and `$request()` raise an error. The ID is read-only and
#' cloning is disabled. The class generator is internal; the public factories
#' establish the session binding required by applications.
#' Managed resource and status reads do not count as owner activity. Record user
#' actions with the manager's `touch()` method in an input event handler; automatic
#' reactive updates must not prolong an idle owner's session.
#'
#' @seealso [oauth_connection()], [OAuthClient], [perform_resource_req()]
#' @examples
#' \dontrun{
#' # Configure outside server(), using an existing provider:
#' client <- oauth_client(
#'   provider, client_id = "registered-app",
#'   redirect_uri = "https://app.example/callback", scopes = c("read", "write"),
#'   resource_bases = c(api = "https://api.example/v1"),
#'   required_scopes = "read"
#' )
#' server <- function(input, output, session) {
#'   auth <- oauth_module_server("auth", client)
#'   connection <- oauth_connection(client, shiny::reactive(auth$token))
#'   output$status <- shiny::renderText(connection$summary()$status)
#'   records <- shiny::reactive({
#'     shiny::req(connection$is_usable())
#'     response <- connection$request("api", "records", required_scopes = "read")
#'     httr2::resp_body_json(response)
#'   })
#' }
#' }
OAuthConnection <- R6::R6Class(
  "OAuthConnection",
  cloneable = FALSE,
  lock_class = TRUE,
  private = list(
    .id = NULL,
    .client = NULL,
    .fingerprint = NULL,
    .resolve = NULL,
    .refresh = NULL,
    record = function() {
      record <- tryCatch(private$.resolve(), error = function(...) {
        err_token("Connection is unavailable")
      })
      valid <- tryCatch(
        is.list(record) && identical(record$client, private$.client) &&
          identical(connection_client_fingerprint(record$client), private$.fingerprint) &&
          (is.null(record$token) || S7::S7_inherits(record$token, OAuthToken)),
        error = function(...) FALSE
      )
      if (!valid) {
        err_token("Connection is unavailable")
      }
      record
    }
  ),
  active = list(
    #' @field id Read-only opaque character string identifying this reference.
    #'   A manager uses the stored grant's ID across sessions and refreshes;
    #'   [oauth_connection()] generates an ID lasting only for that reference.
    #'   The ID is never an access token and does not authorize access by itself.
    id = function(value) {
      if (!missing(value)) {
        err_input("Connection IDs are read-only")
      }
      private$.id
    }
  ),
  public = list(
    #' @description
    #' Initialize a reference. This constructor is for internal use;
    #' applications should use [oauth_connection()] or the manager's
    #' `connection(id)` method to establish session ownership.
    #' Calling it again on an initialized reference is an error.
    #' @param id Opaque character string identifying the reference.
    #' @param client The [OAuthClient] to bind to this reference.
    #' @param resolve Internal function with no arguments that enforces session
    #'   ownership and returns a list with `client` identical to this reference's
    #'   client and `token` containing the current [OAuthToken] or `NULL`.
    #'   It must raise an error when the owning session is unavailable.
    #' @param refresh Optional internal function implementing a manager's
    #'   coordinated refresh. Legacy session references leave this `NULL`.
    #' @return A new `OAuthConnection` instance.
    initialize = function(id, client, resolve, refresh = NULL) {
      if (!is.null(private$.id)) {
        err_input("Connection references are read-only")
      }
      private$.id <- id
      private$.client <- client
      private$.fingerprint <- connection_client_fingerprint(client)
      private$.resolve <- resolve
      private$.refresh <- refresh
      invisible(self)
    },
    #' @description
    #' Check whether the current token is locally usable. This checks token
    #' presence, known unexpired lifetime and the client's required scopes.
    #' It does not refresh the token, contact the provider or guarantee remote
    #' authorization. Request-specific scopes are checked by `$request()`.
    #' @return A single logical value: `TRUE` for an `active` or `limited`
    #'   connection, otherwise `FALSE`, including when resolution fails.
    is_usable = function() {
      tryCatch(
        connection_record_status(private$record()) %in% c("active", "limited"),
        error = function(...) FALSE
      )
    },
    #' @description
    #' Refresh a connection created by [oauth_connections_server()] under the
    #' manager's exclusive store claim. The manager rechecks the owner and current
    #' record before installing replacement credentials. References created with
    #' [oauth_connection()] use their existing module's refresh lifecycle and
    #' cannot invoke this method.
    #' @param scopes Optional non-empty character vector requesting fewer
    #'   permissions for this connection, or `NULL` (default). Scopes must be
    #'   covered by the current grant and client configuration, and retain the
    #'   client's required scopes. SMART clients use semantic coverage.
    #' @details
    #' After explicit narrowing succeeds, subsequent refreshes (including
    #' automatic refreshes and refreshes in another retained Shiny session)
    #' request the accepted scope limit. Widening requires a new authorization.
    #' This is a local connection policy: OAuth refresh-token scope itself is
    #' not reduced by requesting a narrower access token. Existing connections
    #' that have never selected narrowing continue to omit request scope.
    #' Providers may reject requested scopes; there is no retry without them.
    #' @return `TRUE` after a successful commit, or a promise resolving to `TRUE`
    #'   when the manager uses async transport. Failure raises a redacted error.
    refresh = function(scopes = NULL) {
      private$record()
      if (!is.function(private$.refresh)) {
        err_config("This connection uses oauth_module_server() for refresh")
      }
      if (is.null(scopes)) private$.refresh() else private$.refresh(scopes = scopes)
    },
    #' @description
    #' Resolve the current connection and return status information without
    #' credentials, identity claims or token extension fields. Raises an error
    #' when called outside the owning session or after that session closes.
    #' @return A named list with the following entries:
    #'   * `connection_id`: the reference's character ID.
    #'   * `client_label`: the client's application-defined character label.
    #'   * `status`: one of the character values listed in this method's details.
    #'   * `expires_at`: numeric seconds since the Unix epoch, `NA_real_` when
    #'     there is no token or its expiry is unknown, or `Inf` for a
    #'     non-expiring token.
    #'   * `resource_ids`: character vector of the client's approved resource IDs.
    #' @details
    #' Managed lifecycle states take precedence: `refreshing` means a refresh
    #' claim is in progress, `uncertain` requires a new authorization after an
    #' ambiguous refresh outcome, `disconnected` means local access was removed,
    #' and `unavailable` means the stored credentials could not be restored.
    #' Otherwise token status is evaluated in this order:
    #' * `disconnected`: there is no current token.
    #' * `expiry_unknown`: the token's expiry is unknown.
    #' * `expired`: the token has reached its expiry time.
    #' * `insufficient_scope`: the grant lacks a client-required scope.
    #' * `limited`: required scopes are covered, but some other requested scopes
    #'   are absent from the grant.
    #' * `active`: all requested scopes are covered.
    #'
    #' Scope checks use the token's current `granted_scopes`, which may be
    #' assumed or carried forward when an ordinary OAuth provider omits scope
    #' information. SMART clients require explicit evidence and use semantic
    #' coverage for both connection and operation permissions.
    #' See [OAuthToken] for the distinction from verified scope evidence.
    summary = function() {
      connection_record_summary(private$record(), private$.id)
    },
    #' @description
    #' Resolve the current token and perform an authenticated request within a
    #' named resource base. The connection must be usable, and its current grant
    #' must cover any scopes required for this operation.
    #' @param resource_id Single character string naming an entry in the client's
    #'   `resource_bases`.
    #' @param path Single character string resolved relative to the selected base
    #'   directory; `""` selects the base itself. Absolute and root-relative URLs,
    #'   including pagination links, must remain within the same approved origin
    #'   and base path. Dot segments and ambiguous encodings are rejected.
    #' @param query Optional named list of query parameters, or `NULL`.
    #' @param method Single HTTP method string, defaulting to `"GET"`. `TRACE`
    #'   and `TRACK` are rejected by the resource transport.
    #' @param required_scopes Character vector of scopes required for this
    #'   operation, in addition to the client's required scopes. They must have
    #'   been requested by the client and be covered by the current grant.
    #'   `character()` adds no operation-specific scope check.
    #' @param configure Optional function taking an unauthenticated [httr2::request()]
    #'   and returning it with only body and application headers changed. Use
    #'   [httr2::req_body_json()], [httr2::req_body_form()], [httr2::req_body_raw()]
    #'   and [httr2::req_headers()]. Set the HTTP method with `method` above.
    #'   URL, transport policies, authentication and Host headers cannot be changed.
    #' @return An [httr2] response object. Invalid resources, unusable connections,
    #'   insufficient scopes and transport failures raise errors.
    #' @details
    #' Uses [perform_resource_req()] with the configured client for Bearer, DPoP
    #' and mTLS authentication. Redirects are never followed. Transport error
    #' messages are redacted to exclude resource paths, queries and response
    #' bodies. Scope requirements are supplied by the application; they cannot
    #' be inferred from an arbitrary API's HTTP method and path.
    request = function(
      resource_id,
      path = "",
      query = NULL,
      method = "GET",
      required_scopes = character(),
      configure = NULL
    ) {
      connection_record_request(
        private$record(),
        resource_id,
        path,
        query,
        method,
        required_scopes,
        configure
      )
    },
    #' @description
    #' Read interpreted context for a usable SMART connection in this session.
    #' @return The sensitive context list documented in [smart_context()].
    smart_context = function() smart_record_context(private$record()),
    #' @description
    #' Fetch the contextual Patient or validated fhirUser through the approved
    #' FHIR base, using current read permissions. Prefer [smart_patient()] and
    #' [smart_fhir_user()] in application code.
    #' @param kind Either `"patient"` or `"fhirUser"`.
    #' @return An [httr2] response. Missing context, scope or resource binding
    #'   raises an error before an authenticated request is sent.
    smart_resource = function(kind) {
      smart_record_resource(private$record(), kind)
    },
    #' @description
    #' Print the class name and session-binding description, with credentials
    #' redacted. This does not resolve the current token.
    #' @param ... Unused; accepted for compatibility with [base::print()].
    #' @return This reference, invisibly.
    print = function(...) {
      cat(
        "<OAuthConnection: session-bound reference; credentials redacted>\n"
      )
      invisible(self)
    }
  )
)
