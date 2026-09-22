#' OAuthConnection R6 class
#'
#' @description
#' Make API requests using a Shiny session's current OAuth credentials and the
#' client/API configuration supplied by an [OAuthClient]. For example, a hospital
#' connection selects that hospital's API address and reads the session's current
#' token for each request. Obtain it inside `server()` with `auth$connection()`
#' from [oauth_module_server()], or `auth$connection(id)` from
#' [oauth_connections_server()]. Use `$access_token()` for external SDKs,
#' `$request()` for an approved API and `$summary()` for status without credentials.
#'
#' @details
#' The existing reactive token already updates on refresh; this object
#' combines that lookup with client selection, API-address restrictions and
#' session checks. With [oauth_connection()], the application supplies the
#' matching module's token source; the manager resolves its own stored records.
#' These are optional shinyOAuth conveniences, not SMART on FHIR protocol objects.
#'
#' Module factories pin each reference to one authorization. Refresh preserves
#' it; logout or replacement invalidates it permanently. Both factories supply
#' coordinated `$access_token()` and `$refresh()` methods. Every reference expires
#' when its Shiny
#' session closes. A manager can retain the underlying grant across redirects;
#' a new session obtains a new reference after verifying the local owner.
#' The older [oauth_connection()] wrapper follows its supplied token reactive
#' across logins and does not provide coordinated token acquisition or refresh.
#'
#' Factory, `$access_token()` and `$has_scopes()` dependencies reflect
#' authorization/permission changes without invalidating consumers on unchanged
#' token rotations. Explicit status reads may update on each refresh. A connection
#' for an external SDK need not declare `resource_bases`; `$request()` still
#' requires a declared destination. See `vignette("external-integrations")`.
#'
#' Call `[["is_usable"]]()`, `[["summary"]]()` and `[["request"]]()` in the owning session's
#' reactive context. If the connection cannot be resolved, `[["is_usable"]]()` returns
#' `FALSE`; `[["summary"]]()` and `[["request"]]()` raise an error. The ID is read-only and
#' cloning is disabled.
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
#'   auth <- oauth_module_server("auth", client, refresh_proactively = TRUE)
#'   output[["status"]] <- shiny::renderText({
#'     connection <- shiny::req(auth[["connection"]]())
#'     connection[["summary"]]()[["status"]]
#'   })
#'   records <- shiny::reactive({
#'     connection <- shiny::req(auth[["connection"]]())
#'     response <- httr2::request("https://api.example/v1/records") |>
#'       httr2::req_auth_bearer_token(connection[["access_token"]]("read")) |>
#'       httr2::req_perform()
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
    .acquire = NULL,
    .integration_changed = NULL,
    integration_record = function(target = NULL) {
      if (is.function(private[[".integration_changed"]])) {
        private[[".integration_changed"]]()
      }
      token_target_select(shiny::isolate(private[["record"]]()), target)
    },
    record = function() {
      record <- tryCatch(private[[".resolve"]](), error = function(error) {
        if (inherits(error, "shinyOAuth_access_error")) {
          stop(error)
        }
        err_token("Connection is unavailable")
      })
      valid <- tryCatch(
        is.list(record) &&
          identical(record[["client"]], private[[".client"]]) &&
          identical(
            connection_client_fingerprint(record[["client"]]),
            private[[".fingerprint"]]
          ) &&
          (is.null(record[["token"]]) ||
            S7::S7_inherits(record[["token"]], OAuthToken)),
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
    #'   A single module preserves it across refresh and replaces it on login.
    #'   A manager uses the stored grant's ID across sessions and refreshes;
    #'   [oauth_connection()] generates an ID lasting only for that reference.
    #'   The ID is never an access token and does not authorize access by itself.
    id = function(value) {
      if (!missing(value)) {
        err_input("Connection IDs are read-only")
      }
      private[[".id"]]
    }
  ),
  public = list(
    #' @description
    #' Initialize a reference. This constructor is for internal use;
    #' applications should use a module's `connection()` method or the legacy
    #' [oauth_connection()] wrapper to establish session ownership.
    #' @param id Opaque character string identifying the reference.
    #' @param client The [OAuthClient] to bind to this reference.
    #' @param resolve Internal function with no arguments that enforces session
    #'   ownership and returns a list with `client` identical to this reference's
    #'   client and `token` containing the current [OAuthToken] or `NULL`.
    #'   It must raise an error when the owning session is unavailable.
    #' @param refresh Optional internal function implementing the owner's
    #'   coordinated refresh. Legacy wrappers leave this `NULL`.
    #' @return A new `OAuthConnection` instance.
    #' @param acquire Internal coordinated credential refresh for external use,
    #'   accepting `async` and returning TRUE or a promise resolving to TRUE.
    initialize = function(id, client, resolve, refresh = NULL, acquire = NULL) {
      if (!is.null(private[[".id"]])) {
        err_input("Connection references are read-only")
      }
      private[[".id"]] <- id
      private[[".client"]] <- client
      private[[".fingerprint"]] <- connection_client_fingerprint(client)
      private[[".resolve"]] <- resolve
      private[[".refresh"]] <- refresh
      private[[".acquire"]] <- acquire
      if (!is.null(shiny::getDefaultReactiveDomain())) {
        private[[".integration_changed"]] <- connection_integration_signal(
          function() private[["record"]]()
        )
      }
      invisible(self)
    },
    #' @description
    #' Retrieve a bearer-token string for an external SDK or database driver.
    #' Credentials are checked at use time and refreshed once when necessary.
    #' Requires a reference from a module's `connection()` method. The method
    #' never starts login, widens permissions, or retries an application request.
    #' Keep the returned secret on the server and out of logs.
    #' @param required_scopes Operation scopes, in addition to client requirements.
    #'   These check permissions; they do not narrow the grant or add consent.
    #' @param min_valid_for Minimum remaining token lifetime in seconds, including
    #'   the caller's allowance for clock skew and operation duration. Unknown
    #'   expiry requires refresh; an insufficient replacement fails without a loop.
    #' @param force_refresh Bypass the cached token and require acquisition.
    #'   Existing refresh coordination and retry delays still apply.
    #' @param async Return a promise, including for a cached token. Authentication
    #'   failures reject the promise. FALSE always returns a string or errors;
    #'   it never waits on an in-flight asynchronous refresh.
    #' @param target Optional declared token-target name. `NULL` uses the client's
    #'   default. A missing cached target is acquired with the shared refresh
    #'   credential; scope checks use that target's evidence and retained limit.
    #' @return A bearer-token string, or a promise resolving to one. Acquisition
    #'   failures inherit `shinyOAuth_access_error` and expose a stable reason in
    #'   `condition$context$reason`. Argument/configuration errors can be synchronous.
    #'   Sender-constrained tokens must use their transport instead of this method.
    #' @details
    #' Reasons are `authorization_unavailable` (ended or foreign session/reference),
    #' `insufficient_scope`, `refresh_pending` (a synchronous caller cannot join
    #' async work), `refresh_unavailable` (including retry pacing),
    #' `interaction_required` (no usable refresh credential), `lifetime_unavailable`,
    #' `unsupported_token_binding`, `unknown_target` and `unsupported_target`.
    #' No reason initiates browser navigation.
    #' A cached async result is still a promise. Pending async callers join the
    #' same owned refresh and recheck the committed result before returning it.
    #' Acquisition does not count as managed owner activity.
    #' Microsoft tokens can contain previously consented permissions beyond the
    #' configured operation scopes. This method returns the actual bearer token;
    #' it cannot reduce those permissions for an SDK. Connection permission checks
    #' still enforce the configured and retained local limits.
    access_token = function(
      required_scopes = character(),
      min_valid_for = 60,
      force_refresh = FALSE,
      async = FALSE,
      target = NULL
    ) {
      target <- token_target_name(private[[".client"]], target)
      acquire <- private[[".acquire"]]
      if (!is.null(target) && is.function(acquire)) {
        acquire <- function(async, wait_only = FALSE) {
          private[[".acquire"]](
            async = async,
            target = target,
            wait_only = wait_only
          )
        }
      }
      connection_export_token(
        function() private[["integration_record"]](target),
        acquire,
        required_scopes,
        min_valid_for,
        force_refresh,
        async
      )
    },
    #' @description
    #' Check recorded operation permissions without refreshing or requiring an
    #' unexpired access token. This is suitable for optional-feature UI; the
    #' actual operation must still check scopes and remote resource permissions.
    #' @param scopes Character vector of operation scopes to check.
    #' @param target Optional declared token-target name; defaults to the client's
    #'   primary target. An unacquired target returns FALSE, without acquisition.
    #' @return TRUE when the current authorization covers the configured scopes,
    #'   otherwise FALSE. Malformed arguments raise input errors.
    has_scopes = function(scopes, target = NULL) {
      target <- token_target_name(private[[".client"]], target)
      scopes <- connection_scope_arguments(scopes)
      tryCatch(
        {
          record <- private[["integration_record"]](target)
          previous <- if (is.function(private[[".integration_changed"]])) {
            private[[".integration_changed"]]()
          } else {
            NULL
          }
          if (!is.null(target)) {
            previous <- previous[["targets"]][[target]]
          }
          connection_record_has_scopes(record, scopes, previous)
        },
        error = function(...) FALSE
      )
    },
    #' @description
    #' Check whether the current token is locally usable. This checks token
    #' presence, known unexpired lifetime and the client's required scopes.
    #' It does not refresh the token, contact the provider or guarantee remote
    #' authorization. Request-specific scopes are checked by `[["request"]]()`.
    #' @return A single logical value: `TRUE` for an `active` or `limited`
    #'   connection, otherwise `FALSE`, including when resolution fails.
    is_usable = function() {
      tryCatch(
        connection_record_status(token_target_select(private[[
          "record"
        ]]())) %in%
          c("active", "limited"),
        error = function(...) FALSE
      )
    },
    #' @description
    #' Refresh a connection obtained from either module's `connection()` method.
    #' Its owner coordinates refresh and verifies ownership before updating it.
    #' References created with [oauth_connection()] use their existing module's
    #' refresh lifecycle and cannot invoke this method.
    #' @param scopes Optional non-empty character vector requesting fewer
    #'   permissions for this connection, or `NULL` (default). Scopes must be
    #'   covered by the current grant and client configuration, and retain the
    #'   client's required scopes. SMART clients use semantic coverage.
    #' @param target Optional declared token-target name. With targets, narrowing
    #'   applies only to the selected entry and persists across target switching
    #'   and reauthorization. Other targets keep their own retained scope limits.
    #' @details
    #' After explicit narrowing succeeds, subsequent refreshes (including
    #' automatic refreshes and refreshes in another retained Shiny session)
    #' request the accepted scope limit. Widening requires a new authorization.
    #' This is a local connection policy: OAuth refresh-token scope itself is
    #' not reduced by requesting a narrower access token. Ordinary OAuth
    #' connections explicitly request their retained granted scopes when known,
    #' including when no explicit narrowing was selected. SMART omits request
    #' scope while its permissions equal the original launch grant.
    #' Providers may reject requested scopes; there is no retry without them.
    #' Microsoft target API scopes cannot be explicitly narrowed: Entra may
    #' return all previously consented resource permissions. Such requests fail
    #' before HTTP with access-error reason `unsupported_scope_narrowing`, leaving
    #' the current authorization usable. Use a separate registration or change
    #' provider consent when a token with fewer API permissions is required.
    #' OIDC clients that require UserInfo must retain `openid`; narrowing that
    #' removes it is rejected before exchange. Include any additional scopes
    #' needed by the provider's profile endpoint in the client's `required_scopes`.
    #' @return `TRUE` after a successful commit, or a promise resolving to `TRUE`
    #'   when the module uses async transport. Failure raises a redacted error.
    refresh = function(scopes = NULL, target = NULL) {
      target <- token_target_name(private[[".client"]], target)
      private[["record"]]()
      if (!is.function(private[[".refresh"]])) {
        err_config("This connection uses oauth_module_server() for refresh")
      }
      if (!is.null(target)) {
        return(private[[".refresh"]](scopes = scopes, target = target))
      }
      if (is.null(scopes)) {
        private[[".refresh"]]()
      } else {
        private[[".refresh"]](scopes = scopes)
      }
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
    #'   * `replaces_connection_id`: present on managed replacement authorizations;
    #'     identifies the locally ended connection passed to `reauthorize()`.
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
    #' Scope checks enforce retained target limits and use the token's current
    #' `granted_scopes`, which may be
    #' assumed or carried forward when an ordinary OAuth provider omits scope
    #' information. SMART clients require explicit evidence and use semantic
    #' coverage for both connection and operation permissions.
    #' See [OAuthToken] for the distinction from verified scope evidence.
    summary = function() {
      connection_record_summary(
        token_target_select(private[["record"]]()),
        private[[".id"]]
      )
    },
    #' @description
    #' Read explicitly selected fields from the authorization's cryptographically
    #' validated OIDC identity.
    #' This method never returns raw tokens or fetches profile data.
    #' @param claims Character vector of ID-token claim names, defaulting to
    #'   `c("iss", "sub")`. Use `character()` to select none.
    #' @param userinfo Character vector of previously fetched UserInfo field
    #'   names, defaulting to none. UserInfo must have a `sub` exactly matching
    #'   the validated ID token before any requested profile fields are returned.
    #' @return A list with `id_token_claims` and `userinfo`, each containing only
    #'   selected fields that exist. Missing fields are omitted.
    #' @details
    #' Call inside the owning session's reactive context. The result contains
    #' sensitive identity data: select only what the application needs and keep
    #' it out of logs and generic status displays. `[["summary"]]()` and printing
    #' continue to omit identity. Ordinary OAuth connections without validated
    #' OIDC identity cannot use this accessor.
    #'
    #' Ordinary connections require a usable access token with `openid` currently
    #' granted. Target connections retain their validated identity while the
    #' authorization remains available in the owning session, even when the
    #' primary access token expires or its current scopes no longer include
    #' `openid`. Identity availability does not establish permission to call an
    #' API; use `$has_scopes()` and `$access_token()` or `$request()` to check the
    #' selected target's current permissions and token lifetime.
    #'
    #' These are the last validated identity/profile snapshots; an OAuth refresh
    #' can retain earlier ID-token claims and does not establish fresh user
    #' authentication. This accessor does not log the user into your application
    #' or establish an account-retention owner. It does not count as owner activity.
    identity = function(claims = c("iss", "sub"), userinfo = character()) {
      record <- private[["record"]]()
      token <- record[["token"]]
      available <- if (token_targets_configured(record[["client"]])) {
        identical(record[["status"]], "active") && !is.null(token)
      } else {
        connection_record_status(record) %in% c("active", "limited")
      }
      if (
        !available ||
          !provider_uses_oidc(record[["client"]]@provider) ||
          !isTRUE(token@id_token_validated) ||
          (!token_targets_configured(record[["client"]]) &&
            !"openid" %in% token@granted_scopes)
      ) {
        err_token("Connection has no usable validated OIDC identity")
      }
      for (fields in list(claims, userinfo)) {
        if (
          !is.character(fields) ||
            anyNA(fields) ||
            !all(nzchar(fields)) ||
            anyDuplicated(fields)
        ) {
          err_input(
            "Identity field selections must be distinct non-empty names"
          )
        }
      }
      verified <- token@id_token_claims
      if (
        !is_valid_string(verified[["iss"]]) ||
          !is_valid_string(verified[["sub"]])
      ) {
        err_token("Connection has no usable validated OIDC identity")
      }
      profile <- token@userinfo
      if (
        length(userinfo) &&
          length(profile) &&
          !identical(profile[["sub"]], verified[["sub"]])
      ) {
        err_token("UserInfo is not bound to the validated OIDC identity")
      }
      select <- function(values, fields) {
        fields <- intersect(fields, names(values))
        if (!length(fields)) list() else values[fields]
      }
      list(
        id_token_claims = select(verified, claims),
        userinfo = select(profile, userinfo)
      )
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
    #' @param refresh Opt in to coordinated token acquisition before sending the
    #'   request. Default FALSE preserves existing behavior. This synchronous
    #'   operation never waits on async refresh and never refreshes/replays after
    #'   an API failure. Generic HTTP retries are disabled for this opt-in call;
    #'   bound transport and DPoP nonce-challenge handling remain in force.
    #' @param target Optional declared token-target name. Target clients require
    #'   an explicit association through that declaration's `resource_ids`.
    #' @param min_valid_for Minimum remaining lifetime when `refresh = TRUE`,
    #'   in seconds. Has the same meaning as on `$access_token()`.
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
      configure = NULL,
      refresh = FALSE,
      target = NULL,
      min_valid_for = 60
    ) {
      connection_manager_flag(refresh, "refresh")
      target <- token_target_name(private[[".client"]], target)
      token_target_check_destination(private[[".client"]], target, resource_id)
      record <- token_target_select(private[["record"]](), target)
      if (refresh) {
        acquire <- private[[".acquire"]]
        if (!is.null(target) && is.function(acquire)) {
          acquire <- function(async, wait_only = FALSE) {
            private[[".acquire"]](
              async = async,
              target = target,
              wait_only = wait_only
            )
          }
        }
        record <- connection_export_token(
          function() private[["integration_record"]](target),
          acquire,
          required_scopes,
          min_valid_for,
          FALSE,
          FALSE,
          export_bearer = FALSE
        )
      }
      record[["single_attempt"]] <- refresh
      connection_record_request(
        record,
        resource_id,
        path,
        query,
        method,
        required_scopes,
        configure
      )
    },
    #' @description
    #' `r lifecycle::badge("experimental")`
    #'
    #' Read interpreted context for a usable SMART connection in this session.
    #' @return The sensitive context list documented in [smart_context()].
    smart_context = function() smart_record_context(private[["record"]]()),
    #' @description Inspect declared targets without exposing credentials.
    #' @return A named list of target status and granted scopes. A target with no
    #'   response yet has status `not_acquired`; this is not proof of denied consent.
    targets = function() {
      record <- private[["record"]]()
      lapply(
        stats::setNames(
          names(private[[".client"]]@token_targets),
          names(private[[".client"]]@token_targets)
        ),
        function(target) {
          selected <- token_target_select(record, target)
          token <- selected[["token"]]
          list(
            status = if (
              is.null(token) && identical(selected[["status"]], "active")
            ) {
              "not_acquired"
            } else {
              connection_record_status(selected)
            },
            granted_scopes = if (is.null(token)) {
              character()
            } else {
              token@granted_scopes
            },
            scopes_verified = !is.null(token) &&
              isTRUE(token@granted_scopes_verified)
          )
        }
      )
    },
    #' @description
    #' `r lifecycle::badge("experimental")`
    #'
    #' Fetch the contextual Patient or validated fhirUser through the approved
    #' FHIR base, using current read permissions. Prefer [smart_patient()] and
    #' [smart_fhir_user()] in application code.
    #' @param kind Either `"patient"` or `"fhirUser"`.
    #' @return An [httr2] response. Missing context, scope or resource binding
    #'   raises an error before an authenticated request is sent.
    smart_resource = function(kind) {
      smart_record_resource(private[["record"]](), kind)
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
