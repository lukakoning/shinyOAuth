#' OAuthTarget R6 class
#'
#' @description
#' An `OAuthTarget` binds an [OAuthClient] to named, approved resource bases and
#' the scopes required for a usable connection. Create it with [oauth_target()]
#' outside the Shiny `server()` function, then pass it to [oauth_connection()].
#'
#' @details
#' Read configuration with `$`, for example `target$resource_bases`. All active
#' bindings are read-only, and cloning is disabled. Create a new target to change
#' its configuration. The class generator is internal; [oauth_target()] is the
#' application constructor and supplies defaults and resource URL documentation.
#'
#' Resource bases constrain requests to an exact scheme, hostname, effective
#' port and base path. This is local request policy, not evidence of a token's
#' audience. Scope comparison uses literal OAuth scope tokens; a target does not
#' enable SMART launch or scope semantics. Printing shows only the number of
#' approved resources, while `$client` exposes the original client configuration,
#' including any credentials and shared caches.
#'
#' @seealso [oauth_target()], [OAuthConnectionRef], [oauth_connection()]
#' @examples
#' provider <- oauth_provider(
#'   name = "Example",
#'   auth_url = "https://auth.example/authorize",
#'   token_url = "https://auth.example/token",
#'   token_auth_style = "public"
#' )
#' client <- oauth_client(
#'   provider,
#'   client_id = "example-app",
#'   redirect_uri = "https://app.example/callback",
#'   scopes = c("read", "write")
#' )
#' target <- oauth_target(
#'   client,
#'   resource_bases = c(api = "https://api.example/v1"),
#'   required_scopes = "read"
#' )
#' target$resource_bases
#' target$required_scopes
#' print(target)
OAuthTarget <- R6::R6Class(
  "OAuthTarget",
  cloneable = FALSE,
  lock_class = TRUE,
  private = list(
    .client = NULL,
    .bases = NULL,
    .required = NULL,
    .label = NULL,
    .fingerprint = NULL
  ),
  active = list(
    #' @field client Read-only [OAuthClient] configuration supplied at creation.
    #'   Use this client for the Shiny module that supplies a connection's token.
    client = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.client
    },
    #' @field resource_bases Read-only named character vector of normalized,
    #'   approved base URLs. Names are the resource IDs accepted by a connection's
    #'   `$request()` method.
    resource_bases = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.bases
    },
    #' @field required_scopes Read-only character vector of normalized scope
    #'   tokens required for every usable connection. These are a subset of the
    #'   client's requested scopes; `character()` imposes no required scopes.
    required_scopes = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.required
    },
    #' @field label Read-only application-defined display label, returned by a
    #'   connection's `$summary()`. It is a non-empty string of at most 128 bytes
    #'   without control characters.
    label = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.label
    },
    #' @field fingerprint Read-only character string containing an opaque digest
    #'   of the client, provider, scope and resource policy. The display label is
    #'   excluded. This identifies configuration, not a user or an access token.
    fingerprint = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.fingerprint
    }
  ),
  public = list(
    #' @description
    #' Initialize a target. Applications should use [oauth_target()] to create
    #' instances. Calling this method again on an initialized target is an error.
    #' @param client An [OAuthClient] configured outside `server()`.
    #' @param resource_bases Named character vector of approved absolute base
    #'   URLs. See [oauth_target()] for resource ID and URL validation rules.
    #' @param required_scopes Character vector of requested scopes that every
    #'   usable connection needs. Use `character()` for no required scopes.
    #' @param label Non-empty display label of at most 128 bytes without control
    #'   characters.
    #' @return A new `OAuthTarget` instance.
    initialize = function(client, resource_bases, required_scopes, label) {
      if (!is.null(private$.client)) {
        err_config("OAuthTarget configuration is read-only")
      }
      S7::check_is_S7(client, OAuthClient)
      validate_scopes(required_scopes)
      required_scopes <- normalize_scope_tokens(required_scopes)
      if (
        evaluate_scope_coverage(
          required_scopes,
          effective_client_scopes(client)
        )$status !=
          "covered"
      ) {
        err_config(
          "Required scopes must be included in the client's requested scopes"
        )
      }
      if (
        !is_valid_string(label) ||
          nchar(label, type = "bytes") > 128L ||
          grepl("[[:cntrl:]]", label)
      ) {
        err_config(
          "Target label must be a non-empty string of at most 128 bytes"
        )
      }
      private$.client <- client
      private$.bases <- normalize_resource_bases(resource_bases)
      private$.required <- required_scopes
      private$.label <- label
      private$.fingerprint <- state_policy_digest(list(
        version = 1L,
        profile = list(id = "oauth", version = 1L),
        client_id = client@client_id,
        redirect_uri = client@redirect_uri,
        provider = provider_fingerprint(client@provider),
        client_policy = state_client_policy_fingerprint(client),
        scopes = normalize_scope_tokens(effective_client_scopes(client)),
        resource_bases = as.list(private$.bases[sort(names(private$.bases))]),
        required_scopes = required_scopes
      ))
      invisible(self)
    },
    #' @description
    #' Print the class name and number of approved resources, with configuration
    #' and credentials redacted.
    #' @param ... Unused; accepted for compatibility with [base::print()].
    #' @return This target, invisibly.
    print = function(...) {
      cat(
        "<OAuthTarget: ",
        length(private$.bases),
        " approved resource(s); credentials redacted>\n",
        sep = ""
      )
      invisible(self)
    }
  )
)

#' Bind an OAuth client to approved resource bases
#'
#' Creates immutable configuration for connection-bound requests. Resource IDs
#' select exact scheme, hostname, effective port and base-path boundaries.
#' Configuration is local policy; it does not prove an opaque token's audience
#' or add OAuth `resource` parameters. Configure those on [oauth_client()].
#'
#' @param client An existing [OAuthClient], configured outside `server()`.
#' @param resource_bases Named character vector of approved absolute base URLs.
#'   IDs start with a letter and contain letters, digits, `_` or `-` (64 bytes
#'   maximum). HTTPS is required except for loopback development URLs.
#' @param required_scopes Requested scopes that every usable connection needs.
#'   Other requested scopes may be absent from a limited grant. Generic targets
#'   use literal OAuth comparison and do not infer SMART semantics.
#' @param label Short application-defined display label; defaults to provider name.
#' @return An [OAuthTarget] with read-only `$client`, `$resource_bases`,
#'   `$required_scopes`, `$label` and `$fingerprint` properties. Printing redacts
#'   configuration. Supply it to [oauth_connection()] for per-session requests.
#' @details
#' Base URLs exclude user information, query strings and fragments. Dot segments,
#' repeated slashes, semicolon path parameters and encoded ASCII reserved/control
#' characters are rejected. An encoded unreserved character is normalized before
#' comparing paths. Existing generic request helpers keep their own URL policy.
#'
#' Ordinary OAuth/OIDC targets retain their client's scopes and validation rules.
#' Constructing a target does not enable SMART launch, discovery or persistence.
#' @export
oauth_target <- function(
  client,
  resource_bases,
  required_scopes = character(),
  label = client@provider@name
) {
  OAuthTarget$new(client, resource_bases, required_scopes, label)
}
