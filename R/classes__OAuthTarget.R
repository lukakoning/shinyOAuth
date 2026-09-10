# Configuration is immutable through the public interface. S7 client/provider
# copies preserve configuration without serializing caches or private keys.
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
    client = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.client
    },
    resource_bases = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.bases
    },
    required_scopes = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.required
    },
    label = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.label
    },
    fingerprint = function(value) {
      if (!missing(value)) {
        err_config("OAuthTarget configuration is read-only")
      }
      private$.fingerprint
    }
  ),
  public = list(
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
#' @return An `OAuthTarget` with read-only `$client`, `$resource_bases`,
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
