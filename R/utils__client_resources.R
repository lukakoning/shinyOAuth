# Optional application policy belongs to the existing OAuthClient value object.
# No user's credentials or cached configuration digest lives on that object.
default_client_label <- function(provider) {
  # Provider names historically accepted any character vector. Optional display
  # metadata must not add a prerequisite to ordinary OAuth client construction.
  if (!is_valid_string(provider@name)) return("OAuth provider")
  label <- substr(enc2utf8(gsub("[[:cntrl:]]", " ", provider@name)), 1L, 128L)
  while (nchar(label, type = "bytes") > 128L) {
    label <- substr(label, 1L, nchar(label) - 1L)
  }
  label
}

validate_client_resources <- function(client) {
  tryCatch({
    if (length(client@resource_bases)) normalize_resource_bases(client@resource_bases)
    validate_scopes(client@required_scopes)
    if (length(client@required_scopes) &&
        !identical(client_scope_coverage(client, client@required_scopes,
          effective_client_scopes(client, warn = FALSE))$status, "covered")) {
      return("OAuthClient: Required scopes must be included in the client's requested scopes")
    }
    if (!is_valid_string(client@label) || nchar(client@label, type = "bytes") > 128L ||
        grepl("[[:cntrl:]]", client@label)) {
      return("OAuthClient: label must be a non-empty string of at most 128 bytes")
    }
    NULL
  }, error = function(e) paste0("OAuthClient: ", conditionMessage(e)))
}
