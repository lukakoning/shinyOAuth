# Compose test fixtures using the same validated optional OAuthClient properties.
connection_test_client <- function(client = make_test_client(), resource_bases,
    required_scopes = character(), label = client@provider@name) {
  S7::props(client) <- list(resource_bases = normalize_resource_bases(resource_bases),
    required_scopes = normalize_scope_tokens(required_scopes), label = label)
  client
}
