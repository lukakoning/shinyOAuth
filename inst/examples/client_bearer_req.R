# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
if (interactive()) {
  # Get an OAuthToken
  # (typically provided as reactive return value by `oauth_module_server()`)
  token <- OAuthToken()

  # Recommended for most callers: build + perform in one step.
  response <- perform_resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Advanced callers can still build first and perform later.
  request <- resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  response <- httr2::req_perform(request)
}
