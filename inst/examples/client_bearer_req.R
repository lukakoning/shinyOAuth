# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
\dontrun{
# Get an OAuthToken
# (typically provided as reactive return value by `oauth_module_server()`)
token <- OAuthToken()

# Build request
request <- client_bearer_req(
  token, 
  "https://api.example.com/resource", 
  query = list(limit = 5)
)

# Perform request
response <- httr2::req_perform(request)
}
