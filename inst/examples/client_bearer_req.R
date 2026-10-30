# Make request using OAuthToken object
# (code is not run because it requires a real token from user interaction)
if (interactive()) {
  # Inside reactive server code, after login has succeeded:
  token <- auth[["token"]]

  # Build and send in one step.
  response <- perform_resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Prepare a request before sending it.
  request <- resource_req(
    token,
    "https://api.example.com/resource",
    query = list(limit = 5)
  )

  # Sending the prepared request applies the same response-size limits.
  response <- perform_resource_req(token, request)

  # Or start from your own httr2 request and still let shinyOAuth perform it
  # so response limits and DPoP nonce retries remain available.
  custom_request <- httr2::request("https://api.example.com/resource") |>
    httr2::req_headers(Accept = "application/json") |>
    httr2::req_url_query(limit = 5)

  response <- perform_resource_req(token, custom_request)

  # resource_hosts restricts this dynamic URL to api.example.com.
  response <- perform_resource_req(
    token,
    input[["resource_url"]],
    resource_hosts = "api.example.com",
    follow_redirect = FALSE
  )
}
