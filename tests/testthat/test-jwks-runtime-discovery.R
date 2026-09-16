runtime_discovery_fixture <- function(issuer) {
  key <- openssl::rsa_keygen(2048)
  jwk <- jsonlite::fromJSON(
    write_test_jwk(key[["pubkey"]]),
    simplifyVector = FALSE
  )
  jwk[["kid"]] <- "runtime-discovery"
  client <- make_test_client(use_nonce = FALSE)
  client@provider@issuer <- issuer
  client@provider@userinfo_url <- "https://example.com/userinfo"
  client@provider@jwks_host_issuer_match <- FALSE
  jwt <- jose::jwt_encode_sig(
    jose::jwt_claim(iss = issuer, sub = "subject", aud = client@client_id),
    key,
    header = list(kid = jwk[["kid"]])
  )
  list(client = client, jwt = jwt, jwks = list(keys = list(jwk)))
}

test_that("runtime metadata retrieval obeys tightened host and scheme policy", {
  for (issuer in c("https://retired.example", "http://retired.example")) {
    local_options(
      shinyOAuth.allowed_hosts = NULL,
      shinyOAuth.allowed_non_https_hosts = c(
        "retired.example",
        "localhost",
        "127.0.0.1"
      )
    )
    fixture <- runtime_discovery_fixture(issuer)
    client <- fixture[["client"]]
    explicit_client <- client
    explicit_client@provider@jwks_uri <- "https://example.com/jwks"
    requests <- character()
    local_mocked_bindings(req_with_retry = function(req, ...) {
      url <- req[["url"]]
      requests <<- c(requests, url)
      body <- if (url == client@provider@userinfo_url) {
        fixture[["jwt"]]
      } else {
        as.character(jsonlite::toJSON(
          if (url == "https://example.com/jwks") {
            fixture[["jwks"]]
          } else {
            list(issuer = issuer, jwks_uri = "https://example.com/jwks")
          },
          auto_unbox = TRUE
        ))
      }
      httr2::response(
        url = url,
        status_code = 200L,
        headers = list(
          `content-type` = if (url == client@provider@userinfo_url) {
            "application/jwt"
          } else {
            "application/json"
          }
        ),
        body = charToRaw(body)
      )
    })
    if (startsWith(issuer, "https:")) {
      options(shinyOAuth.allowed_hosts = "example.com")
    } else {
      options(shinyOAuth.allowed_non_https_hosts = character())
    }
    expect_error(get_userinfo(client, "synthetic-access"))
    expect_identical(requests, client@provider@userinfo_url)

    # An explicit JWKS URI need not contact the issuer identifier.
    expect_identical(
      get_userinfo(explicit_client, "synthetic-access")[["sub"]],
      "subject"
    )
    expect_false(any(startsWith(requests, issuer)))
  }
})

test_that("runtime JWKS discovery preserves issuer path bytes", {
  for (path in c(
    "/tenants//one",
    "/tenants/%2fone",
    "/tenant",
    "/tenant/",
    "/tenant//"
  )) {
    issuer <- paste0("https://issuer.example", path)
    fixture <- runtime_discovery_fixture(issuer)
    client <- fixture[["client"]]
    requests <- character()
    trimmed <- sub("/$", "", path)
    metadata_url <- paste0(
      "https://issuer.example",
      trimmed,
      "/.well-known/openid-configuration"
    )
    local_mocked_bindings(req_with_retry = function(req, ...) {
      url <- req[["url"]]
      requests <<- c(requests, url)
      is_userinfo <- identical(url, client@provider@userinfo_url)
      is_jwks <- identical(url, "https://example.com/jwks")
      body <- if (is_userinfo) {
        fixture[["jwt"]]
      } else {
        as.character(jsonlite::toJSON(
          if (is_jwks) {
            fixture[["jwks"]]
          } else {
            list(issuer = issuer, jwks_uri = "https://example.com/jwks")
          },
          auto_unbox = TRUE
        ))
      }
      httr2::response(
        url = url,
        status_code = if (is_userinfo || is_jwks || url == metadata_url) {
          200L
        } else {
          404L
        },
        headers = list(
          `content-type` = if (is_userinfo) {
            "application/jwt"
          } else {
            "application/json"
          }
        ),
        body = charToRaw(body)
      )
    })
    expect_identical(
      get_userinfo(client, "synthetic-access")[["sub"]],
      "subject"
    )
    expect_identical(
      requests,
      c(
        client@provider@userinfo_url,
        paste0(
          "https://issuer.example/.well-known/oauth-authorization-server",
          trimmed
        ),
        paste0(
          "https://issuer.example/.well-known/openid-configuration",
          trimmed
        ),
        metadata_url,
        "https://example.com/jwks"
      )
    )
    expect_identical(.discover_build_request(issuer)[["url"]], metadata_url)
  }
})
