make_mtls_registration_client <- function(
  token_auth_style,
  mtls_client_certificate_bound_access_tokens = FALSE,
  mtls_certificate_bound_access_tokens = FALSE
) {
  provider <- oauth_provider(
    name = "example",
    auth_url = "https://example.com/auth",
    token_url = "https://example.com/token",
    use_nonce = FALSE,
    use_pkce = TRUE,
    id_token_required = FALSE,
    id_token_validation = FALSE,
    token_auth_style = token_auth_style,
    mtls_client_certificate_bound_access_tokens = mtls_client_certificate_bound_access_tokens
  )

  oauth_client(
    provider = provider,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100/callback",
    scopes = character(0),
    mtls_client_cert_file = mtls_pem_fixture("client-cert.pem"),
    mtls_client_key_file = mtls_pem_fixture("client-key.pem"),
    mtls_client_ca_file = mtls_pem_fixture("ca-cert.pem"),
    mtls_certificate_bound_access_tokens = mtls_certificate_bound_access_tokens
  )
}

test_that("oauth_client_mtls_registration derives subject DN metadata", {
  client <- make_mtls_registration_client("tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)

  expect_identical(metadata$token_endpoint_auth_method, "tls_client_auth")
  expect_identical(
    metadata$tls_client_auth_subject_dn,
    "CN=shiny-mtls-client,OU=Tests,O=shinyOAuth,L=Local,ST=NA,C=US"
  )
})

test_that("oauth_client_mtls_registration supports explicit SAN identifiers", {
  client <- make_mtls_registration_client("tls_client_auth")
  identifiers <- list(
    san_dns = list(
      field = "tls_client_auth_san_dns",
      value = "client.example.com"
    ),
    san_uri = list(
      field = "tls_client_auth_san_uri",
      value = "spiffe://example/client"
    ),
    san_ip = list(
      field = "tls_client_auth_san_ip",
      value = "192.0.2.10"
    ),
    san_email = list(
      field = "tls_client_auth_san_email",
      value = "client@example.com"
    )
  )

  for (identifier in names(identifiers)) {
    metadata <- shinyOAuth::oauth_client_mtls_registration(
      client,
      tls_client_auth_type = identifier,
      tls_client_auth_value = identifiers[[identifier]]$value
    )

    expect_identical(metadata$token_endpoint_auth_method, "tls_client_auth")
    expect_identical(
      metadata[[identifiers[[identifier]]$field]],
      identifiers[[identifier]]$value
    )
  }
})

test_that("oauth_client_mtls_registration emits certificate-bound token intent", {
  client <- make_mtls_registration_client(
    token_auth_style = "tls_client_auth",
    mtls_client_certificate_bound_access_tokens = TRUE,
    mtls_certificate_bound_access_tokens = TRUE
  )

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)

  expect_identical(metadata$token_endpoint_auth_method, "tls_client_auth")
  expect_true(isTRUE(metadata$tls_client_certificate_bound_access_tokens))
  expect_identical(
    metadata$tls_client_auth_subject_dn,
    "CN=shiny-mtls-client,OU=Tests,O=shinyOAuth,L=Local,ST=NA,C=US"
  )
})

test_that("oauth_client_mtls_registration supports public certificate-bound clients", {
  client <- make_mtls_registration_client(
    token_auth_style = "public",
    mtls_client_certificate_bound_access_tokens = TRUE,
    mtls_certificate_bound_access_tokens = TRUE
  )

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)

  expect_identical(metadata$token_endpoint_auth_method, "none")
  expect_true(isTRUE(metadata$tls_client_certificate_bound_access_tokens))
  expect_false(any(grepl("^tls_client_auth_", names(metadata))))
  expect_null(metadata[["jwks"]])
  expect_null(metadata[["jwks_uri"]])
})

test_that("SAN helpers classify unique certificate alt names", {
  cert_info <- list(
    alt_names = c(
      "DNS:client.example.com",
      "URI:spiffe://example/client",
      "IP Address:192.0.2.10",
      "email:client@example.com"
    )
  )

  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_dns"),
    "client.example.com"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_uri"),
    "spiffe://example/client"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_ip"),
    "192.0.2.10"
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(cert_info, "san_email"),
    "client@example.com"
  )

  expect_error(
    shinyOAuth:::resolve_certificate_alt_name_value(
      list(alt_names = c("DNS:a.example.com", "DNS:b.example.com")),
      "san_dns"
    ),
    regexp = "multiple candidate values"
  )
})

test_that("SAN helpers normalize IP literals for registration metadata", {
  expect_identical(
    shinyOAuth:::parse_certificate_alt_name("IP Address:192.000.002.010"),
    list(type = "san_ip", value = "192.0.2.10")
  )
  expect_identical(
    shinyOAuth:::parse_certificate_alt_name(
      "IP Address:2001:0DB8:0000:0000:0001:0000:0000:0001"
    ),
    list(type = "san_ip", value = "2001:db8::1:0:0:1")
  )
  expect_identical(
    shinyOAuth:::resolve_certificate_alt_name_value(
      list(alt_names = c("IP Address:2001:0DB8:0000:0000:0001:0000:0000:0001")),
      "san_ip"
    ),
    "2001:db8::1:0:0:1"
  )
})

test_that("oauth_client_mtls_registration builds inline self-signed jwks", {
  client <- make_mtls_registration_client("self_signed_tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(client)
  encoded <- jsonlite::toJSON(metadata, auto_unbox = TRUE)
  leaf_der_b64 <- as.character(openssl::base64_encode(openssl::write_der(
    openssl::read_cert(mtls_pem_fixture("client-cert.pem"))
  )))

  expect_identical(
    metadata$token_endpoint_auth_method,
    "self_signed_tls_client_auth"
  )
  expect_true(is.list(metadata$jwks))
  expect_silent(shinyOAuth:::validate_jwks(metadata$jwks))
  expect_identical(as.vector(metadata$jwks$keys[[1]]$x5c)[[1]], leaf_der_b64)
  expect_match(encoded, '"x5c":\\[')
  expect_false(any(
    names(metadata$jwks$keys[[1]]) %in%
      c(
        "d",
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",
        "k"
      )
  ))
})

test_that("oauth_client_mtls_registration supports self-signed jwks_uri", {
  client <- make_mtls_registration_client("self_signed_tls_client_auth")

  metadata <- shinyOAuth::oauth_client_mtls_registration(
    client,
    jwks_uri = "https://example.com/jwks.json"
  )

  expect_identical(
    metadata$token_endpoint_auth_method,
    "self_signed_tls_client_auth"
  )
  expect_identical(metadata$jwks_uri, "https://example.com/jwks.json")
  expect_null(metadata[["jwks"]])
})
