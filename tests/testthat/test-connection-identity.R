connection_identity_fixture <- function() {
  provider <- make_test_provider(use_nonce = TRUE)
  provider@id_token_validation <- TRUE
  client <- oauth_client(
    provider,
    "identity-app",
    redirect_uri = "https://app.example/callback",
    scopes = c("openid", "profile", "read"),
    required_scopes = c("openid", "read"),
    resource_bases = c(api = "https://api.example")
  )
  key <- openssl::rsa_keygen(2048)
  jwks <- list(
    keys = list(jsonlite::fromJSON(
      write_test_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    ))
  )
  jwt <- jose::jwt_encode_sig(
    jose::jwt_claim(
      iss = provider@issuer,
      sub = "synthetic-subject",
      aud = client@client_id,
      nonce = "synthetic-nonce",
      exp = as.numeric(Sys.time()) + 300
    ),
    key
  )
  withr::local_options(list(shinyOAuth.tls_min_version = NULL))
  testthat::local_mocked_bindings(
    fetch_jwks = function(...) jwks,
    .package = "shinyOAuth"
  )
  verified <- verify_token_set(
    client,
    list(
      access_token = "synthetic-access",
      token_type = "Bearer",
      expires_in = 300,
      scope = "openid profile read",
      id_token = jwt
    ),
    nonce = "synthetic-nonce"
  )
  token <- OAuthToken(
    access_token = "synthetic-access",
    refresh_token = "synthetic-refresh",
    token_type = "Bearer",
    expires_at = as.numeric(Sys.time()) + 300,
    id_token = jwt,
    id_token_validated = verified[[".id_token_validated"]],
    granted_scopes = verified[["granted_scopes"]],
    granted_scopes_verified = TRUE,
    userinfo = list(
      sub = "synthetic-subject",
      name = "Synthetic Name",
      email = "private@example.test"
    )
  )
  list(client = client, token = token)
}

test_that("identity selects validated claims and bound UserInfo without raw credentials", {
  f <- connection_identity_fixture()
  shiny::testServer(
    function(input, output, session) {
      source <- shiny::reactiveVal(f[["token"]])
      connection <- oauth_connection(f[["client"]], shiny::reactive(source()))
    },
    {
      expect_identical(
        connection[["identity"]](),
        list(
          id_token_claims = list(
            iss = f[["client"]]@provider@issuer,
            sub = "synthetic-subject"
          ),
          userinfo = list()
        )
      )
      selected <- connection[["identity"]](
        claims = "sub",
        userinfo = c("name", "absent")
      )
      expect_identical(
        selected,
        list(
          id_token_claims = list(sub = "synthetic-subject"),
          userinfo = list(name = "Synthetic Name")
        )
      )
      expect_false(any(
        c("access_token", "refresh_token", "id_token") %in% names(selected)
      ))
      expect_false(grepl(
        "synthetic-subject|Synthetic Name|private@",
        paste(
          capture.output(str(connection[["summary"]]())),
          capture.output(print(connection)),
          collapse = " "
        )
      ))
      updated <- f[["token"]]
      updated@userinfo[["name"]] <- "Updated Name"
      source(updated)
      expect_identical(
        connection[["identity"]](userinfo = "name")[["userinfo"]][["name"]],
        "Updated Name"
      )
      updated@userinfo[["sub"]] <- "another-subject"
      source(updated)
      expect_error(connection[["identity"]](userinfo = "name"), "not bound")
      updated <- f[["token"]]
      updated@id_token_validated <- FALSE
      source(updated)
      expect_error(connection[["identity"]](), "validated OIDC")
      source(f[["token"]])
      expect_error(
        connection[["identity"]](claims = c("sub", "sub")),
        "distinct"
      )
      source(NULL)
      expect_error(connection[["identity"]](), "validated OIDC")
    }
  )
})

test_that("managed identity references require the current owning session", {
  f <- connection_identity_fixture()
  manager <- oauth_connections(
    list(oidc = f[["client"]]),
    "https://app.example"
  )
  oauth_connections_ui(shiny::fluidPage("Identity"), "auth", manager)
  reference <- NULL
  shiny::testServer(
    oauth_connections_server,
    session = manager_test_session(),
    args = list(id = "auth", manager = manager),
    {
      auth <- session[["returned"]]
      hooks <- controller[["hooks"]]("oidc")
      context <- hooks[["prepare"]]()
      hooks[["accept"]](f[["token"]], context, as.numeric(Sys.time()))
      id <- controller[["records"]]()[[1L]][["stored"]][["id"]]
      reference <<- auth[["connection"]](id)
      expect_identical(
        reference[["identity"]]()[["id_token_claims"]][["sub"]],
        "synthetic-subject"
      )
      other <- shiny::MockShinySession[["new"]]()
      shiny::withReactiveDomain(
        other,
        shiny::isolate(
          expect_error(reference[["identity"]](), "unavailable")
        )
      )
      other[["close"]]()
      auth[["disconnect"]](id, revoke = FALSE)
      expect_error(reference[["identity"]](), "validated OIDC")
    }
  )
  expect_error(reference[["identity"]](), "unavailable")
})
