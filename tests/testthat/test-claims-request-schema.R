test_that("duplicate claims members cannot weaken client verification requirements", {
  bad <- list(
    '{"id_token":{"acr":{"essential":true,"value":"mfa"}},"id_token":{"acr":null}}',
    '{"id_token":{"acr":null},"id_\\u0074oken":{"acr":{"essential":true}}}',
    '{"userinfo":{"email":{"essential":false},"email":{"essential":true}}}',
    '{"id_token":{"acr":{"essential":false,"essential":true}}}',
    '{"id_token":{"custom":{"value":{"security":1,"security":2}}}}',
    setNames(
      list(list(acr = NULL), list(acr = list(essential = TRUE))),
      c("id_token", "id_token")
    ),
    list(
      id_token = setNames(list(NULL, list(essential = TRUE)), c("acr", "acr"))
    ),
    list(
      id_token = list(
        acr = setNames(list(FALSE, TRUE), c("essential", "essential"))
      )
    )
  )
  for (claims in bad) {
    for (mode in c("none", "warn", "strict")) {
      expect_error(
        make_test_client(claims = claims, claims_validation = mode),
        "[Dd]uplicate|unique"
      )
    }
  }
})

test_that("malformed essential claims and request structures fail closed", {
  bad <- list(
    list("id_token"),
    list(id_token = "acr"),
    list(id_token = NULL),
    list(userinfo = list(email = TRUE)),
    list(id_token = list(acr = list("mfa"))),
    '{"id_token":[]}',
    '{"id_token":{"acr":[]}}',
    '{"userinfo":null}',
    '{"id_token":{"acr":{"essential":"true"}}}',
    '{"id_token":{"acr":{"essential":1}}}',
    '{"id_token":{"acr":{"essential":[true]}}}',
    '{"id_token":{"acr":{"essential":null}}}',
    '{"id_token":{"acr":{"values":"mfa"}}}',
    '{"id_token":{"acr":{"values":{}}}}',
    '{"id_token":{"acr":{"values":[]}}}',
    '{"id_token":{"acr":{"value":"mfa","values":["pwd"]}}}',
    list(id_token = list(acr = list(essential = "true"))),
    list(id_token = list(acr = list(essential = NA))),
    list(id_token = list(acr = list(value = 1))),
    list(userinfo = list(email_verified = list(value = "true")))
  )
  for (claims in bad) {
    expect_error(
      make_test_client(claims = claims, claims_validation = "none"),
      "claims|Claims"
    )
  }
})

test_that("valid extensions, objects and singleton choices preserve their intended policy", {
  for (claims in list(
    '{"id_token":{},"userinfo":{"nickname":null}}',
    list(id_token = list(), userinfo = list(nickname = NULL)),
    list(),
    list(
      id_token = list(
        acr = list(
          essential = FALSE,
          values = "mfa",
          extension = list(custom = TRUE)
        )
      ),
      extra_target = list(vendor = "hint")
    ),
    list(
      id_token = list(
        custom = list(value = list(address = list(country = "NL")))
      )
    )
  )) {
    client <- make_test_client(claims = claims, claims_validation = "none")
    expect_no_error(prepare_call(client, browser_token = valid_browser_token()))
  }
  claims <- list(id_token = list(acr = list(essential = TRUE, values = "mfa")))
  client <- make_test_client(
    use_nonce = TRUE,
    claims = claims,
    claims_validation = "strict"
  )
  url <- prepare_call(client, browser_token = valid_browser_token())
  wire <- parse_query_param(url, "claims", decode = TRUE)
  expect_identical(
    jsonlite::fromJSON(wire, simplifyVector = FALSE)[["id_token"]][["acr"]][[
      "values"
    ]],
    list("mfa")
  )
  expect_error(
    validate_essential_claims(client, list(acr = "pwd"), "id_token"),
    class = "shinyOAuth_id_token_error"
  )
  expect_no_error(validate_essential_claims(
    client,
    list(acr = "mfa"),
    "id_token"
  ))
  expect_error(
    S7::props(client) <- list(
      claims = '{"id_token":{"acr":{"essential":"true"}}}'
    ),
    "Boolean"
  )
})
