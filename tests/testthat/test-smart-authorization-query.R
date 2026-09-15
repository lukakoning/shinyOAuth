test_that("SMART endpoint queries cannot supply transaction or unsupported composition fields", {
  site <- smart_client_fixture()
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]],
    list("authorize-post")
  )
  for (launch in c("standalone", "ehr")) {
    for (method in c("GET", "POST")) {
      for (query in c(
        "aud=https%3A%2F%2Fother.example%2Ffhir&launch=stale",
        "aud=https%3A%2F%2Fehr.example%2Ffhir%2FR4",
        "%61ud=other",
        "l%61unch=stale",
        "launch=stale&launch=another",
        "request_uri=https%3A%2F%2Fehr.example%2Frequest",
        "request=object",
        "max_age=0",
        "claims=%7B%7D",
        "resource=other",
        "dpop_jkt=key"
      )) {
        altered <- site
        altered[["metadata"]][["authorization_endpoint"]] <- paste0(
          "https://ehr.example/authorize?",
          query
        )
        expect_error(
          smart_client(
            altered,
            "example",
            "https://app.example/callback",
            scopes = "user/Patient.r",
            launch = launch,
            authorization_method = method
          ),
          "SMART authorization endpoint query"
        )
      }
    }
  }
  client <- smart_client(
    site,
    "example",
    "https://app.example/callback",
    scopes = "user/Patient.r"
  )
  expect_error(
    client@provider@auth_url <- "https://ehr.example/authorize?launch=stale",
    "SMART authorization endpoint query"
  )
  provider <- client@provider
  attr(provider, "auth_url") <- "https://ehr.example/authorize?aud=other"
  attr(client, "provider") <- provider
  expect_error(
    prepare_call(client, valid_browser_token()),
    "SMART authorization endpoint query"
  )
})

test_that("SMART retains benign fixed queries and ordinary OAuth extension handling", {
  site <- smart_client_fixture()
  site[["metadata"]][[
    "authorization_endpoint"
  ]] <- "https://ehr.example/authorize?tenant=demo%2Bsite"
  site[["metadata"]][["capabilities"]] <- c(
    site[["metadata"]][["capabilities"]],
    list("authorize-post")
  )
  for (method in c("GET", "POST")) {
    client <- smart_client(
      site,
      "example",
      "https://app.example/callback",
      scopes = "user/Patient.r",
      authorization_method = method
    )
    prepared <- prepare_authorization_request(client, valid_browser_token())
    if (method == "GET") {
      fields <- decode_form_pairs(url_raw_query(prepared[["url"]]), "test")
      expect_identical(fields[["tenant"]], "demo+site")
    } else {
      fields <- stats::setNames(
        lapply(prepared[["fields"]], `[[`, "value"),
        vapply(prepared[["fields"]], `[[`, "", "name")
      )
      expect_identical(
        prepared[["url"]],
        site[["metadata"]][["authorization_endpoint"]]
      )
    }
    expect_identical(fields[["aud"]], site[["fhir_base"]])
    expect_null(fields[["launch"]])
  }
  ordinary <- make_test_client()
  expect_no_error({
    ordinary@provider@auth_url <- "https://example.com/authorize?aud=extension&launch=extension"
  })
  expect_no_error(prepare_call(ordinary, valid_browser_token()))
})
