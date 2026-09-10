test_that("resource bases preserve full paths and compare exact origins", {
  base <- "https://api.example/fhir/R4"
  expect_identical(
    resolve_bound_resource(base, "Patient/123"),
    paste0(base, "/Patient/123")
  )
  expect_identical(
    resolve_bound_resource(base, "/fhir/R4/Patient/123"),
    paste0(base, "/Patient/123")
  )
  expect_identical(
    resolve_bound_resource(base, "https://API.EXAMPLE:443/fhir/R4/Patient/123"),
    paste0(base, "/Patient/123")
  )
  expect_identical(
    resolve_bound_resource(paste0(base, "/"), "Patient/%31%32%33"),
    paste0(base, "/Patient/123")
  )
  expect_identical(
    resolve_bound_resource(base, "Patient?_page=2"),
    paste0(base, "/Patient?_page=2")
  )
  expect_identical(
    resolve_bound_resource(base, "?next=a%2Fb"),
    paste0(base, "/?next=a%2Fb")
  )
  for (reference in c(
    "https://other.example/fhir/R4/Patient/123",
    "https://api.example:444/fhir/R4/Patient/123",
    "http://api.example/fhir/R4/Patient/123",
    "/fhir/R4-other/Patient/123",
    "/fhir/R5/Patient/123",
    "https://api.example/Patient/123",
    "//api.example/fhir/R4/Patient/123",
    "https://user:password@api.example/fhir/R4/Patient/123",
    "https://api.example./fhir/R4/Patient/123"
  )) {
    expect_error(
      resolve_bound_resource(base, reference),
      "approved base|ambiguous"
    )
  }
})

test_that("ambiguous paths fail closed before destination normalization", {
  for (path in c(
    "../Patient/123",
    "./Patient/123",
    "Patient/../123",
    "Patient//123",
    "Patient/%2e%2e/123",
    "Patient/%252e/123",
    "Patient/%2f123",
    "Patient/%5c123",
    "Patient\\123",
    "Patient/123;extra",
    "Patient/%3b123",
    "Patient/%00",
    "Patient/%zz",
    "Patient/123#fragment",
    "Patient/123\n",
    "Patient/%20"
  )) {
    expect_error(
      resolve_bound_resource("https://api.example/fhir/R4", path),
      "approved base|ambiguous"
    )
  }
})

test_that("base policy cannot be expanded by permissive generic URL options", {
  local_options(
    shinyOAuth.allowed_hosts = "*",
    shinyOAuth.allowed_non_https_hosts = "*",
    shinyOAuth.allow_redirect = TRUE
  )
  expect_error(
    normalize_resource_bases(c(api = "http://api.example/v1")),
    "approved base|ambiguous"
  )
  expect_error(
    resolve_bound_resource(
      "https://api.example/v1",
      "https://other.example/v1"
    ),
    "approved base|ambiguous"
  )
  expect_identical(
    normalize_resource_bases(c(api = "http://127.0.0.1:8080/v1/")),
    c(api = "http://127.0.0.1:8080/v1")
  )
  for (base in c(
    "https://api.example/v1?x=1",
    "https://api.example/v1#x",
    "https://api.example/v1//"
  )) {
    expect_error(
      normalize_resource_bases(c(api = base)),
      "approved base|ambiguous"
    )
  }
  expect_error(
    normalize_resource_bases(c("https://api.example/v1")),
    "resource_bases"
  )
  expect_error(
    normalize_resource_bases(c(
      api = "https://api.example/v1",
      api = "https://api.example/v2"
    )),
    "resource_bases"
  )
  expect_error(
    normalize_resource_bases(c(
      a = "https://api.example/v1",
      b = "https://api.example/v1/"
    )),
    "distinct"
  )
})
