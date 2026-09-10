smart_sandbox_urls <- function() {
  list(
    launcher = "http://localhost:18413",
    fhir = "http://localhost:18413/v/r4/fhir",
    raw_fhir = "http://localhost:18404/hapi-fhir-jpaserver/fhir",
    picker = "http://localhost:18412"
  )
}

smart_sandbox_get <- function(url) {
  httr2::request(url) |>
    httr2::req_headers(Accept = "application/fhir+json, application/json") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_timeout(5) |>
    httr2::req_perform()
}

smart_sandbox_json <- function(url) {
  httr2::resp_body_json(smart_sandbox_get(url), simplifyVector = FALSE)
}
