keycloak_callback_rejection_base <- function(redirect_uri) {
  parts <- httr2::url_parse(redirect_uri)
  if (
    !parts[["scheme"]] %in% c("http", "https") ||
      !parts[["hostname"]] %in% c("localhost", "127.0.0.1") ||
      !is.null(parts[["username"]]) ||
      !is.null(parts[["password"]]) ||
      length(parts[["query"]]) ||
      !is.null(parts[["fragment"]])
  ) {
    stop("Callback rejection checks require the configured loopback route")
  }
  if (is.null(parts[["path"]]) || !nzchar(parts[["path"]])) {
    parts[["path"]] <- "/"
  }
  httr2::url_build(parts)
}

keycloak_callback_rejection_target <- function(redirect_uri, location) {
  if (
    !is.character(location) ||
      length(location) != 1L ||
      is.na(location) ||
      !grepl("^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$", location)
  ) {
    stop(
      "Callback rejection Location must be an opaque query-only locator with an empty fragment"
    )
  }
  paste0(keycloak_callback_rejection_base(redirect_uri), location)
}

keycloak_callback_rejection_url_matches <- function(url, redirect_uri) {
  tryCatch(
    {
      base <- keycloak_callback_rejection_base(redirect_uri)
      if (
        !is.character(url) ||
          length(url) != 1L ||
          is.na(url) ||
          !startsWith(url, paste0(base, "?"))
      ) {
        return(FALSE)
      }
      query <- sub("#$", "", substring(url, nchar(base) + 1L))
      identical(
        sub("#$", "", url),
        sub(
          "#$",
          "",
          keycloak_callback_rejection_target(redirect_uri, paste0(query, "#"))
        )
      )
    },
    error = function(...) FALSE
  )
}

keycloak_follow_callback_rejection <- function(
  response,
  redirect_uri,
  expected_status,
  sensitive = character(),
  .perform = httr2::req_perform
) {
  testthat::expect_identical(httr2::resp_status(response), 303L)
  if (!identical(httr2::resp_status(response), 303L)) {
    stop("Expected the callback rejection cleanup hop")
  }
  target <- keycloak_callback_rejection_target(
    redirect_uri,
    httr2::resp_header(response, "location")
  )
  testthat::expect_false(httr2::resp_has_body(response))
  testthat::expect_identical(
    httr2::resp_header(response, "cache-control"),
    "no-store"
  )
  testthat::expect_identical(
    httr2::resp_header(response, "referrer-policy"),
    "no-referrer"
  )
  terminal <- httr2::request(target) |>
    httr2::req_method("GET") |>
    httr2::req_options(followlocation = FALSE) |>
    httr2::req_timeout(10) |>
    httr2::req_error(is_error = function(...) FALSE) |>
    .perform()
  testthat::expect_identical(httr2::resp_status(terminal), expected_status)
  testthat::expect_null(httr2::resp_header(terminal, "location"))
  testthat::expect_true(keycloak_callback_rejection_url_matches(
    httr2::resp_url(terminal),
    redirect_uri
  ))
  testthat::expect_identical(
    httr2::resp_header(terminal, "cache-control"),
    "no-store"
  )
  testthat::expect_identical(
    httr2::resp_header(terminal, "referrer-policy"),
    "no-referrer"
  )
  testthat::expect_match(
    httr2::resp_header(terminal, "content-type"),
    "^text/plain"
  )
  text <- paste(
    c(
      httr2::resp_headers(response),
      httr2::resp_headers(terminal),
      if (httr2::resp_has_body(terminal)) {
        httr2::resp_body_string(terminal)
      } else {
        ""
      }
    ),
    collapse = "\n"
  )
  for (value in sensitive) {
    testthat::expect_false(grepl(value, text, fixed = TRUE))
  }
  terminal
}

keycloak_expect_callback_rejection_page <- function(
  drv,
  redirect_uri,
  sensitive = character()
) {
  page <- jsonlite::fromJSON(drv[["get_js"]](paste0(
    "JSON.stringify({href:location.href,body:document.body&&document.body.innerText,",
    "appPresent:document.querySelector('#auth_state')!==null})"
  )))
  testthat::expect_true(keycloak_callback_rejection_url_matches(
    page[["href"]],
    redirect_uri
  ))
  testthat::expect_false(page[["appPresent"]])
  for (value in sensitive) {
    testthat::expect_false(grepl(
      value,
      paste(page[["href"]], page[["body"]]),
      fixed = TRUE
    ))
  }
  invisible(page)
}
