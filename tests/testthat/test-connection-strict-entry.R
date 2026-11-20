test_that("Strict external entry rechecks the retained cookie without replacing it", {
  f <- manager_test_fixture(owner = oauth_browser_owner(same_site = "Strict"))
  cookie <- manager_test_cookie(f)
  owners <- f[["manager"]][["state"]][["owners"]]
  owner <- owners[["resolve"]](sub("^[^=]+=", "", cookie))
  owners[["retain"]](owner)
  req <- manager_test_request(query = "view=a%20b&view=c&&")
  req[["HTTP_SEC_FETCH_SITE"]] <- "cross-site"
  response <- f[["ui"]](req)
  expect_identical(response[["status"]], 200L)
  expect_match(
    response[["content"]],
    "shinyOAuth_owner_recovery=1",
    fixed = TRUE
  )
  expect_false(grepl("Connections", response[["content"]], fixed = TRUE))
  expect_null(response[["headers"]][["Set-Cookie"]])

  req[["QUERY_STRING"]] <- paste0(
    "?",
    req[["QUERY_STRING"]],
    "&shinyOAuth_owner_recovery=1"
  )
  req[["HTTP_SEC_FETCH_SITE"]] <- "same-origin"
  req[["HTTP_COOKIE"]] <- cookie
  recovered <- f[["ui"]](req)
  expect_identical(recovered[["status"]], 303L)
  expect_identical(
    recovered[["headers"]][["Location"]],
    "https://app.example/?view=a%20b&view=c&&"
  )
  expect_null(recovered[["headers"]][["Set-Cookie"]])
  req[["QUERY_STRING"]] <- "view=a%20b&view=c&&"
  loaded <- f[["ui"]](req)
  expect_match(loaded[["content"]], "Connections", fixed = TRUE)
  expect_null(loaded[["headers"]][["Set-Cookie"]])
  expect_identical(owners[["resolve"]](sub("^[^=]+=", "", cookie)), owner)
})

test_that("Strict recovery is bounded and its marker cannot establish an owner", {
  f <- manager_test_fixture(owner = oauth_browser_owner(same_site = "Strict"))
  expect_rejected_entry <- function(req) {
    response <- f[["ui"]](req)
    expect_identical(response[["status"]], 303L)
    expect_match(
      response[["headers"]][["Location"]],
      "^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$"
    )
    terminal <- callback_rejection_terminal(f[["ui"]], req, response)
    expect_identical(terminal[["status"]], 400L)
    for (hop in list(response, terminal)) {
      expect_null(hop[["headers"]][["Set-Cookie"]])
      expect_false(grepl(
        'http-equiv="refresh"',
        hop[["content"]],
        fixed = TRUE
      ))
    }
  }
  for (query in c(
    "shinyOAuth_owner_recovery=1",
    "shinyOAuth_owner_recovery=2",
    "shinyOAuth_owner_recovery=1&shinyOAuth_owner_recovery=1"
  )) {
    req <- manager_test_request(query = query)
    for (site in c("cross-site", "same-site", "none")) {
      req[["HTTP_SEC_FETCH_SITE"]] <- site
      req[["HTTP_REFERER"]] <- "https://app.example/"
      expect_rejected_entry(req)
    }
  }
  req <- manager_test_request(query = "shinyOAuth_owner_recovery=1")
  expect_rejected_entry(req)
  req[["HTTP_REFERER"]] <- "https://app.example/"
  recovered <- f[["ui"]](req)
  expect_identical(recovered[["status"]], 303L)
  expect_identical(recovered[["headers"]][["Location"]], "https://app.example/")
  expect_null(recovered[["headers"]][["Set-Cookie"]])
  expect_false(grepl(
    'http-equiv="refresh"',
    recovered[["content"]],
    fixed = TRUE
  ))
  req[["QUERY_STRING"]] <- ""
  expect_match(f[["ui"]](req)[["headers"]][["Set-Cookie"]], "SameSite=Strict")
  req[["HTTP_REFERER"]] <- "https://app.example.evil/"
  expect_null(f[["ui"]](req)[["headers"]][["Set-Cookie"]])
})
