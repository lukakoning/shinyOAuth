test_that("JSON and list claims render the same structural summary", {
  client <- make_test_client()
  client@claims <- list(
    userinfo = list(email = list(value = "alice.private@example.com"))
  )
  list_output <- format(client)
  client@claims <- as.character(jsonlite::toJSON(
    client@claims,
    auto_unbox = TRUE
  ))
  expect_identical(format(client), list_output)
  expect_false(any(grepl("alice.private", list_output, fixed = TRUE)))
})

test_that("short credentials expose no prefix or suffix", {
  client <- make_test_client()
  client@client_secret <- "abcdefghijkl"
  for (output in c(format(client), capture.output(print(client)))) {
    expect_false(grepl("abcd", output, fixed = TRUE))
    expect_false(grepl("ijkl", output, fixed = TRUE))
  }
})
