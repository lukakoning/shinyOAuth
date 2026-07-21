spotify_vignette_path <- function() {
  candidates <- c(
    file.path("vignettes", "example-spotify.Rmd"),
    testthat::test_path("..", "..", "vignettes", "example-spotify.Rmd"),
    file.path("doc", "example-spotify.Rmd"),
    system.file("doc", "example-spotify.Rmd", package = "shinyOAuth")
  )
  candidates <- candidates[file.exists(candidates) & nzchar(candidates)]
  if (!length(candidates)) {
    return(NA_character_)
  }
  candidates[[1]]
}

test_that("Spotify vignette never disables table escaping", {
  path <- spotify_vignette_path()
  skip_if(is.na(path), "Spotify vignette is not available")

  source <- readLines(path, warn = FALSE)
  expect_false(any(grepl("escape\\s*=\\s*FALSE", source)))
  expect_gte(sum(grepl("escape\\s*=\\s*TRUE", source)), 2L)
})

test_that("DT escaping covers adversarial Spotify metadata", {
  skip_if_not_installed("DT")

  payload <- "<img src=x onerror=alert('stored-xss')>"
  metadata <- data.frame(
    Track = payload,
    Artist = payload,
    Album = payload,
    Genres = payload
  )

  widget <- DT::datatable(metadata, rownames = FALSE, escape = TRUE)

  expect_identical(attr(widget$x$options, "escapeIdx"), "true")
})
