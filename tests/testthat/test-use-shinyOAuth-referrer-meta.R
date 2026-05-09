testthat::test_that("use_shinyOAuth injects referrer meta by default", {
  ui <- use_shinyOAuth()
  rt <- htmltools::renderTags(ui)

  testthat::expect_true(
    grepl(
      "<meta[^>]+name=\"referrer\"[^>]+content=\"no-referrer\"",
      rt$head
    )
  )
  testthat::expect_false(
    grepl(
      "<meta[^>]+name=\"referrer\"[^>]+content=\"no-referrer\"",
      rt$html
    )
  )
})

testthat::test_that("use_shinyOAuth can disable referrer meta injection", {
  ui <- use_shinyOAuth(inject_referrer_meta = FALSE)
  rt <- htmltools::renderTags(ui)

  testthat::expect_false(
    grepl(
      "<meta[^>]+name=\"referrer\"",
      rt$head
    )
  )
  testthat::expect_false(
    grepl(
      "<meta[^>]+name=\"referrer\"",
      rt$html
    )
  )
})
