test_that("the first three multiple-authorization chunks assemble a complete app", {
  path <- test_path("..", "..", "vignettes", "multiple-authorizations.Rmd")
  skip_if_not(
    file.exists(path),
    "Vignette source is unavailable in installed tests"
  )
  lines <- readLines(path, warn = FALSE)
  starts <- grep("^```\\{r ", lines)
  expect_identical(
    sub("^```\\{r ([^,]+),.*$", "\\1", lines[starts[1:3]]),
    c("multiple-clients", "multiple-manager", "multiple-app")
  )
  chunks <- lapply(starts[1:3], function(start) {
    end <- start + which(lines[-seq_len(start)] == "```")[[1L]]
    parse(text = lines[seq.int(start + 1L, end - 1L)])
  })
  withr::local_envvar(c(
    SERVICE_A_CLIENT_ID = "synthetic-a",
    SERVICE_A_CLIENT_SECRET = "synthetic-a-secret",
    SERVICE_B_CLIENT_ID = "synthetic-b",
    SERVICE_B_CLIENT_SECRET = "synthetic-b-secret"
  ))
  env <- new.env(parent = asNamespace("shinyOAuth"))
  env[["library"]] <- function(...) invisible(NULL)
  env[["runApp"]] <- function(appDir, ...) appDir
  # Supply the Shiny symbols normally attached by the first chunk's library().
  for (name in getNamespaceExports("shiny")) {
    env[[name]] <- getExportedValue("shiny", name)
  }
  env[["runApp"]] <- function(appDir, ...) appDir
  app <- NULL
  for (chunk in chunks) {
    app <- eval(chunk, envir = env)
  }
  expect_s3_class(app, "shiny.appobj")
  expect_true(is.function(env[["server"]]))
  expect_setequal(names(env[["clients"]]), c("a", "b"))
})
