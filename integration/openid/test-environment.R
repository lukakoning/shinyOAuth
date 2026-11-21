testthat::test_that("the suite lock rejects floating images and changed schemas", {
  root <- withr::local_tempdir("openid-lock-")
  dir.create(file.path(root, "integration/openid"), recursive = TRUE)
  lock <- openid_lock("../..")
  path <- file.path(root, "integration/openid/suite-lock.json")
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_identical(openid_lock(root), lock)
  lock[["images"]][[
    "server"
  ]] <- "registry.gitlab.com/openid/conformance-suite:latest"
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_error(openid_lock(root), "every image must use")
  lock <- openid_lock("../..")
  lock[["schema_version"]] <- 2L
  jsonlite::write_json(lock, path, auto_unbox = TRUE)
  testthat::expect_error(openid_lock(root), "Invalid OpenID suite lock")
})

testthat::test_that("missing, malformed and duplicated plan metadata fail preflight", {
  plans <- list(list(planName = "basic"), list(planName = "config"))
  testthat::expect_identical(
    openid_plan_ids(plans, c("basic", "config")),
    c("basic", "config")
  )
  testthat::expect_error(
    openid_plan_ids(plans, "refresh"),
    "missing required plans"
  )
  testthat::expect_error(
    openid_plan_ids(list(), "basic"),
    "missing required plans"
  )
  testthat::expect_error(
    openid_plan_ids(c(plans, plans), "basic"),
    "duplicate plans"
  )
  testthat::expect_error(
    openid_plan_ids(list(list(name = "basic")), "basic"),
    "no planName"
  )
})

testthat::test_that("cleanup refuses another Compose project before invoking Docker", {
  testthat::expect_error(
    openid_compose(list(project = "another-project"), "down"),
    "unowned"
  )
})

testthat::test_that("readiness has a bounded failure and API paths stay local", {
  testthat::expect_error(
    openid_wait(function() FALSE, "unavailable service", 0),
    "Timed out: unavailable"
  )
  testthat::expect_error(
    openid_api(list(), "https://other.example/api/server"),
    "Invalid OpenID API path"
  )
})

testthat::test_that("a Chrome port timeout retries once with a fresh pinned profile", {
  withr::local_options(chromote.timeout = 7)
  profiles <- character()
  closed <- FALSE
  stub <- list(
    get_browser = function() {
      list(
        get_process = function() list(is_alive = function() FALSE)
      )
    },
    close = function(wait) {
      closed <<- wait
      invisible(NULL)
    }
  )
  testthat::local_mocked_bindings(
    Chrome = list(new = function(args) {
      profile <- sub(
        "^--user-data-dir=",
        "",
        grep("--user-data-dir=", args, value = TRUE)
      )
      profiles <<- c(profiles, profile)
      testthat::expect_true(dir.exists(profile))
      testthat::expect_true(
        "--ignore-certificate-errors-spki-list=pin" %in% args
      )
      testthat::expect_identical(getOption("chromote.timeout"), 30)
      if (length(profiles) == 1L) {
        rlang::abort(
          "Chrome debugging port not open after 30 seconds.",
          class = "error_stop_port_search"
        )
      }
      profile
    }),
    Chromote = list(new = function(browser) {
      force(browser)
      stub
    }),
    .package = "chromote"
  )
  start <- function() {
    browser <- openid_browser("pin")
    testthat::expect_false(closed)
    testthat::expect_true(all(dir.exists(profiles)))
    browser
  }
  testthat::expect_message(
    actual <- start(),
    "retrying browser startup once"
  )
  testthat::expect_identical(actual, stub)
  testthat::expect_length(unique(profiles), 2L)
  testthat::expect_identical(getOption("chromote.timeout"), 7)
  testthat::expect_true(closed)
  testthat::expect_false(any(dir.exists(profiles)))
})

testthat::test_that("a second Chrome port timeout or executable failure fails startup", {
  for (message in c(
    "Chrome debugging port not open after 30 seconds.",
    "Failed to start Chrome."
  )) {
    local({
      profiles <- character()
      testthat::local_mocked_bindings(
        Chrome = list(new = function(args) {
          path <- sub(
            "^--user-data-dir=",
            "",
            grep("--user-data-dir=", args, value = TRUE)
          )
          profiles <<- c(profiles, path)
          rlang::abort(message, class = "error_stop_port_search")
        }),
        Chromote = list(new = function(browser) force(browser)),
        .package = "chromote"
      )
      start <- function() openid_browser("pin")
      suppressMessages(testthat::expect_error(
        start(),
        class = "error_stop_port_search"
      ))
      testthat::expect_length(
        unique(profiles),
        if (startsWith(message, "Chrome debugging")) 2L else 1L
      )
      testthat::expect_false(any(dir.exists(profiles)))
    })
  }
})

testthat::test_that("image reuse requires the exact locked content digest", {
  digest <- paste0("sha256:", paste(rep("a", 64L), collapse = ""))
  image <- paste0("registry.example/suite@", digest)
  inspect <- function(...) {
    list(
      status = 0L,
      stdout = as.character(jsonlite::toJSON(
        paste0("registry.example/suite@", digest)
      ))
    )
  }
  no_pull <- function(...) stop("A verified cache must not need the registry")
  testthat::expect_identical(
    openid_prepare_image(image, "unused", .run = inspect, .pull = no_pull),
    "cached"
  )
  for (metadata in c(
    "[]",
    "null",
    "{}",
    "not-json",
    '["registry.example/suite@sha256:wrong"]'
  )) {
    invalid <- function(...) list(status = 0L, stdout = metadata)
    testthat::expect_error(
      openid_prepare_image(image, "unused", .run = invalid, .pull = no_pull),
      "RepoDigests"
    )
  }
  testthat::expect_error(
    openid_prepare_image(
      "registry.example/suite:latest",
      "unused",
      .run = inspect,
      .pull = no_pull
    ),
    "pinned digest"
  )
})

testthat::test_that("missing images are pulled by digest and verified afterward", {
  image <- paste0(
    "registry.example/suite@sha256:",
    paste(rep("a", 64L), collapse = "")
  )
  inspections <- 0L
  request <- function(command, args, ...) {
    testthat::expect_identical(command, "docker")
    testthat::expect_identical(args[1:3], c("image", "inspect", image))
    inspections <<- inspections + 1L
    list(
      status = if (inspections == 1L) 1L else 0L,
      stdout = as.character(jsonlite::toJSON(image))
    )
  }
  pulls <- list()
  pull <- function(args, log) pulls[[length(pulls) + 1L]] <<- list(args, log)
  testthat::expect_identical(
    openid_prepare_image(image, "private.log", .run = request, .pull = pull),
    "pulled"
  )
  testthat::expect_identical(pulls, list(list(c("pull", image), "private.log")))
  absent <- function(...) list(status = 1L, stdout = "")
  testthat::expect_error(
    openid_prepare_image(
      image,
      "private.log",
      .run = absent,
      .pull = function(...) stop("Registry unavailable")
    ),
    "Registry unavailable"
  )
  testthat::expect_error(
    openid_prepare_image(
      image,
      "private.log",
      .run = absent,
      .pull = function(...) NULL
    ),
    "missing after pull"
  )
})
