test_that("required cache methods cannot be supplied by prefix collisions", {
  methods <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(TRUE)
  )
  for (field in names(methods)) {
    cache <- methods
    names(cache)[names(cache) == field] <- paste0(field, "_extension")
    client <- make_test_client()
    expect_error(
      {
        client@state_store <- cache
      },
      "state_store"
    )
    if (field %in% c("get", "set")) {
      provider <- make_test_provider()
      expect_error(
        {
          provider@jwks_cache <- cache
        },
        "jwks_cache"
      )
    }
  }
})

test_that("a prefixed take method cannot satisfy atomic state consumption", {
  local_options(shinyOAuth.allow_non_atomic_state_store = FALSE)
  called <- FALSE
  store <- list(
    get = function(key, missing = NULL) missing,
    set = function(key, value) invisible(NULL),
    remove = function(key) invisible(TRUE),
    take_extension = function(key, missing = NULL) {
      called <<- TRUE
      missing
    }
  )
  client <- make_test_client()
  client@state_store <- store
  expect_error(
    state_store_get_remove(client, "exact-state"),
    "requires atomic",
    class = "shinyOAuth_config_error"
  )
  expect_false(called)
})

test_that("repository R code and documented R chunks use exact member access", {
  root <- test_path("..", "..")
  skip_if_not(
    file.exists(file.path(root, "R", "utils__state.R")),
    "Package source unavailable"
  )
  directories <- file.path(
    root,
    c(
      "R",
      "tests",
      "inst",
      "man",
      "playground",
      "integration",
      ".github",
      ".vscode"
    )
  )
  files <- file.path(root, "README.md")
  while (length(directories)) {
    directory <- directories[[1L]]
    directories <- directories[-1L]
    if (!dir.exists(directory)) {
      next
    }
    files <- c(
      files,
      list.files(directory, pattern = "[.](R|Rmd|Rd|md)$", full.names = TRUE)
    )
    children <- list.dirs(directory, recursive = FALSE, full.names = TRUE)
    directories <- c(
      directories,
      children[!startsWith(basename(children), ".")]
    )
  }
  violations <- character()
  inspect <- function(node, label, assignment = FALSE) {
    if (!is.call(node) && !is.expression(node) && !is.pairlist(node)) {
      return(invisible(NULL))
    }
    operation <- if (is.call(node) && is.symbol(node[[1L]])) {
      as.character(node[[1L]])
    } else if (
      is.call(node) &&
        is.call(node[[1L]]) &&
        is.symbol(node[[1L]][[1L]]) &&
        as.character(node[[1L]][[1L]]) %in% c("::", ":::")
    ) {
      as.character(node[[1L]][[3L]])
    } else {
      ""
    }
    if (operation %in% c("$", "$<-")) {
      violations <<- c(violations, paste(label, "uses dollar access"))
    }
    if (
      operation == "[[" &&
        "exact" %in% names(node) &&
        !identical(node[["exact"]], TRUE)
    ) {
      violations <<- c(violations, paste(label, "enables partial matching"))
    }
    if (operation == "attr" && !assignment) {
      exact <- if ("exact" %in% names(node)) {
        node[["exact"]]
      } else if (length(node) >= 4L) {
        node[[4L]]
      } else {
        FALSE
      }
      if (!identical(exact, TRUE)) {
        violations <<- c(
          violations,
          paste(label, "reads an attribute without exact matching")
        )
      }
    }
    if (
      operation %in%
        c("do.call", "get", "match.fun") &&
        length(node) >= 2L &&
        is.character(node[[2L]]) &&
        node[[2L]] %in% c("$", "$<-")
    ) {
      violations <<- c(violations, paste(label, "uses indirect dollar access"))
    }
    for (i in seq_along(node)) {
      if (!identical(node[[i]], quote(expr = ))) {
        inspect(
          node[[i]],
          label,
          assignment = operation %in% c("<-", "<<-", "=") && i == 2L
        )
      }
    }
    invisible(NULL)
  }
  for (file in files[file.exists(files)]) {
    lines <- readLines(file, warn = FALSE)
    if (endsWith(file, ".R")) {
      snippets <- list(lines)
    } else if (endsWith(file, ".Rd")) {
      examples <- Filter(
        function(node) {
          identical(attr(node, "Rd_tag", exact = TRUE), "\\examples")
        },
        tools::parse_Rd(file)
      )
      snippets <- lapply(examples, function(node) {
        paste(unlist(node, use.names = FALSE), collapse = "")
      })
    } else {
      snippets <- list()
      start <- NULL
      for (i in seq_along(lines)) {
        if (
          is.null(start) &&
            grepl(
              "^\\s*```(?:\\{[rR](?:[ ,}]|$)|[rR]\\s*$)",
              lines[[i]],
              perl = TRUE
            )
        ) {
          start <- i + 1L
        } else if (
          !is.null(start) && grepl("^\\s*```\\s*$", lines[[i]], perl = TRUE)
        ) {
          snippets[[length(snippets) + 1L]] <- if (i > start) {
            lines[seq.int(start, i - 1L)]
          } else {
            character()
          }
          start <- NULL
        }
      }
    }
    for (snippet in snippets) {
      parsed <- parse(text = snippet, keep.source = TRUE)
      inspect(parsed, file)
      data <- utils::getParseData(parsed)
      if (is.null(data)) {
        next
      }
      bad <- data[["terminal"]] &
        (data[["token"]] == "'$'" |
          (data[["token"]] %in%
            c("SYMBOL_FUNCTION_CALL", "SYMBOL") &
            data[["text"]] %in% c("`$`", "`$<-`")))
      if (any(bad)) {
        violations <- c(
          violations,
          paste(file, data[["line1"]][bad], sep = ":")
        )
      }
    }
  }
  expect_identical(
    length(violations),
    0L,
    info = paste(violations, collapse = "\n")
  )
})
