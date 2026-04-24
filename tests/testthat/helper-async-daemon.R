async_daemon_is_source_root <- function(path) {
  if (!(is.character(path) && length(path) == 1L && nzchar(path))) {
    return(FALSE)
  }

  root <- normalizePath(path, winslash = "/", mustWork = FALSE)
  file.exists(file.path(root, "DESCRIPTION")) &&
    file.exists(file.path(root, "NAMESPACE")) &&
    dir.exists(file.path(root, "R")) &&
    (dir.exists(file.path(root, ".git")) ||
      file.exists(file.path(root, "shinyOAuth.Rproj")))
}

async_daemon_source_root <- function() {
  candidates <- unique(normalizePath(
    c(
      testthat::test_path("..", ".."),
      getwd(),
      "."
    ),
    winslash = "/",
    mustWork = FALSE
  ))
  matches <- Filter(async_daemon_is_source_root, candidates)
  if (!length(matches)) {
    return(NULL)
  }
  matches[[1L]]
}

async_daemon_source_files <- function() {
  root <- async_daemon_source_root()
  if (is.null(root)) {
    return(character(0))
  }
  c(
    file.path(root, "DESCRIPTION"),
    file.path(root, "NAMESPACE"),
    list.files(
      file.path(root, "R"),
      full.names = TRUE,
      recursive = TRUE,
      all.files = FALSE
    )
  )
}

assert_shinyoauth_available_in_daemon <- function() {
  source_root <- async_daemon_source_root()
  source_files <- async_daemon_source_files()
  source_times <- file.info(source_files)$mtime
  source_times <- source_times[!is.na(source_times)]
  source_mtime <- if (length(source_times)) max(source_times) else NA
  source_version <- if (is.null(source_root)) {
    NA_character_
  } else {
    read.dcf(
      file.path(source_root, "DESCRIPTION"),
      fields = "Version"
    )[[1L]]
  }

  pkg_check <- mirai::mirai({
    available <- requireNamespace("shinyOAuth", quietly = TRUE)
    if (!isTRUE(available)) {
      return(list(available = FALSE))
    }

    pkg_path <- normalizePath(find.package("shinyOAuth"), winslash = "/")
    pkg_files <- c(
      file.path(pkg_path, "DESCRIPTION"),
      file.path(pkg_path, "Meta", "package.rds")
    )
    pkg_times <- file.info(pkg_files)$mtime
    pkg_times <- pkg_times[!is.na(pkg_times)]

    list(
      available = TRUE,
      path = pkg_path,
      version = as.character(utils::packageVersion("shinyOAuth")),
      built_mtime = if (length(pkg_times)) max(pkg_times) else NA_real_
    )
  })
  mirai::call_mirai(pkg_check)

  testthat::skip_if_not(
    isTRUE(pkg_check$data$available),
    "shinyOAuth must be installed for mirai daemon tests"
  )

  if (!is.null(source_root)) {
    testthat::skip_if_not(
      identical(pkg_check$data$version, source_version),
      paste0(
        "mirai daemon loaded shinyOAuth ",
        pkg_check$data$version,
        " from ",
        pkg_check$data$path,
        "; expected source version ",
        source_version,
        ". Install the current checkout first."
      )
    )
  }

  if (!is.null(source_root) && !is.na(source_mtime)) {
    testthat::skip_if_not(
      is.na(pkg_check$data$built_mtime) ||
        pkg_check$data$built_mtime >= source_mtime,
      paste0(
        "mirai daemon loaded an older shinyOAuth install from ",
        pkg_check$data$path,
        ". Install the current checkout first so worker code matches the source tree."
      )
    )
  }
}
