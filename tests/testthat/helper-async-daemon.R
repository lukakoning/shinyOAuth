async_daemon_source_root <- function() {
  normalizePath(testthat::test_path("..", ".."), winslash = "/")
}

async_daemon_source_files <- function() {
  root <- async_daemon_source_root()
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
  source_files <- async_daemon_source_files()
  source_times <- file.info(source_files)$mtime
  source_times <- source_times[!is.na(source_times)]
  source_mtime <- max(source_times)
  source_version <- read.dcf(
    file.path(async_daemon_source_root(), "DESCRIPTION"),
    fields = "Version"
  )[[1L]]

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
