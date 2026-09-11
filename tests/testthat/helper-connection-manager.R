manager_test_request <- function(cookie = NULL, method = "GET", path = "/", query = "") {
  list(REQUEST_METHOD = method, PATH_INFO = path, SCRIPT_NAME = "", QUERY_STRING = query,
    HTTP_HOST = "app.example", "rook.url_scheme" = "https", HTTP_COOKIE = cookie)
}

manager_test_session <- function(cookie = NULL) {
  session_env <- new.env(parent = asNamespace("shiny"))
  session_env$request_data <- list(HTTP_ORIGIN = "https://app.example", HTTP_COOKIE = cookie)
  R6::R6Class(inherit = shiny::MockShinySession, portable = FALSE, lock_objects = FALSE,
    parent_env = session_env, active = list(request = function(value) {
      if (!missing(value)) request_data <<- value
      request_data
    }))$new()
}

manager_test_cookie <- function(f) {
  response <- f$ui(manager_test_request())
  sub(";.*$", "", response$headers[["Set-Cookie"]])
}
