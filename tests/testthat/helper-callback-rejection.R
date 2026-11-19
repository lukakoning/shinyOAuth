callback_rejection_terminal <- function(handler, req, response = handler(req)) {
  location <- response[["headers"]][["Location"]]
  if (
    identical(response[["status"]], 303L) &&
      is.character(location) &&
      length(location) == 1L &&
      grepl(
        "^\\?shinyOAuth_callback_error=ce1_[A-Za-z0-9_-]{43}#$",
        location
      )
  ) {
    clean <- as.list(req)
    clean[["REQUEST_METHOD"]] <- "GET"
    clean[["QUERY_STRING"]] <- sub("#$", "", sub("^\\?", "", location))
    return(handler(clean))
  }
  response
}

callback_rejection_request <- function(
  query = "",
  body = NULL,
  path = "/callback"
) {
  req <- list(
    REQUEST_METHOD = if (is.null(body)) "GET" else "POST",
    PATH_INFO = path,
    SCRIPT_NAME = "",
    QUERY_STRING = query,
    rook.url_scheme = "http",
    HTTP_HOST = "localhost:8100"
  )
  if (!is.null(body)) {
    req[["CONTENT_TYPE"]] <- "application/x-www-form-urlencoded"
    req[["CONTENT_LENGTH"]] <- as.character(nchar(body, type = "bytes"))
    req[["rook.input"]] <- list(read = function(n) charToRaw(body))
  }
  req
}
