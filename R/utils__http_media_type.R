#' Check a JSON response media type
#'
#' Accepts JSON and registered structured JSON subtypes, with optional media
#' type parameters. Used before parsing UserInfo and introspection bodies.
#' @param resp An httr2 response.
#' @return Whether the response declares a JSON media type.
#' @keywords internal
#' @noRd
response_has_json_media_type <- function(resp) {
  type <- tryCatch(httr2::resp_content_type(resp), error = function(...) NULL)
  is_valid_string(type) &&
    grepl("^application/(json|[a-z0-9!#$&^_.+-]+[+]json)$", tolower(type))
}
