#' Validate understood optional OIDC claim types across response channels
#'
#' Checks only present claims, preserving the parser's JSON array distinctions.
#' @param claims Claims parsed without simplifying JSON arrays.
#' @param error Typed condition constructor for the response channel.
#' @param source Stable response name used in condition messages.
#' @return Invisibly returns `TRUE`, or raises a typed validation error.
#' @keywords internal
#' @noRd
validate_oidc_standard_claim_types <- function(claims, error, source) {
  scalar_string <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value)
  }
  for (field in c("email_verified", "phone_number_verified", "acr", "amr")) {
    if (!field %in% names(claims)) next
    value <- claims[[field]]
    valid <- switch(field,
      acr = scalar_string(value),
      amr = is.list(value) && is.null(names(value)) &&
        all(vapply(value, scalar_string, logical(1))),
      is.logical(value) && length(value) == 1L && !is.na(value)
    )
    if (!valid) {
      shape <- switch(field,
        acr = "a JSON string",
        amr = "a JSON array of strings",
        "a JSON Boolean"
      )
      error(paste0(source, " '", field, "' must be ", shape))
    }
  }
  invisible(TRUE)
}
