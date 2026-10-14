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
  string_fields <- c(
    "name", "given_name", "family_name", "middle_name", "nickname",
    "preferred_username", "profile", "picture", "website", "email", "gender",
    "birthdate", "zoneinfo", "locale", "phone_number", "acr"
  )
  address_fields <- c(
    "formatted", "street_address", "locality", "region", "postal_code", "country"
  )
  for (field in c(string_fields, "email_verified", "phone_number_verified",
    "amr", "updated_at", "address")) {
    if (!field %in% names(claims)) {
      next
    }
    value <- claims[[field]]
    valid <- if (field %in% string_fields) {
      scalar_string(value)
    } else switch(
      field,
      amr = is.list(value) &&
        is.null(names(value)) &&
        all(vapply(value, scalar_string, logical(1))),
      updated_at = is.numeric(value) && length(value) == 1L && is.finite(value),
      address = is.list(value) && !is.null(names(value)) && !is.data.frame(value),
      is.logical(value) && length(value) == 1L && !is.na(value)
    )
    if (!valid) {
      shape <- if (field %in% string_fields) "a JSON string" else switch(
        field,
        amr = "a JSON array of strings",
        updated_at = "a finite JSON number",
        address = "a JSON object",
        "a JSON Boolean"
      )
      error(paste0(source, " '", field, "' must be ", shape))
    }
    if (field == "address") {
      for (member in intersect(address_fields, names(value))) {
        if (!scalar_string(value[[member]])) {
          error(paste0(source, " 'address.", member, "' must be a JSON string"))
        }
      }
    }
  }
  invisible(TRUE)
}
