#' Encode and validate an OIDC claims request
#'
#' Used by client validation and authorization construction so local enforcement
#' reads the same unambiguous request that is sent to the provider. Implements
#' the request structure in OpenID Connect Core sections 5.5 and 5.5.1.
#'
#' @param claims A named R list or pre-encoded JSON object.
#' @return Validated JSON text, or `NULL` for an absent request.
#' @keywords internal
#' @noRd
claims_request_json <- function(claims) {
  if (is.null(claims)) {
    return(NULL)
  }
  if (is.list(claims)) {
    check_names <- function(node, depth = 0L) {
      if (!is.list(node)) {
        return(invisible(NULL))
      }
      if (depth > 64L) {
        err_config("claims exceeds the maximum nesting depth")
      }
      nms <- names(node)
      if (
        !is.null(nms) && (anyNA(nms) || !all(nzchar(nms)) || anyDuplicated(nms))
      ) {
        err_config("claims object members must have unique, non-empty names")
      }
      for (child in node) {
        check_names(child, depth + 1L)
      }
      invisible(NULL)
    }
    check_names(claims)
    if (length(claims) == 0L) {
      names(claims) <- character()
    }
    for (target in intersect(c("id_token", "userinfo"), names(claims))) {
      section <- claims[[target]]
      if (!is.list(section)) {
        next
      }
      if (length(section) == 0L) {
        names(section) <- character()
      }
      for (name in names(section)) {
        entry <- section[[name]]
        if (!is.list(entry)) {
          next
        }
        if (length(entry) == 0L) {
          names(entry) <- character()
        }
        if (
          "values" %in%
            names(entry) &&
            is.atomic(entry[["values"]]) &&
            !is.null(entry[["values"]])
        ) {
          # OIDC requires an array even for a single acceptable value.
          entry[["values"]] <- I(unname(entry[["values"]]))
        }
        section[[name]] <- entry
      }
      claims[[target]] <- section
    }
    claims <- as.character(jsonlite::toJSON(
      claims,
      auto_unbox = TRUE,
      null = "null"
    ))
  } else if (!is_valid_string(claims)) {
    err_config(
      "claims must be NULL, a named list, or a single non-empty JSON string"
    )
  }
  claims <- as.character(claims)
  if (!isTRUE(jsonlite::validate(claims))) {
    err_config("claims must be valid JSON")
  }
  assert_json_text_is_object(claims, "claims", signal_error = err_config)
  reject_duplicate_json_object_members(claims, "claims", on_error = err_config)
  parsed <- jsonlite::fromJSON(claims, simplifyVector = FALSE)
  is_object <- function(value) is.list(value) && !is.null(names(value))
  for (target in intersect(c("id_token", "userinfo"), names(parsed))) {
    section <- parsed[[target]]
    if (!is_object(section)) {
      err_config(paste0("claims ", target, " must be a JSON object"))
    }
    for (name in names(section)) {
      entry <- section[[name]]
      if (is.null(entry)) {
        next
      }
      if (!is_object(entry)) {
        err_config(paste0(
          "claims ",
          target,
          " entries must be null or JSON objects"
        ))
      }
      if ("essential" %in% names(entry)) {
        essential <- entry[["essential"]]
        if (
          !is.logical(essential) || length(essential) != 1L || is.na(essential)
        ) {
          err_config("claims essential must be a JSON Boolean")
        }
      }
      if (all(c("value", "values") %in% names(entry))) {
        err_config("claims entries must use either value or values, not both")
      }
      if ("values" %in% names(entry)) {
        values <- entry[["values"]]
        if (!is.list(values) || !is.null(names(values)) || !length(values)) {
          err_config("claims values must be a non-empty JSON array")
        }
      }
      requested <- extract_requested_claim_values(entry)
      for (value in requested) {
        validate_oidc_standard_claim_types(
          stats::setNames(list(value), name),
          err_config,
          "Claims request"
        )
      }
    }
  }
  as.character(claims)
}
