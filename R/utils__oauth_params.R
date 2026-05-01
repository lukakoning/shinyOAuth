# This file contains small helpers that normalize or inspect OAuth parameter
# values before they are used in requests, claims enforcement, or provider
# validation.
# Use them to keep token auth style, PKCE, response-mode handling, and OIDC
# claims request parsing consistent across constructors and request builders.

# 1 OAuth parameter helpers ------------------------------------------------

## 1.1 Normalize protocol parameters --------------------------------------

#' Internal: normalize token endpoint auth style names
#'
#' Canonical runtime spelling uses `public` for secretless public-client token
#' requests. `none` is accepted as an alias to mirror OIDC discovery metadata.
#'
#' @keywords internal
#' @noRd
normalize_token_auth_style <- function(style) {
  if (!is.character(style) || length(style) != 1L || is.na(style)) {
    return(style)
  }

  normalized <- tolower(trimws(style))

  if (identical(normalized, "none")) {
    return("public")
  }

  if (
    normalized %in%
      c(
        "header",
        "body",
        "public",
        "tls_client_auth",
        "self_signed_tls_client_auth",
        "client_secret_jwt",
        "private_key_jwt"
      )
  ) {
    return(normalized)
  }

  style
}

#' Internal: normalize PKCE method names without silently accepting typos
#'
#' @keywords internal
#' @noRd
normalize_pkce_method <- function(pkce_method, default = NULL) {
  if (is.null(pkce_method)) {
    return(default)
  }

  if (
    is.character(pkce_method) && length(pkce_method) == 1L && is.na(pkce_method)
  ) {
    return(default)
  }

  if (!is.character(pkce_method) || length(pkce_method) != 1L) {
    return(pkce_method)
  }

  normalized <- trimws(pkce_method)
  if (identical(toupper(normalized), "S256")) {
    return("S256")
  }
  if (identical(tolower(normalized), "plain")) {
    return("plain")
  }

  pkce_method
}

# Inspect the configured authorization response_mode and reject unsupported
# values early.
# Used by provider validation and constructors. Input: extra_auth_params list.
# Output: list with index, resolved mode, and optional error.
inspect_auth_response_mode <- function(extra_auth_params) {
  out <- list(index = integer(0), mode = NULL, error = NULL)

  if (!is.list(extra_auth_params) || length(extra_auth_params) == 0) {
    return(out)
  }

  nms <- names(extra_auth_params)
  if (is.null(nms)) {
    return(out)
  }

  idx <- which(tolower(trimws(nms)) == "response_mode")
  if (!length(idx)) {
    return(out)
  }
  if (length(idx) > 1L) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode must be supplied at most once"
    )
    return(out)
  }

  out$index <- idx[[1]]
  raw_mode <- extra_auth_params[[out$index]]
  if (
    !is.character(raw_mode) ||
      length(raw_mode) != 1L ||
      is.na(raw_mode) ||
      !nzchar(trimws(raw_mode))
  ) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode must be a single non-empty string"
    )
    return(out)
  }

  mode <- tolower(trimws(raw_mode))
  if (!identical(mode, "query")) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$response_mode = ",
      sQuote(raw_mode),
      " is not supported. shinyOAuth only supports the default 'query' response mode because plain Shiny callback URLs do not accept POST form callbacks."
    )
    return(out)
  }

  out$mode <- mode
  out
}

## 1.2 Claims request parsing and enforcement -----------------------------

# Normalize the requested claims specification into a list.
# Used by the claims helpers below so they can treat JSON strings and R lists the same way.
# Input: client claims setting. Output: parsed list or NULL.
parse_claims_spec <- function(claims_spec) {
  if (is.null(claims_spec)) {
    return(NULL)
  }

  if (is.character(claims_spec)) {
    return(
      tryCatch(
        jsonlite::fromJSON(claims_spec, simplifyVector = FALSE),
        error = function(e) NULL
      )
    )
  }

  claims_spec
}

# Pull the requested claims for one response target.
# Used by the claims helpers to look only at `id_token` or `userinfo` rules.
# Input: full claims spec and target name. Output: claim-entry list for that target.
extract_target_claims <- function(claims_spec, target) {
  claims_spec <- parse_claims_spec(claims_spec)

  if (!is.list(claims_spec)) {
    return(list())
  }

  target_claims <- claims_spec[[target]]
  if (!is.list(target_claims) || length(target_claims) == 0) {
    return(list())
  }

  target_claims
}

# Find which requested claims were marked as essential.
# Used by validate_essential_claims() to decide which claims must be present.
# Input: claims spec and target name. Output: character vector of essential claim names.
extract_essential_claims <- function(claims_spec, target) {
  target_claims <- extract_target_claims(claims_spec, target)
  if (length(target_claims) == 0) {
    return(character(0))
  }

  essential_names <- character(0)
  for (nm in names(target_claims)) {
    entry <- target_claims[[nm]]
    # A claim is essential if it has a list value with essential = TRUE.
    # NULL entries (claim requested without parameters) are not essential.
    if (is.list(entry) && isTRUE(entry$essential)) {
      essential_names <- c(essential_names, nm)
    }
  }

  essential_names
}

# Collect the requested values for one claim entry.
# Used by extract_claim_value_constraints() when a client requested exact claim values.
# Input: one claim entry from the claims spec. Output: list of accepted values.
extract_requested_claim_values <- function(entry) {
  if (!is.list(entry) || length(entry) == 0) {
    return(list())
  }

  requested <- list()

  if ("value" %in% names(entry)) {
    requested <- c(requested, list(entry$value))
  }

  if ("values" %in% names(entry) && !is.null(entry$values)) {
    values <- entry$values
    if (is.list(values)) {
      value_names <- names(values)
      if (!is.null(value_names) && any(nzchar(value_names))) {
        requested <- c(requested, list(values))
      } else {
        requested <- c(requested, unname(values))
      }
    } else if (length(values) > 0) {
      requested <- c(requested, as.list(unname(values)))
    }
  }

  requested
}

# Build exact-value rules for claims on one target.
# Used by validate_essential_claims() when the client asked for specific values.
# Input: claims spec and target name. Output: named list of claim-to-value constraints.
extract_claim_value_constraints <- function(claims_spec, target) {
  target_claims <- extract_target_claims(claims_spec, target)
  if (length(target_claims) == 0) {
    return(list())
  }

  constraints <- list()
  for (nm in names(target_claims)) {
    requested <- extract_requested_claim_values(target_claims[[nm]])
    if (length(requested) > 0) {
      constraints[[nm]] <- requested
    }
  }

  constraints
}

# Check whether any target in the claims request creates enforceable work.
# Used by verify_token_set() to skip claim checks when nothing strict was requested.
# Input: full claims spec. Output: TRUE/FALSE.
claims_request_has_enforceable_requirements <- function(claims_spec) {
  targets <- c("id_token", "userinfo")

  any(vapply(
    targets,
    function(target) {
      claims_request_target_has_enforceable_requirements(claims_spec, target)
    },
    logical(1)
  ))
}

# Check whether one target in the claims request has enforceable rules.
# Used by claims_request_has_enforceable_requirements() and verify_token_set().
# Input: claims spec and target name. Output: TRUE/FALSE.
claims_request_target_has_enforceable_requirements <- function(
  claims_spec,
  target
) {
  length(extract_essential_claims(claims_spec, target)) > 0 ||
    length(extract_claim_value_constraints(claims_spec, target)) > 0
}

# Convert one claim value into a stable comparable string.
# Used by the value-matching helpers so nested lists, scalars, and arrays can be compared consistently.
# Input: one claim value. Output: canonical string form.
canonicalize_claim_value <- function(value) {
  encoded <- tryCatch(
    jsonlite::toJSON(
      value,
      auto_unbox = TRUE,
      null = "null",
      na = "null",
      digits = NA
    ),
    error = function(e) NULL
  )

  if (!is.null(encoded)) {
    return(as.character(encoded))
  }

  paste(
    utils::capture.output(utils::str(value, give.attr = FALSE)),
    collapse = " "
  )
}

# Check whether the actual claim value matches one of the requested values.
# Used by validate_essential_claims() when the client requested exact claim values.
# Input: actual value plus requested value list. Output: TRUE/FALSE.
claim_matches_requested_values <- function(actual, requested) {
  actual_value <- canonicalize_claim_value(actual)
  requested_values <- vapply(requested, canonicalize_claim_value, character(1))
  actual_value %in% requested_values
}

# Render requested claim values into a short human-readable message.
# Used by validate_essential_claims() when building error text for value mismatches.
# Input: requested value list. Output: one description string.
format_claim_value_expectation <- function(requested) {
  rendered <- vapply(requested, canonicalize_claim_value, character(1))
  if (length(rendered) == 1) {
    return(rendered[[1]])
  }

  paste0("one of ", paste(rendered, collapse = ", "))
}

# Check that the returned claims satisfy what the client asked for.
# Used by verify_token_set() for ID token claims and by userinfo validation code for userinfo claims.
# Input: client, decoded claims list, and target name. Output: invisible NULL on success or an error/warning.
validate_essential_claims <- function(client, claims_present, target) {
  mode <- client@claims_validation %||% "none"
  if (identical(mode, "none")) {
    return(invisible(NULL))
  }

  essential <- extract_essential_claims(client@claims, target)
  value_constraints <- extract_claim_value_constraints(client@claims, target)
  if (length(essential) == 0 && length(value_constraints) == 0) {
    return(invisible(NULL))
  }

  if (!is.list(claims_present) || length(claims_present) == 0) {
    present_names <- character(0)
  } else {
    present_names <- names(claims_present) %||% character(0)
  }

  missing_claims <- setdiff(essential, present_names)

  value_mismatches <- character(0)
  if (length(value_constraints) > 0) {
    for (claim_name in names(value_constraints)) {
      expected_values <- value_constraints[[claim_name]]

      if (!claim_name %in% present_names) {
        if (!claim_name %in% missing_claims) {
          value_mismatches <- c(
            value_mismatches,
            paste0(
              claim_name,
              " is missing (expected ",
              format_claim_value_expectation(expected_values),
              ")"
            )
          )
        }
        next
      }

      actual_value <- claims_present[[claim_name]]
      if (!claim_matches_requested_values(actual_value, expected_values)) {
        value_mismatches <- c(
          value_mismatches,
          paste0(
            claim_name,
            " expected ",
            format_claim_value_expectation(expected_values),
            " but got ",
            canonicalize_claim_value(actual_value)
          )
        )
      }
    }
  }

  if (length(missing_claims) == 0 && length(value_mismatches) == 0) {
    return(invisible(NULL))
  }

  target_label <- if (identical(target, "id_token")) "ID token" else "userinfo"
  msg_parts <- character(0)
  if (length(missing_claims) > 0) {
    msg_parts <- c(
      msg_parts,
      paste0(
        "Essential claims missing from ",
        target_label,
        " response (OIDC Core Section 5.5): ",
        paste(missing_claims, collapse = ", ")
      )
    )
  }
  if (length(value_mismatches) > 0) {
    msg_parts <- c(
      msg_parts,
      paste0(
        "Requested claim values not satisfied in ",
        target_label,
        " response (OIDC Core Section 5.5): ",
        paste(value_mismatches, collapse = "; ")
      )
    )
  }
  msg <- paste(msg_parts, collapse = ". ")

  guidance <- paste(
    "Set claims_validation = 'warn' or 'none' to allow unsatisfied claim requests"
  )

  if (identical(mode, "strict")) {
    if (identical(target, "id_token")) {
      err_id_token(c(
        "x" = msg,
        "i" = guidance
      ))
    } else {
      err_userinfo(c(
        "x" = msg,
        "i" = guidance
      ))
    }
  } else if (identical(mode, "warn")) {
    rlang::warn(
      c(
        "!" = msg,
        "i" = "Set claims_validation = 'none' to suppress this warning"
      ),
      .frequency = "once",
      .frequency_id = paste0("claims-validation-missing-", target)
    )
  }

  invisible(NULL)
}
