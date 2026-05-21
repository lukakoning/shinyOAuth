# This file contains small helpers that normalize or inspect OAuth parameter
# values before they are used in requests or validation
# Used for keeping common protocol parameters consistent across constructors,
# request builders, and validators

# 1 OAuth parameter helpers ----------------------------------------------------

## 1.1 Normalize protocol parameters -------------------------------------------

#' Internal: normalize token endpoint auth style names
#'
#' Canonical runtime spelling uses `public` for secretless public-client token
#' requests. `none` is accepted as an alias to mirror OIDC discovery metadata,
#' and is normalized to `public`. Used by provider constructors and request
#' builders.
#'
#' @param style Token-endpoint authentication style.
#' @return Normalized token-auth style string, or the original input when it is
#'   not recognized.
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
#' Used by provider validation and request-building helpers.
#'
#' @param pkce_method PKCE method value to normalize.
#' @param default Fallback value used for `NULL` or `NA` inputs.
#' @return Normalized PKCE method string, or the original input when it is not
#'   recognized.
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

#' Resolve an authorization response mode value
#'
#' Used by provider validation, client validation, and request-building helpers.
#'
#' @param raw_mode Candidate response mode value.
#' @param arg Label used in validation errors.
#' @param context Prefix used in validation errors.
#' @return A list containing the normalized mode and optional error text.
#' @keywords internal
#' @noRd
resolve_auth_response_mode <- function(
  raw_mode,
  arg = "response_mode",
  context = "OAuthClient"
) {
  out <- list(mode = NULL, error = NULL)

  if (is.null(raw_mode)) {
    return(out)
  }

  if (is.character(raw_mode) && length(raw_mode) == 1L && is.na(raw_mode)) {
    return(out)
  }

  if (
    !is.character(raw_mode) ||
      length(raw_mode) != 1L ||
      !nzchar(trimws(raw_mode))
  ) {
    out$error <- paste0(
      context,
      ": ",
      arg,
      " must be NULL or a single non-empty string"
    )
    return(out)
  }

  mode <- tolower(trimws(raw_mode))
  if (!mode %in% c("query", "form_post")) {
    jarm_modes <- c("jwt", "query.jwt", "fragment.jwt", "form_post.jwt")
    if (mode %in% jarm_modes) {
      out$error <- paste0(
        context,
        ": ",
        arg,
        " = ",
        sQuote(raw_mode),
        " is a JWT Secured Authorization Response Mode (JARM) value, ",
        "which shinyOAuth does not currently support. shinyOAuth supports ",
        "plain 'query' and 'form_post' response modes for authorization-code ",
        "callbacks."
      )
    } else {
      out$error <- paste0(
        context,
        ": ",
        arg,
        " = ",
        sQuote(raw_mode),
        " is not supported. shinyOAuth supports plain 'query' and ",
        "'form_post' response modes for authorization-code callbacks."
      )
    }
    return(out)
  }

  out$mode <- mode
  out
}

#' Inspect the configured authorization response mode
#'
#' Used by provider validation and constructors.
#'
#' @param extra_auth_params Provider `extra_auth_params` list.
#' @return A list containing the matched index, resolved mode, and optional
#'   error text.
#' @keywords internal
#' @noRd
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
  resolved <- resolve_auth_response_mode(
    extra_auth_params[[out$index]],
    arg = "extra_auth_params$response_mode",
    context = "OAuthProvider"
  )
  out$mode <- resolved$mode
  out$error <- resolved$error
  out
}

#' Resolve the effective OAuthClient authorization response mode
#'
#' Merges the client-level `response_mode` with any provider
#' `extra_auth_params$response_mode`, validates conflicts against advertised
#' provider support, and strips the provider-level `response_mode` from the
#' returned auth params so request builders can add it exactly once when
#' explicitly configured.
#'
#' @param oauth_client [OAuthClient] object.
#' @param default_mode Fallback response mode when neither client nor provider
#'   config sets one.
#' @return A list containing the effective mode, explicit mode (or `NULL`),
#'   cleaned provider auth params, and optional error text.
#' @keywords internal
#' @noRd
resolve_oauth_client_response_mode <- function(
  oauth_client,
  default_mode = "query"
) {
  S7::check_is_S7(oauth_client, class = OAuthClient)

  extra_auth_params <- oauth_client@provider@extra_auth_params
  out <- list(
    mode = default_mode,
    explicit_mode = NULL,
    extra_auth_params = extra_auth_params,
    error = NULL
  )

  client_response_mode_info <- resolve_auth_response_mode(
    oauth_client@response_mode %||% NA_character_,
    arg = "response_mode",
    context = "OAuthClient"
  )
  if (!is.null(client_response_mode_info$error)) {
    out$error <- client_response_mode_info$error
    return(out)
  }

  provider_response_mode_info <- inspect_auth_response_mode(extra_auth_params)
  if (!is.null(provider_response_mode_info$error)) {
    out$error <- provider_response_mode_info$error
    return(out)
  }

  if (
    !is.null(client_response_mode_info$mode) &&
      !is.null(provider_response_mode_info$mode) &&
      !identical(
        client_response_mode_info$mode,
        provider_response_mode_info$mode
      )
  ) {
    out$error <- paste0(
      "OAuthClient: response_mode = ",
      sQuote(client_response_mode_info$mode),
      " conflicts with OAuthProvider.extra_auth_params$response_mode = ",
      sQuote(provider_response_mode_info$mode),
      ". Configure response_mode on the client or provider extra_auth_params, not both."
    )
    return(out)
  }

  out$explicit_mode <- client_response_mode_info$mode %||%
    provider_response_mode_info$mode
  out$mode <- out$explicit_mode %||% default_mode

  if (length(provider_response_mode_info$index) == 1L) {
    extra_auth_params[[provider_response_mode_info$index]] <- NULL
  }
  out$extra_auth_params <- extra_auth_params

  if (
    !is.null(out$mode) &&
      length(oauth_client@provider@response_modes_supported) > 0 &&
      !out$mode %in% oauth_client@provider@response_modes_supported
  ) {
    out$error <- paste0(
      "OAuthClient: response_mode = ",
      sQuote(out$mode),
      " is not advertised in provider response_modes_supported"
    )
    return(out)
  }

  out
}

#' Inspect the configured OIDC max_age authorization parameter
#'
#' Used by provider validation, login-time ID token checks, and telemetry.
#'
#' @param extra_auth_params Provider `extra_auth_params` list.
#' @return A list containing the matched index, normalized numeric value, and
#'   optional error text.
#' @keywords internal
#' @noRd
inspect_auth_max_age <- function(extra_auth_params) {
  out <- list(index = integer(0), value = NULL, error = NULL)

  if (!is.list(extra_auth_params) || length(extra_auth_params) == 0) {
    return(out)
  }

  nms <- names(extra_auth_params)
  if (is.null(nms)) {
    return(out)
  }

  idx <- which(tolower(trimws(nms)) == "max_age")
  if (!length(idx)) {
    return(out)
  }
  if (length(idx) > 1L) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$max_age must be supplied at most once"
    )
    return(out)
  }

  out$index <- idx[[1]]
  raw_max_age <- extra_auth_params[[out$index]]
  if (length(raw_max_age) != 1L) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$max_age must be a single non-negative number of seconds"
    )
    return(out)
  }

  max_age <- suppressWarnings(as.numeric(raw_max_age[[1]]))
  if (
    length(max_age) != 1L ||
      is.na(max_age) ||
      !is.finite(max_age) ||
      max_age < 0
  ) {
    out$error <- paste0(
      "OAuthProvider: extra_auth_params$max_age must be a single non-negative number of seconds"
    )
    return(out)
  }

  out$value <- as.numeric(max_age)
  out
}

## 1.2 Claims request parsing and enforcement ----------------------------------

#' Normalize a claims specification
#'
#' Used by the claims helpers below so JSON strings and R lists can be handled
#' the same way.
#'
#' @param claims_spec Client claims setting.
#' @return Parsed claims list, or `NULL`.
#' @keywords internal
#' @noRd
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

#' Extract claims for one target
#'
#' Used by claims helpers that focus on one target such as `id_token` or
#' `userinfo`.
#'
#' @param claims_spec Full claims specification.
#' @param target Target name, such as `"id_token"` or `"userinfo"`.
#' @return Claim-entry list for the requested target.
#' @keywords internal
#' @noRd
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

#' Extract essential claim names
#'
#' Used by `validate_essential_claims()` when deciding which claims must be
#' present.
#'
#' @param claims_spec Full claims specification.
#' @param target Target name.
#' @return Character vector of essential claim names.
#' @keywords internal
#' @noRd
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

#' Extract requested values from one claim entry
#'
#' Used by `extract_claim_value_constraints()` when exact values were requested.
#'
#' @param entry One claim entry from the claims specification.
#' @return List of accepted values.
#' @keywords internal
#' @noRd
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

#' Extract claim value constraints
#'
#' Used by `validate_essential_claims()` when the client asked for specific
#' claim values.
#'
#' @param claims_spec Full claims specification.
#' @param target Target name.
#' @return Named list mapping claim names to requested values.
#' @keywords internal
#' @noRd
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

#' Check whether a claims request has enforceable requirements
#'
#' Used by `verify_token_set()` to skip claim checks when nothing strict was
#' requested.
#'
#' @param claims_spec Full claims specification.
#' @return `TRUE` when any supported target has essential claims or exact-value
#'   constraints; otherwise `FALSE`.
#' @keywords internal
#' @noRd
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

#' Check whether one claims target has enforceable requirements
#'
#' Used by `claims_request_has_enforceable_requirements()` and
#' `verify_token_set()`.
#'
#' @param claims_spec Full claims specification.
#' @param target Target name.
#' @return `TRUE` when the target has essential claims or exact-value
#'   constraints; otherwise `FALSE`.
#' @keywords internal
#' @noRd
claims_request_target_has_enforceable_requirements <- function(
  claims_spec,
  target
) {
  length(extract_essential_claims(claims_spec, target)) > 0 ||
    length(extract_claim_value_constraints(claims_spec, target)) > 0
}

#' Canonicalize a claim value
#'
#' Used by claim value-matching helpers so scalars, arrays, and nested values
#' compare consistently.
#'
#' @param value Claim value to normalize.
#' @return Canonical string representation suitable for comparisons.
#' @keywords internal
#' @noRd
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

#' Check whether a claim value matches requested values
#'
#' Used by `validate_essential_claims()` when exact claim values were
#' requested.
#'
#' @param actual Actual claim value returned by the provider.
#' @param requested Requested value list.
#' @return `TRUE` when the actual value matches one requested value; otherwise
#'   `FALSE`.
#' @keywords internal
#' @noRd
claim_matches_requested_values <- function(actual, requested) {
  actual_value <- canonicalize_claim_value(actual)
  requested_values <- vapply(requested, canonicalize_claim_value, character(1))
  actual_value %in% requested_values
}

#' Format a claim value expectation
#'
#' Used by `validate_essential_claims()` when it builds mismatch messages.
#'
#' @param requested Requested value list.
#' @return One human-readable expectation string.
#' @keywords internal
#' @noRd
format_claim_value_expectation <- function(requested) {
  rendered <- vapply(requested, canonicalize_claim_value, character(1))
  if (length(rendered) == 1) {
    return(rendered[[1]])
  }

  paste0("one of ", paste(rendered, collapse = ", "))
}

#' Validate requested claims against returned claims
#'
#' Used by `verify_token_set()` for ID token claims and by UserInfo validation
#' for UserInfo claims.
#'
#' @param client OAuth client carrying claims and claims-validation settings.
#' @param claims_present Decoded claims list returned by the provider.
#' @param target Target name being validated.
#' @return Invisibly returns `NULL` on success. Otherwise this function warns or
#'   raises an error depending on the validation mode.
#' @keywords internal
#' @noRd
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
    warn_pkg(
      "Requested claims could not be validated",
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
