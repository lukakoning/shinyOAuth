#' Read a connection's current SMART context
#'
#' Return interpreted patient/encounter and validated user references for the
#' current accepted token. This is sensitive data; keep it out of general status
#' tables and logs. Raw token extensions remain available separately on tokens.
#'
#' @param connection An [OAuthConnection] for a [smart_client()], accessed in
#'   its owning Shiny session.
#' @return `smart_context()` returns a list with `version`, `fhir_base`, `revision`,
#'   `changed`, `patient`, `encounter`, `fhirUser` and `need_patient_banner`.
#'   Absent values are `NULL`. `revision` increases when interpreted context
#'   changes; key patient-dependent application data by connection ID and this
#'   revision. Refresh omission carries context forward, except that a changed
#'   or cleared patient clears an omitted encounter. Explicit null clears a
#'   field, unless patient access still requires patient context. An initial
#'   launch query never establishes this context.
#' @details
#' `smart_patient()` fetches the contextual Patient only when the current grant
#' covers `patient/Patient.r` or `user/Patient.r`. `smart_fhir_user()` fetches the
#' identity reference only from a validated ID token. It accepts `openid fhirUser`,
#' a matching user read scope, or patient read permission when the identity is
#' the contextual Patient. Both stay inside the FHIR base and refuse redirects.
#' A foreign `fhirUser` reference is reported as context but is never fetched
#' with this connection's token. FHIR search, write, batch and pagination helpers
#' are outside these two convenience methods.
#'
#' Patient IDs and user identity are different: the first identifies a chart,
#' the second the authenticated user. Neither changes the local connection owner.
#' General summaries omit all of this data. The application remains responsible
#' for displaying patient identity clearly and discarding data from an older
#' context revision. Experimental `fhirContext` and styling extensions remain
#' raw data and are not automatically fetched or interpreted.
#' @seealso [smart_client()], [OAuthConnection]
#' @export
smart_context <- function(connection) {
  if (!inherits(connection, "OAuthConnection")) err_input("Expected an OAuthConnection")
  connection$smart_context()
}

#' @rdname smart_context
#' @return `smart_patient()` and `smart_fhir_user()` return an [httr2] response.
#' @export
smart_patient <- function(connection) {
  if (!inherits(connection, "OAuthConnection")) err_input("Expected an OAuthConnection")
  connection$smart_resource("patient")
}

#' @rdname smart_context
#' @export
smart_fhir_user <- function(connection) {
  if (!inherits(connection, "OAuthConnection")) err_input("Expected an OAuthConnection")
  connection$smart_resource("fhirUser")
}

smart_update_token_context <- function(client, token, previous = NULL) {
  if (!client_uses_smart(client)) return(token)
  prior <- if (is.null(previous)) NULL else previous@smart_context
  if (!is.null(previous) && (!identical(prior$version, 1L) ||
      !identical(prior$fhir_base, client@smart$fhir_base))) {
    err_token("SMART refresh requires the original interpreted context")
  }
  values <- list(patient = NULL, encounter = NULL, fhirUser = NULL,
    need_patient_banner = NULL)
  for (name in names(values)) {
    if (!is.null(prior)) values[name] <- prior[name]
  }
  for (name in c("patient", "encounter")) {
    if (!name %in% names(token@extra_fields)) next
    value <- token@extra_fields[[name]]
    if (!is.null(value) && (!is_valid_string(value) ||
        !grepl("^[A-Za-z0-9.-]{1,64}$", value))) {
      err_token("SMART context contains an invalid FHIR resource ID")
    }
    values[name] <- list(value)
  }
  if (!is.null(prior) && !identical(values$patient, prior$patient) &&
      !"encounter" %in% names(token@extra_fields)) {
    values["encounter"] <- list(NULL)
  }
  if ("need_patient_banner" %in% names(token@extra_fields)) {
    value <- token@extra_fields$need_patient_banner
    if (!is.null(value) && (!is.logical(value) || length(value) != 1L || is.na(value))) {
      err_token("SMART need_patient_banner must be a boolean or null")
    }
    values["need_patient_banner"] <- list(value)
  }
  if (any(startsWith(token@granted_scopes, "patient/")) && is.null(values$patient)) {
    err_token("SMART patient permissions require patient context")
  }
  if (identical(client@smart$identity, "fhirUser")) {
    if (!isTRUE(token@id_token_validated)) err_token("SMART identity has not been validated")
    reference <- token@id_token_claims$fhirUser
    if (!is_valid_string(reference)) err_token("SMART identity requires fhirUser")
    if (!is.null(prior$fhirUser) && !identical(prior$fhirUser, reference)) {
      err_token("SMART fhirUser changed; a fresh authorization is required")
    }
    values$fhirUser <- reference
  }
  changed <- !is.null(prior) && !identical(values, prior[names(values)])
  token@smart_context <- c(list(version = 1L, fhir_base = client@smart$fhir_base,
    revision = if (is.null(prior)) 1L else prior$revision + as.integer(changed),
    changed = changed), values)
  token
}

smart_record_context <- function(record) {
  if (!client_uses_smart(record$client) ||
      !connection_record_status(record) %in% c("active", "limited") ||
      !identical(record$token@smart_context$version, 1L) ||
      !identical(record$token@smart_context$fhir_base, record$client@smart$fhir_base)) {
    err_token("SMART context is unavailable")
  }
  record$token@smart_context
}

smart_record_resource <- function(record, kind) {
  context <- smart_record_context(record)
  if (identical(kind, "patient")) {
    if (!is_valid_string(context$patient)) err_token("No SMART patient is in context")
    path <- paste0("Patient/", context$patient)
    candidates <- list("patient/Patient.r", "user/Patient.r")
  } else if (identical(kind, "fhirUser")) {
    if (!is_valid_string(context$fhirUser) || !isTRUE(record$token@id_token_validated)) {
      err_token("No validated SMART fhirUser is available")
    }
    path <- tryCatch(resolve_bound_resource(record$client@resource_bases[["fhir"]],
      context$fhirUser), error = function(...) err_token("SMART fhirUser is outside this connection's FHIR base"))
    base_path <- resource_binding_components(record$client@resource_bases[["fhir"]])$path
    relative <- substring(resource_binding_components(path)$path,
      nchar(paste0(sub("/$", "", base_path), "/")) + 1L)
    candidates <- list()
    if (identical(record$client@smart$identity, "fhirUser")) {
      candidates <- list(c("openid", "fhirUser"))
    }
    # Absolute FHIR references need not use a REST-style resource path.
    if (grepl("^[A-Z][A-Za-z0-9]*/[A-Za-z0-9.-]{1,64}$", relative)) {
      candidates <- c(candidates, list(paste0("user/", sub("/.*$", "", relative), ".r")))
    }
    if (is_valid_string(context$patient) &&
        identical(relative, paste0("Patient/", context$patient))) {
      candidates <- c(candidates, list("patient/Patient.r"))
    }
  } else err_input("Unknown SMART resource helper")
  usable <- vapply(candidates, function(scope) {
    identical(client_scope_coverage(record$client, scope,
      effective_client_scopes(record$client))$status, "covered") &&
      identical(client_scope_coverage(record$client, scope,
        record$token@granted_scopes)$status, "covered")
  }, logical(1))
  if (!any(usable)) err_token("SMART grant does not cover this resource read")
  connection_record_request(record, "fhir", path, NULL, "GET", candidates[[which(usable)[1L]]])
}
