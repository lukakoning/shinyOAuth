# Read the owned test session's exchanges in memory, then return only counts and
# booleans. These additional driver assertions do not change Inferno's verifier.
inferno_session_requests <- function(stack, session) {
  results <- inferno_api(stack, paste0("/api/test_sessions/", session$id, "/results"))
  summaries <- unlist(lapply(results, function(result) result$requests), recursive = FALSE)
  ids <- unique(vapply(summaries, function(request) request$id, character(1)))
  requests <- lapply(ids, function(id) inferno_api(stack, paste0("/api/requests/", id)))
  requests[order(vapply(requests, function(request) request$index, numeric(1)))]
}

inferno_exchange_summary <- function(stack, session, registration, launch, authorization_method = "GET",
  requests = inferno_session_requests(stack, session)) {
  path <- function(request) httr2::url_parse(request$url)$path
  fhir_path <- httr2::url_parse(stack$fhir_base)$path
  prefix <- sub("/fhir$", "", fhir_path)
  auth <- Filter(function(request) identical(path(request), paste0(prefix, "/auth/authorization")), requests)
  tokens <- Filter(function(request) identical(path(request), paste0(prefix, "/auth/token")), requests)
  access <- Filter(function(request) startsWith(path(request), paste0(fhir_path, "/")), requests)
  stopifnot(length(auth) == 1L, toupper(auth[[1L]]$verb) == authorization_method)
  params <- lapply(tokens, function(request) shiny::parseQueryString(request$request_body))
  bodies <- lapply(tokens, function(request) jsonlite::fromJSON(request$response_body, simplifyVector = FALSE))
  narrow <- identical(registration$patient, "patient-a")
  stopifnot(length(tokens) == if (narrow) 3L else 2L,
    identical(params[[1L]]$grant_type, "authorization_code"),
    all(vapply(params[-1L], function(value) identical(value$grant_type, "refresh_token"), logical(1))),
    all(vapply(tokens, function(request) request$status == 200L && toupper(request$verb) == "POST", logical(1))))
  auth_params <- if (authorization_method == "GET") httr2::url_parse(auth[[1L]]$url)$query else
    shiny::parseQueryString(auth[[1L]]$request_body)
  stopifnot(identical(auth_params$aud, stack$fhir_base),
    identical(auth_params$code_challenge_method, "S256"),
    identical(!is.null(auth_params$launch), launch == "ehr"))
  scopes <- function(value) if (is.null(value)) character() else strsplit(value, " ", fixed = TRUE)[[1L]]
  limited <- c("patient/Patient.r", "user/Practitioner.r", "offline_access", "openid", "fhirUser")
  if (narrow) {
    stopifnot(all(vapply(params[-1L], function(value) setequal(scopes(value$scope), limited), logical(1))),
      all(vapply(bodies[-1L], function(value) setequal(scopes(value$scope), limited), logical(1))))
  } else {
    stopifnot(all(vapply(bodies, function(value) "patient/Patient.rs" %in% scopes(value$scope), logical(1))))
  }
  if (registration$style == "private_key_jwt") {
    algorithms <- vapply(params, function(value) {
      encoded <- strsplit(value$client_assertion, ".", fixed = TRUE)[[1L]][[1L]]
      header <- openssl::base64_decode(paste0(chartr("-_", "+/", encoded),
        strrep("=", (4L - nchar(encoded) %% 4L) %% 4L)))
      jsonlite::fromJSON(rawToChar(header))$alg
    }, character(1))
    stopifnot(all(algorithms == registration$algorithm))
  }
  patient_path <- paste0(fhir_path, "/Patient/", registration$patient)
  user_path <- paste0(fhir_path, "/Practitioner/", registration$practitioner)
  search_path <- paste0(fhir_path, "/Patient")
  count <- function(wanted) sum(vapply(access, function(request) identical(path(request), wanted), logical(1)))
  reads <- if (narrow) 5L else 2L
  searches <- if (narrow) 1L else 2L
  stopifnot(count(patient_path) == reads, count(user_path) == reads,
    count(search_path) == searches, length(access) == 2L * reads + searches)
  # Verify each successful read used the most recently issued access token from
  # this session, and every code/refresh response was followed by both reads.
  token_index <- vapply(tokens, function(request) request$index, numeric(1))
  for (request in access) {
    previous <- which(token_index < request$index)
    stopifnot(length(previous) > 0L, request$status == 200L, toupper(request$verb) == "GET")
    current <- bodies[[tail(previous, 1L)]]$access_token
    headers <- Filter(function(header) identical(tolower(header$name), "authorization"), request$request_headers)
    stopifnot(length(headers) == 1L, identical(headers[[1L]]$value, paste("Bearer", current)))
  }
  for (index in seq_along(tokens)) {
    end <- if (index < length(tokens)) token_index[[index + 1L]] else Inf
    following <- Filter(function(request) request$index > token_index[[index]] && request$index < end, access)
    stopifnot(all(c(patient_path, user_path) %in% vapply(following, path, character(1))))
  }
  list(authorization_requests = length(auth), code_exchanges = 1L, refresh_requests = length(tokens) - 1L,
    patient_reads = reads, fhir_user_reads = reads, search_requests = searches,
    every_issued_token_used_for_patient_and_user = TRUE,
    explicit_narrowing_preserved = narrow, untouched_grant_kept_search = !narrow)
}
