# Resolve an additive transport policy without changing requests or runtime
# state. Curl encodes the minimum in the low 16 bits and maximum in the high
# 16 bits of sslversion. NULL retains the linked backend's existing defaults.
resolve_tls_policy <- function(
  minimum = getOption("shinyOAuth.tls_min_version", NULL),
  request_options = list()
) {
  problem <- NULL
  if (
    !is.null(minimum) &&
      !(is_valid_string(minimum) && minimum %in% c("1.2", "1.3"))
  ) {
    problem <- "shinyOAuth.tls_min_version must be NULL, '1.2' or '1.3'"
  }
  version <- request_options$sslversion
  peer <- request_options$ssl_verifypeer
  host <- request_options$ssl_verifyhost
  verification <- (is.null(peer) ||
    identical(peer, TRUE) ||
    isTRUE(peer == 1)) &&
    (is.null(host) || isTRUE(host == 2))
  if (!is.null(problem) || is.null(minimum)) {
    return(list(
      problem = problem,
      minimum = minimum,
      sslversion = version,
      verification = verification
    ))
  }
  if (!verification) {
    return(list(
      problem = "Explicit TLS policy requires certificate and hostname verification"
    ))
  }
  value <- version %||% 0L
  if (
    !is.numeric(value) ||
      length(value) != 1L ||
      is.na(value) ||
      !is.finite(value) ||
      value != floor(value) ||
      value < 0 ||
      value > .Machine$integer.max
  ) {
    return(list(
      problem = "Supplied TLS version constraints cannot be resolved"
    ))
  }
  low <- bitwAnd(as.integer(value), 65535L)
  high <- bitwShiftR(as.integer(value), 16L)
  if (!low %in% c(0L, 1L, 4:7) || !high %in% c(0L, 1L, 4:7)) {
    return(list(problem = "Supplied TLS version constraints are unsupported"))
  }
  low <- max(low, if (minimum == "1.3") 7L else 6L)
  if (high > 1L && high < low) {
    return(list(
      problem = "Supplied TLS maximum conflicts with the required minimum"
    ))
  }
  list(
    problem = NULL,
    minimum = if (low == 7L) "1.3" else "1.2",
    sslversion = bitwOr(low, bitwShiftL(high, 16L)),
    verification = TRUE
  )
}

req_apply_tls_policy <- function(req) {
  if (!inherits(req, "httr2_request")) {
    return(req)
  }
  policy <- resolve_tls_policy(request_options = req$options %||% list())
  if (!is.null(policy$problem)) {
    err_config(policy$problem)
  }
  if (
    is.null(policy$minimum) || !grepl("^https://", req$url, ignore.case = TRUE)
  ) {
    return(req)
  }
  runtime <- curl::curl_version()
  # Older wolfSSL curl integrations interpreted minima as exact versions.
  if (
    grepl("wolfSSL", runtime$ssl_version, ignore.case = TRUE) &&
      utils::compareVersion(runtime$version, "8.10.0") < 0L
  ) {
    err_config(
      "Explicit TLS minima require libcurl 8.10.0 or later with wolfSSL"
    )
  }
  httr2::req_options(req, sslversion = policy$sslversion)
}

configured_tls_minimum <- function() {
  policy <- resolve_tls_policy()
  if (!is.null(policy$problem)) {
    err_config(policy$problem)
  }
  policy$minimum
}
