# This selection uses the native OP's absent HTTP freshness headers and the
# package's unchanged default cache_mem(max_age = 3600). It does not prove an
# origin-advertised max-age, browser cookie binding, or worker cache sharing.
rotation_require <- function(ok, message) {
  if (!isTRUE(ok)) {
    stop(message, call. = FALSE)
  }
  invisible(TRUE)
}

rotation_hash <- function(value) {
  paste(openssl::sha256(serialize(value, NULL, version = 3)), collapse = "")
}

rotation_snapshot <- function(cache, key) {
  entry <- cache[["get"]](key, missing = NULL)
  if (is.null(entry)) {
    return(NULL)
  }
  now <- as.numeric(Sys.time())
  list(
    entry_hash = rotation_hash(entry),
    fetched_at = entry[["fetched_at"]],
    observed_at = now,
    usable = is.list(entry[["jwks"]]) && now < entry[["fresh_until"]],
    origin_freshness_unbounded = identical(entry[["fresh_until"]], Inf),
    kids = unname(lapply(entry[["jwks"]][["keys"]], `[[`, "kid")),
    jwks_uri = entry[["jwks_uri"]],
    discovery_issuer = entry[["discovery_issuer"]]
  )
}

rotation_restart <- function(stack) {
  details <- jsonlite::fromJSON(
    openid_docker(c("inspect", stack[["container"]])),
    simplifyVector = FALSE
  )[[1L]]
  rotation_require(
    identical(
      details[["Config"]][["Labels"]][["shinyoauth.oidc-provider.run_id"]],
      stack[["run_id"]]
    ),
    "Refusing to restart an unrelated provider container"
  )
  openid_docker(
    c("logs", stack[["container"]]),
    file.path(stack[["output"]], "provider-before-rotation.log")
  )
  openid_docker(c("restart", stack[["container"]]))
  info <- openid_wait(
    function() {
      tryCatch(
        interop_request(stack, "/api/server"),
        httr2_error = function(...) NULL
      )
    },
    "Restarted native provider readiness",
    30
  )
  rotation_require(
    isTRUE(info[["ready"]]) &&
      identical(info[["version"]], stack[["lock"]][["provider_version"]]) &&
      identical(info[["node_version"]], stack[["lock"]][["node_version"]]),
    "Restarted provider runtime mismatch"
  )
  invisible(NULL)
}

rotation_authorize <- function(url, stack, redirect_uri) {
  cookies <- tempfile("rotation-cookies-")
  on.exit(unlink(cookies), add = TRUE)
  method <- "GET"
  for (hop in seq_len(30L)) {
    rotation_require(
      startsWith(url, paste0(stack[["origin"]], "/")),
      "Authorization left the trusted provider"
    )
    req <- httr2::request(url) |>
      httr2::req_options(
        cainfo = stack[["ca"]],
        proxy = "",
        followlocation = FALSE
      ) |>
      httr2::req_cookie_preserve(cookies) |>
      httr2::req_timeout(10)
    if (identical(method, "POST")) {
      req <- req |>
        httr2::req_body_raw(raw(), "application/x-www-form-urlencoded") |>
        httr2::req_headers(Origin = stack[["origin"]])
    }
    response <- httr2::req_perform(req)
    status <- httr2::resp_status(response)
    if (status %in% c(302L, 303L)) {
      target <- xml2::url_absolute(
        httr2::resp_header(response, "location"),
        url
      )
      # Never request the app callback with this protocol-only HTTP driver.
      if (startsWith(target, paste0(redirect_uri, "?"))) {
        return(target)
      }
      url <- target
      method <- "GET"
    } else {
      rotation_require(
        status == 200L &&
          grepl(
            "^/interaction/[A-Za-z0-9_-]+$",
            httr2::url_parse(url)[["path"]]
          ),
        "Unexpected provider authorization response"
      )
      document <- xml2::read_html(httr2::resp_body_string(response))
      forms <- xml2::xml_find_all(document, "//form")
      rotation_require(
        length(forms) == 1L &&
          identical(xml2::xml_attr(forms[[1L]], "method"), "post") &&
          length(xml2::xml_find_all(
            forms[[1L]],
            ".//button[@id='fixture-login' or @id='fixture-consent']"
          )) ==
            1L,
        "Unexpected native provider interaction form"
      )
      action <- xml2::xml_attr(forms[[1L]], "action")
      if (!is.na(action) && nzchar(action)) {
        url <- xml2::url_absolute(action, url)
      }
      method <- "POST"
    }
  }
  stop(
    "Native authorization did not reach the registered callback",
    call. = FALSE
  )
}

rotation_login <- function(client, stack) {
  result <- NULL
  shiny::testServer(
    shinyOAuth::oauth_module_server,
    args = list(
      id = "auth",
      client = client,
      auto_redirect = FALSE,
      indefinite_session = TRUE,
      async = FALSE
    ),
    expr = {
      rotation_require(
        !isTRUE(values[["authenticated"]]),
        "Module started authenticated"
      )
      auth_url <- values[["build_auth_url"]]()
      sent <- httr2::url_parse(auth_url)[["query"]]
      before <- client@state_store[["keys"]]()
      rotation_require(
        length(before) == 1L,
        "Required pending callback record was not created"
      )
      callback <- rotation_authorize(auth_url, stack, client@redirect_uri)
      received <- httr2::url_parse(callback)[["query"]]
      rotation_require(
        identical(received[["state"]], sent[["state"]]) &&
          is.character(received[["code"]]) &&
          nzchar(received[["code"]]),
        "Native code callback did not match the pending state"
      )
      values[[".process_query"]](
        paste0("?", sub("^[^?]*[?]", "", callback)),
        current_path = "/",
        current_uri = callback
      )
      session[["flushReact"]]()
      token <- values[["token"]]
      rotation_require(
        isTRUE(values[["authenticated"]]) &&
          is.null(values[["error"]]) &&
          !is.null(token) &&
          isTRUE(token@id_token_validated),
        "Native code login failed ID-token validation"
      )
      claims <- shinyOAuth:::parse_jwt_payload(token@id_token)
      result <<- list(
        proof = list(
          authenticated = TRUE,
          id_token_validated = TRUE,
          kid = shinyOAuth:::parse_jwt_header(token@id_token)[["kid"]],
          subject_matches = identical(claims[["sub"]], "local-test-account"),
          issuer_matches = identical(claims[["iss"]], stack[["origin"]]),
          audience_matches = identical(claims[["aud"]], client@client_id),
          state_matches = identical(received[["state"]], sent[["state"]]),
          pending_before = length(before),
          pending_after = length(client@state_store[["keys"]]())
        ),
        id_token = token@id_token
      )
    }
  )
  result
}

rotation_rogue <- function(client, id_token, kid, expected) {
  claims <- shinyOAuth:::parse_jwt_payload(id_token)
  claims[["iat"]] <- floor(as.numeric(Sys.time())) - 1
  claims[["exp"]] <- floor(as.numeric(Sys.time())) + 300
  rogue <- jose::jwt_encode_sig(
    do.call(jose::jwt_claim, as.list(claims)),
    key = openssl::rsa_keygen(bits = 2048),
    header = list(alg = "RS256", kid = kid, typ = "JWT")
  )
  error <- tryCatch(
    shinyOAuth:::validate_id_token(client, rogue),
    error = identity
  )
  rotation_require(
    inherits(error, "shinyOAuth_id_token_error") &&
      grepl(expected, conditionMessage(error)),
    "Rogue signature was not rejected at the expected boundary"
  )
  list(
    kid = kid,
    rejected = TRUE,
    error_class = "shinyOAuth_id_token_error",
    reason = if (identical(expected, "signature")) {
      "signature"
    } else {
      "unknown_kid"
    }
  )
}

rotation_check <- function(proof) {
  check <- function(ok) {
    rotation_require(ok, "Warm JWKS rotation proof failed validation")
  }
  finite_time <- function(value) {
    is.numeric(value) &&
      length(value) == 1L &&
      is.null(dim(value)) &&
      !is.na(value) &&
      is.finite(value)
  }
  hex <- function(value, digits) {
    is.character(value) &&
      length(value) == 1L &&
      is.null(dim(value)) &&
      !is.na(value) &&
      grepl(paste0("^[a-f0-9]{", digits, "}$"), value)
  }
  truth <- function(value, fields) {
    all(vapply(value[fields], isTRUE, logical(1))) &&
      all(fields %in% names(value))
  }
  entry_valid <- function(entry) {
    is.list(entry) &&
      hex(entry[["entry_hash"]], 64L) &&
      finite_time(entry[["fetched_at"]]) &&
      finite_time(entry[["observed_at"]]) &&
      entry[["observed_at"]] >= entry[["fetched_at"]] &&
      truth(entry, c("usable", "origin_freshness_unbounded"))
  }
  same_entry <- function(a, b) {
    entry_valid(a) &&
      entry_valid(b) &&
      identical(a[["entry_hash"]], b[["entry_hash"]]) &&
      identical(a[["fetched_at"]], b[["fetched_at"]])
  }
  check(
    identical(
      proof[["scope"]],
      "native_oidc_provider_warm_jwks_rotation_sync"
    ) &&
      is.numeric(proof[["backend_max_age"]]) &&
      length(proof[["backend_max_age"]]) == 1L &&
      proof[["backend_max_age"]] == 3600 &&
      identical(proof[["origin_freshness"]], "absent_default_backend_policy") &&
      truth(
        proof,
        c(
          "same_cache_identity",
          "same_issuer",
          "no_cache_configuration_override",
          "browser_cookie_check_bypassed",
          "no_browser_or_worker_credit"
        )
      )
  )
  issuer <- proof[["issuer"]]
  uri <- proof[["jwks_uri"]]
  check(
    is.character(issuer) &&
      length(issuer) == 1L &&
      grepl("^https://localhost:[0-9]+$", issuer) &&
      identical(uri, paste0(issuer, "/jwks"))
  )
  logins <- proof[["logins"]]
  check(length(logins) == 3L)
  for (login in logins) {
    check(
      truth(
        login,
        c(
          "authenticated",
          "id_token_validated",
          "subject_matches",
          "issuer_matches",
          "audience_matches",
          "state_matches"
        )
      ) &&
        identical(login[["pending_before"]], 1L) &&
        identical(login[["pending_after"]], 0L)
    )
  }
  before <- proof[["provider_before"]]
  restarted <- proof[["provider_after_restart"]]
  after <- proof[["provider_after"]]
  old <- before[["jwks_rotation"]][["active_kid"]]
  new <- after[["jwks_rotation"]][["active_kid"]]
  for (provider in list(before, restarted, after)) {
    check(hex(provider[["jwks_rotation"]][["instance_id"]], 32L))
  }
  check(
    hex(old, 32L) &&
      hex(new, 32L) &&
      hex(proof[["run_id"]], 32L) &&
      !identical(old, new) &&
      !identical(
        before[["jwks_rotation"]][["instance_id"]],
        after[["jwks_rotation"]][["instance_id"]]
      ) &&
      identical(before[["jwks_rotation"]][["issuer"]], issuer) &&
      identical(after[["jwks_rotation"]][["issuer"]], issuer) &&
      identical(restarted[["jwks_rotation"]], after[["jwks_rotation"]]) &&
      length(restarted[["events"]]) == 0L &&
      identical(before[["run_id"]], proof[["run_id"]]) &&
      identical(restarted[["run_id"]], proof[["run_id"]]) &&
      identical(after[["run_id"]], proof[["run_id"]]) &&
      identical(lapply(logins, `[[`, "kid"), list(old, old, new))
  )
  first <- proof[["populated"]]
  warm <- proof[["warm"]]
  retained <- proof[["before_rotated_login"]]
  refreshed <- proof[["refreshed"]]
  for (entry in list(first, warm, retained, refreshed)) {
    check(
      entry_valid(entry) &&
        identical(entry[["jwks_uri"]], uri) &&
        identical(entry[["discovery_issuer"]], issuer)
    )
  }
  check(
    same_entry(first, warm) &&
      same_entry(warm, retained) &&
      identical(first[["kids"]], list(old)) &&
      identical(refreshed[["kids"]], list(new)) &&
      refreshed[["fetched_at"]] > retained[["fetched_at"]] &&
      !identical(refreshed[["entry_hash"]], retained[["entry_hash"]])
  )
  calls <- proof[["fetch_calls"]]
  check(
    length(calls) == 4L &&
      identical(
        lapply(calls, `[[`, "force_refresh"),
        list(FALSE, FALSE, FALSE, TRUE)
      ) &&
      is.null(calls[[1L]][["entry"]]) &&
      same_entry(calls[[2L]][["entry"]], first) &&
      same_entry(calls[[3L]][["entry"]], first) &&
      same_entry(calls[[4L]][["entry"]], first) &&
      isTRUE(calls[[4L]][["entry"]][["usable"]])
  )
  requests <- proof[["requests"]]
  check(
    length(requests) == 2L &&
      is.null(requests[[1L]][["entry"]]) &&
      same_entry(requests[[2L]][["entry"]], first) &&
      isTRUE(requests[[2L]][["entry"]][["usable"]])
  )
  for (i in seq_along(requests)) {
    check(
      identical(requests[[i]][["url"]], uri) &&
        identical(requests[[i]][["status"]], 200L) &&
        is.null(requests[[i]][["cache_control"]]) &&
        is.null(requests[[i]][["expires"]]) &&
        identical(requests[[i]][["kids"]], list(c(old, new)[[i]]))
    )
  }
  # Native OP observations must corroborate the package-side pass-through trace.
  for (i in seq_len(2L)) {
    events <- list(before, after)[[i]][["events"]]
    keys <- Filter(function(event) identical(event[["type"]], "jwks"), events)
    grants <- Filter(
      function(event) identical(event[["type"]], "grant.success"),
      events
    )
    authorizations <- Filter(
      function(event) identical(event[["type"]], "authorization.accepted"),
      events
    )
    check(
      length(keys) == 1L &&
        length(grants) == c(2L, 1L)[[i]] &&
        length(authorizations) == length(grants)
    )
    check(
      identical(keys[[1L]][["status"]], 200L) &&
        identical(keys[[1L]][["kids"]], list(c(old, new)[[i]])) &&
        is.null(keys[[1L]][["cache_control"]]) &&
        is.null(keys[[1L]][["expires"]])
    )
    for (event in grants) {
      check(
        truth(
          event,
          c(
            "client_matches",
            "authentication_valid",
            "pkce_verified",
            "code_matches",
            "access_token_present",
            "id_token_present"
          )
        ) &&
          identical(event[["grant_type"]], "authorization_code")
      )
    }
    for (event in authorizations) {
      check(truth(
        event,
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ))
    }
    check(
      !any(vapply(
        events,
        function(event) grepl("error", event[["type"]]),
        logical(1)
      ))
    )
  }
  check(
    identical(proof[["pre_rotation_requests"]], 1L) &&
      identical(proof[["post_restart_requests"]], 0L) &&
      identical(proof[["post_rogue_requests"]], 1L) &&
      is.null(proof[["throttle_before"]]) &&
      finite_time(proof[["throttle_after"]]) &&
      proof[["throttle_after"]] >= retained[["observed_at"]] &&
      proof[["throttle_after"]] <= refreshed[["observed_at"]]
  )
  rogues <- proof[["rogues"]]
  check(
    length(rogues) == 2L &&
      identical(lapply(rogues, `[[`, "kid"), list(old, new)) &&
      identical(
        lapply(rogues, `[[`, "reason"),
        list("unknown_kid", "signature")
      )
  )
  for (rogue in rogues) {
    check(
      isTRUE(rogue[["rejected"]]) &&
        identical(rogue[["error_class"]], "shinyOAuth_id_token_error")
    )
  }
  invisible(TRUE)
}
