interop_advanced_limitations <- function() {
  c(
    "selected_rsa_jar_basic_auth_variants",
    "native_userinfo_resource_only",
    "mtls_binding_not_client_authentication",
    "opaque_mtls_cnf_not_required_locally",
    "resource_and_lifecycle_in_main_process",
    "no_rfc8707_or_navigation_retention"
  )
}

interop_advanced_provider_matches <- function(row, lock) {
  provider <- row[["provider"]]
  mode <- row[["mode"]]
  rejected <- identical(row[["outcome"]], "callback_rejected")
  if (
    !identical(provider[["run_id"]], row[["case_id"]]) ||
      !identical(provider[["advanced"]], mode) ||
      !identical(provider[["provider_version"]], lock[["provider_version"]]) ||
      !identical(provider[["node_version"]], lock[["node_version"]]) ||
      !identical(provider[["client_auth_type"]], "client_secret_basic") ||
      !identical(
        provider[["features"]],
        list(
          dev_interactions = FALSE,
          userinfo = TRUE,
          pkce_required = TRUE,
          refresh_rotation = TRUE
        )
      )
  ) {
    return(FALSE)
  }
  events <- provider[["events"]]
  types <- vapply(events, function(event) event[["type"]], character(1))
  if (
    !identical(
      vapply(events, function(event) event[["sequence"]], integer(1)),
      seq_along(events)
    ) ||
      length(types) < 6L ||
      !identical(
        types[1:6],
        c(
          "request_object",
          "frontchannel",
          "interaction",
          "interaction",
          "authorization.accepted",
          "authorization.success"
        )
      )
  ) {
    return(FALSE)
  }
  allowed <- c(
    "request_object",
    "frontchannel",
    "interaction",
    "authorization.accepted",
    "authorization.success",
    "jarm",
    "grant.success",
    "userinfo",
    "userinfo.error",
    "introspection",
    "revocation"
  )
  if (!all(types %in% allowed)) {
    return(FALSE)
  }
  select <- function(type) events[types == type]
  all_true <- function(value, fields) {
    all(vapply(fields, function(name) isTRUE(value[[name]]), logical(1)))
  }
  jar <- select("request_object")
  front <- select("frontchannel")
  accepted <- select("authorization.accepted")
  success <- select("authorization.success")
  interactions <- select("interaction")
  if (
    length(jar) != 1L ||
      length(front) != 1L ||
      length(accepted) != 1L ||
      length(success) != 1L ||
      length(interactions) != 2L ||
      !all_true(
        jar[[1L]],
        c(
          "signature_valid",
          "issuer_matches",
          "audience_matches",
          "redirect_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ) ||
      !identical(
        jar[[1L]][["source"]],
        if (mode[["par"]]) "par" else "direct"
      ) ||
      !jar[[1L]][["status"]] %in%
        (if (mode[["par"]]) 201L else c(302L, 303L)) ||
      !identical(
        jar[[1L]][["par_reference_issued"]],
        if (mode[["par"]]) TRUE else NULL
      ) ||
      !identical(
        jar[[1L]][["dpop_jkt_present"]],
        if (identical(mode[["sender"]], "dpop")) TRUE else NULL
      ) ||
      !identical(front[[1L]][["pushed"]], mode[["par"]]) ||
      !identical(front[[1L]][["signed"]], !mode[["par"]]) ||
      !identical(
        front[[1L]][["par_only"]],
        if (mode[["par"]]) TRUE else NULL
      ) ||
      !identical(
        vapply(
          interactions,
          function(event) event[["prompt"]],
          character(1)
        ),
        c("login", "consent")
      ) ||
      !all_true(
        accepted[[1L]],
        c(
          "client_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present"
        )
      ) ||
      !identical(
        accepted[[1L]][["response_mode"]],
        if (mode[["jarm"]]) "jwt" else "query"
      ) ||
      !isTRUE(success[[1L]][["code_issued"]])
  ) {
    return(FALSE)
  }
  jarm <- select("jarm")
  if (length(jarm) != (if (mode[["jarm"]]) 1L else 0L)) {
    return(FALSE)
  }
  if (
    mode[["jarm"]] &&
      !all_true(
        jarm[[1L]],
        c(
          "signature_valid",
          "issuer_matches",
          "audience_matches",
          "code_present",
          "expiry_valid",
          "query_only"
        )
      )
  ) {
    return(FALSE)
  }
  grants <- select("grant.success")
  userinfo <- select("userinfo")
  errors <- select("userinfo.error")
  introspection <- select("introspection")
  revocation <- select("revocation")
  if (rejected) {
    return(
      length(grants) == 0L &&
        length(userinfo) == 0L &&
        length(errors) == 0L &&
        length(introspection) == 0L &&
        length(revocation) == 0L
    )
  }
  if (
    length(grants) != 2L ||
      !identical(
        vapply(grants, function(event) event[["grant_type"]], character(1)),
        c("authorization_code", "refresh_token")
      )
  ) {
    return(FALSE)
  }
  for (i in 1:2) {
    if (
      !all_true(
        grants[[i]],
        c(
          "client_matches",
          "authentication_valid",
          "access_token_present",
          "id_token_present",
          "refresh_token_present",
          "sender_bound"
        )
      )
    ) {
      return(FALSE)
    }
  }
  if (
    !all_true(grants[[1L]], c("pkce_verified", "code_matches")) ||
      !is.null(grants[[1L]][["refresh_token_rotated"]]) ||
      !isTRUE(grants[[2L]][["refresh_token_rotated"]]) ||
      !is.null(grants[[2L]][["pkce_verified"]]) ||
      !is.null(grants[[2L]][["code_matches"]])
  ) {
    return(FALSE)
  }
  good <- Filter(function(event) identical(event[["status"]], 200L), userinfo)
  denied <- Filter(function(event) identical(event[["status"]], 401L), userinfo)
  dpop <- identical(mode[["sender"]], "dpop")
  mtls <- identical(mode[["sender"]], "mtls")
  probes <- if (dpop) {
    c("bearer", "wrong_key", "replay", "revoked")
  } else if (mtls) {
    c("missing_cert", "wrong_cert", "forged_header", "revoked")
  } else {
    "revoked"
  }
  if (
    length(good) != (if (dpop) 4L else 3L) ||
      length(denied) != length(probes) ||
      length(errors) != length(probes) ||
      length(userinfo) != length(good) + length(denied)
  ) {
    return(FALSE)
  }
  for (event in good) {
    if (
      !all_true(
        event,
        c(
          "signed_response_valid",
          "issuer_matches",
          "audience_matches",
          "subject_present",
          "current_token_used"
        )
      ) ||
        !identical(event[["dpop_key_matches"]], if (dpop) TRUE else NULL) ||
        !identical(event[["mtls_peer_matches"]], if (mtls) TRUE else NULL) ||
        !identical(event[["mtls_peer_present"]], mtls)
    ) {
      return(FALSE)
    }
  }
  if (
    sum(vapply(good, function(event) is.null(event[["probe"]]), logical(1))) !=
      3L ||
      (dpop &&
        sum(vapply(
          good,
          function(event) identical(event[["probe"]], "replay_valid"),
          logical(1)
        )) !=
          1L)
  ) {
    return(FALSE)
  }
  for (set in list(denied, errors)) {
    tags <- vapply(set, function(event) event[["probe"]], character(1))
    if (anyDuplicated(tags) || !setequal(tags, probes)) {
      return(FALSE)
    }
    for (event in set) {
      tag <- event[["probe"]]
      if (
        !isTRUE(event[["current_token_used"]]) ||
          !identical(
            event[["dpop_key_matches"]],
            if (dpop) !tag %in% c("bearer", "wrong_key") else NULL
          ) ||
          !identical(
            event[["mtls_peer_present"]],
            mtls && tag != "missing_cert"
          ) ||
          !identical(
            event[["mtls_peer_matches"]],
            if (mtls) tag == "revoked" else NULL
          )
      ) {
        return(FALSE)
      }
    }
  }
  if (
    !all(vapply(
      errors,
      function(event) identical(event[["error"]], "invalid_token"),
      logical(1)
    ))
  ) {
    return(FALSE)
  }
  if (
    !all(vapply(
      denied,
      function(event) {
        identical(event[["signed_response_valid"]], FALSE) &&
          identical(event[["subject_present"]], FALSE)
      },
      logical(1)
    ))
  ) {
    return(FALSE)
  }
  if (
    length(introspection) != 2L ||
      length(revocation) != 1L ||
      !identical(
        vapply(introspection, function(event) event[["active"]], logical(1)),
        c(TRUE, FALSE)
      )
  ) {
    return(FALSE)
  }
  all(vapply(
    c(introspection, revocation),
    function(event) {
      identical(event[["status"]], 200L) &&
        all_true(event, c("client_matches", "current_token_used"))
    },
    logical(1)
  ))
}

interop_advanced_row_matches <- function(row, context, selection, lock) {
  rejected <- endsWith(row[["id"]], "-invalid-jarm")
  mode <- selection[c("sender", "par", "jarm")]
  if (
    !identical(row[["mode"]], mode) ||
      !identical(row[["run_id"]], context[["run_id"]]) ||
      !identical(row[["checkout_revision"]], context[["checkout_revision"]]) ||
      !identical(
        row[["outcome"]],
        if (rejected) "callback_rejected" else "authenticated"
      ) ||
      !isTRUE(row[["cleanup_verified"]]) ||
      !isTRUE(row[["worker_cleanup_verified"]]) ||
      !openid_string(row[["browser_version"]]) ||
      !interop_advanced_provider_matches(row, lock)
  ) {
    return(FALSE)
  }
  metadata <- row[["discovery"]]
  if (
    !grepl("^https://localhost:[0-9]+$", row[["provider_origin"]]) ||
      !grepl("^https://localhost:[0-9]+$", row[["app_origin"]]) ||
      identical(row[["provider_origin"]], row[["app_origin"]]) ||
      !identical(metadata[["issuer"]], row[["provider_origin"]]) ||
      !isTRUE(metadata[["require_signed_request_object"]])
  ) {
    return(FALSE)
  }
  paths <- c(
    authorization_endpoint = "/authorize",
    token_endpoint = "/token",
    userinfo_endpoint = "/userinfo",
    jwks_uri = "/jwks",
    introspection_endpoint = "/token/introspection",
    revocation_endpoint = "/token/revocation"
  )
  if (mode[["par"]]) {
    paths <- c(paths, pushed_authorization_request_endpoint = "/request")
  } else if (!is.null(metadata[["pushed_authorization_request_endpoint"]])) {
    return(FALSE)
  }
  for (name in names(paths)) {
    if (
      !identical(
        metadata[[name]],
        paste0(row[["provider_origin"]], paths[[name]])
      )
    ) {
      return(FALSE)
    }
  }
  if (identical(mode[["sender"]], "mtls")) {
    aliases <- metadata[["mtls_endpoint_aliases"]]
    origin <- sub("/token$", "", aliases[["token_endpoint"]])
    if (
      !grepl("^https://localhost:[0-9]+$", origin) ||
        origin %in% c(row[["provider_origin"]], row[["app_origin"]])
    ) {
      return(FALSE)
    }
    expected_aliases <- paths[
      !names(paths) %in% c("authorization_endpoint", "jwks_uri")
    ]
    if (!setequal(names(aliases), names(expected_aliases))) {
      return(FALSE)
    }
    for (name in names(expected_aliases)) {
      if (
        !identical(aliases[[name]], paste0(origin, expected_aliases[[name]]))
      ) {
        return(FALSE)
      }
    }
  } else if (!is.null(metadata[["mtls_endpoint_aliases"]])) {
    return(FALSE)
  }
  for (name in c(
    "request_object_signing_alg_values_supported",
    "userinfo_signing_alg_values_supported"
  )) {
    if (!"RS256" %in% unlist(metadata[[name]])) return(FALSE)
  }
  if (
    mode[["par"]] &&
      (!isTRUE(metadata[["require_pushed_authorization_requests"]]) ||
        !openid_string(metadata[["pushed_authorization_request_endpoint"]]))
  ) {
    return(FALSE)
  }
  if (
    mode[["jarm"]] &&
      (!"jwt" %in% unlist(metadata[["response_modes_supported"]]) ||
        !"RS256" %in%
          unlist(metadata[["authorization_signing_alg_values_supported"]]))
  ) {
    return(FALSE)
  }
  if (
    identical(mode[["sender"]], "dpop") &&
      !"ES256" %in% unlist(metadata[["dpop_signing_alg_values_supported"]])
  ) {
    return(FALSE)
  }
  if (
    identical(mode[["sender"]], "mtls") &&
      (!isTRUE(metadata[["tls_client_certificate_bound_access_tokens"]]) ||
        !all(
          c(
            "token_endpoint",
            "userinfo_endpoint",
            "introspection_endpoint",
            "revocation_endpoint"
          ) %in%
            names(metadata[["mtls_endpoint_aliases"]])
        ))
  ) {
    return(FALSE)
  }
  expected <- if (rejected) {
    list(
      outcome = "callback_rejected",
      error_code = "http_callback_rejected",
      jarm_error = "with-invalid-sig",
      state_present = FALSE,
      issuer_present = FALSE
    )
  } else {
    list(
      outcome = "refreshed",
      action = "refresh",
      export_blocked = !is.null(mode[["sender"]])
    )
  }
  if (!openid_transport_matches(row, expected, context)) {
    return(FALSE)
  }
  if (rejected) {
    return(
      isTRUE(row[["tampered"]]) &&
        isTRUE(mode[["jarm"]]) &&
        openid_http_callback_matches(row, expected) &&
        openid_app_matches(
          row[["app"]],
          expected,
          row[["case_id"]],
          context[["package_version"]]
        ) &&
        all(vapply(
          row[c("resource", "probes", "lifecycle")],
          is.null,
          logical(1)
        ))
    )
  }
  if (
    !identical(row[["tampered"]], FALSE) ||
      !isTRUE(row[["callback_cleaned"]]) ||
      !is.null(row[["callback_http"]]) ||
      !openid_refresh_matches(
        row,
        expected,
        row[["case_id"]],
        context[["package_version"]]
      )
  ) {
    return(FALSE)
  }
  if (
    identical(mode[["sender"]], "mtls") &&
      (!isTRUE(row[["app"]][["mtls_configured"]]) ||
        !isTRUE(row[["before_refresh"]][["mtls_configured"]]))
  ) {
    return(FALSE)
  }
  for (name in c("resource", "probes", "lifecycle")) {
    value <- row[[name]]
    if (
      !isTRUE(value[["done"]]) ||
        isTRUE(value[["failed"]]) ||
        !identical(value[["transport"]], "main_process") ||
        !identical(value[["pid"]], row[["app"]][["transport"]][["app_pid"]])
    ) {
      return(FALSE)
    }
  }
  if (
    !all(vapply(
      row[["resource"]][c("succeeded", "signed_response", "connection_usable")],
      isTRUE,
      logical(1)
    )) ||
      !all(
        c("succeeded", "signed_response", "connection_usable") %in%
          names(row[["resource"]])
      ) ||
      !identical(row[["resource"]][["api"]], "connection")
  ) {
    return(FALSE)
  }
  statuses <- row[["probes"]][["statuses"]]
  desired <- if (identical(mode[["sender"]], "dpop")) {
    list(bearer = 401L, wrong_key = 401L, replay_valid = 200L, replay = 401L)
  } else if (identical(mode[["sender"]], "mtls")) {
    list(missing_cert = 401L, wrong_cert = 401L, forged_header = 401L)
  } else {
    list()
  }
  if (!identical(statuses, desired)) {
    return(FALSE)
  }
  life <- row[["lifecycle"]]
  all(vapply(
    c("active_before", "client_matches", "subject_matches", "revoked"),
    function(name) isTRUE(life[[name]]),
    logical(1)
  )) &&
    identical(life[["active_after"]], FALSE) &&
    identical(life[["resource_status"]], 401L)
}

interop_advanced_matches <- function(report, context, lock, cases) {
  tryCatch(
    {
      if (
        !interop_report_source_matches(report, context) ||
          !identical(
            report[["scope"]],
            "oidc_provider_advanced_interoperability"
          ) ||
          !identical(report[["coverage_complete"]], FALSE) ||
          !identical(
            unlist(report[["coverage_limitations"]]),
            interop_advanced_limitations()
          ) ||
          !isTRUE(report[["cleanup_verified"]]) ||
          !isTRUE(report[["driver_failure_control_passed"]]) ||
          !interop_sanitized(report) ||
          !identical(report[["provider_lock"]], lock) ||
          !identical(report[["image_id"]], context[["image_id"]]) ||
          !grepl("^sha256:[a-f0-9]{64}$", report[["image_id"]]) ||
          !identical(report[["source_hashes"]], context[["source_hashes"]])
      ) {
        return(FALSE)
      }
      for (name in c(
        "run_id",
        "checkout_revision",
        "transport",
        "package_version"
      )) {
        if (
          !openid_string(context[[name]]) ||
            !identical(report[[name]], context[[name]])
        ) {
          return(FALSE)
        }
      }
      if (!context[["transport"]] %in% c("sync", "mirai")) {
        return(FALSE)
      }
      ids <- vapply(cases, function(value) value[["id"]], character(1))
      expected <- c(
        ids,
        paste0(
          ids[vapply(
            cases,
            function(value) isTRUE(value[["jarm"]]),
            logical(1)
          )],
          "-invalid-jarm"
        )
      )
      rows <- report[["results"]]
      if (length(rows) != length(expected)) {
        return(FALSE)
      }
      actual <- vapply(rows, function(row) row[["id"]], character(1))
      instances <- vapply(rows, function(row) row[["case_id"]], character(1))
      if (
        anyDuplicated(actual) ||
          anyDuplicated(instances) ||
          !setequal(actual, expected) ||
          !all(grepl("^[a-f0-9]{32}$", instances))
      ) {
        return(FALSE)
      }
      for (row in rows) {
        selection <- cases[[match(sub("-invalid-jarm$", "", row[["id"]]), ids)]]
        if (!interop_advanced_row_matches(row, context, selection, lock)) {
          return(FALSE)
        }
      }
      TRUE
    },
    error = function(...) FALSE
  )
}

# These mutations target checked evidence, including both true and false sender
# facts. They are report-parser controls; live attacks run in separate requests.
interop_advanced_mutations <- function(report) {
  mutations <- list()
  add <- function(path, value = NULL) {
    mutations[[paste(path, collapse = "_")]] <<- list(
      path = path,
      value = value
    )
  }
  for (field in c(
    "cleanup_verified",
    "driver_failure_control_passed",
    "coverage_limitations",
    "image_id"
  )) {
    add(field)
  }
  for (i in seq_along(report[["results"]])) {
    base <- c("results", as.character(i))
    row <- report[["results"]][[i]]
    fields <- c(
      "provider",
      "discovery",
      "worker_cleanup_verified",
      "app_origin"
    )
    fields <- c(
      fields,
      if (row[["outcome"]] == "authenticated") {
        c("callback_cleaned", "resource", "probes", "lifecycle")
      } else {
        c("callback_http", "tampered")
      }
    )
    for (field in fields) {
      add(c(base, field))
    }
    if (row[["outcome"]] == "authenticated") {
      for (path in list(
        c("app", "id_token_validated"),
        c("app", "has_refresh_token"),
        c("app", "refresh", "access_changed"),
        c("app", "refresh", "subject_unchanged"),
        c("app", "transport", "events_verified"),
        c("resource", "signed_response"),
        c("lifecycle", "active_after"),
        c("lifecycle", "resource_status")
      )) {
        add(c(base, path))
      }
    }
    for (j in seq_along(row[["provider"]][["events"]])) {
      event <- row[["provider"]][["events"]][[j]]
      path <- c(base, "provider", "events", as.character(j))
      add(path)
      fields <- switch(
        event[["type"]],
        request_object = c(
          "source",
          "status",
          "signature_valid",
          "issuer_matches",
          "audience_matches",
          "redirect_matches",
          "code_flow",
          "pkce_s256",
          "state_present",
          "nonce_present",
          "dpop_jkt_present",
          "par_reference_issued"
        ),
        frontchannel = c("pushed", "signed", "par_only"),
        interaction = "prompt",
        authorization.accepted = c(
          "client_matches",
          "code_flow",
          "response_mode",
          "pkce_s256",
          "state_present",
          "nonce_present"
        ),
        authorization.success = "code_issued",
        jarm = c(
          "signature_valid",
          "issuer_matches",
          "audience_matches",
          "code_present",
          "expiry_valid",
          "query_only"
        ),
        grant.success = c(
          "grant_type",
          "client_matches",
          "authentication_valid",
          "pkce_verified",
          "code_matches",
          "access_token_present",
          "id_token_present",
          "refresh_token_present",
          "refresh_token_rotated",
          "sender_bound"
        ),
        userinfo = c(
          "status",
          "signed_response_valid",
          "subject_present",
          "probe",
          "current_token_used",
          "dpop_key_matches",
          "mtls_peer_present",
          "mtls_peer_matches",
          if (identical(event[["status"]], 200L)) {
            c("issuer_matches", "audience_matches")
          }
        ),
        userinfo.error = c(
          "error",
          "probe",
          "current_token_used",
          "dpop_key_matches",
          "mtls_peer_present",
          "mtls_peer_matches"
        ),
        introspection = c(
          "status",
          "client_matches",
          "current_token_used",
          "active"
        ),
        revocation = c("status", "client_matches", "current_token_used")
      )
      for (field in fields) {
        value <- event[[field]]
        if (is.null(value)) {
          next
        }
        replacement <- if (is.logical(value)) {
          !value
        } else if (is.numeric(value)) {
          599L
        } else {
          "mutated"
        }
        add(c(path, field), replacement)
      }
    }
  }
  mutations
}

interop_advanced_replace <- function(value, path, replacement) {
  index <- if (grepl("^[0-9]+$", path[[1L]])) {
    as.integer(path[[1L]])
  } else {
    path[[1L]]
  }
  if (length(path) == 1L) {
    value[index] <- list(replacement)
  } else {
    value[index] <- list(interop_advanced_replace(
      value[[index]],
      path[-1L],
      replacement
    ))
  }
  value
}

interop_advanced_rejections <- function(report, context, lock, cases) {
  matches <- function(value) {
    interop_advanced_matches(value, context, lock, cases)
  }
  if (!matches(report)) {
    stop("The actual advanced report must pass before rejection controls")
  }
  mutations <- interop_advanced_mutations(report)
  controls <- lapply(mutations, function(mutation) {
    !matches(interop_advanced_replace(
      report,
      mutation[["path"]],
      mutation[["value"]]
    ))
  })
  controls <- c(controls, interop_source_rejections(report, matches))
  failed <- names(controls)[!vapply(controls, isTRUE, logical(1))]
  if (length(failed)) {
    stop(
      "Advanced rejection controls unexpectedly passed: ",
      paste(failed, collapse = ", ")
    )
  }
  controls
}

interop_advanced_check_report <- function(report, context, lock, cases) {
  controls <- report[["rejection_controls"]]
  interop_advanced_matches(report, context, lock, cases) &&
    is.list(controls) &&
    !anyDuplicated(names(controls)) &&
    setequal(
      names(controls),
      c(
        names(interop_advanced_mutations(report)),
        names(interop_source_rejection_overrides(report))
      )
    ) &&
    all(vapply(controls, isTRUE, logical(1)))
}
