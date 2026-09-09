# A registry selects only preconfigured clients. Issuer values are routing
# hints; the selected bridge still verifies issuer, state and JARM, and the
# module still verifies the browser binding before consuming logical state.
oauth_callback_registry <- function(clients) {
  if (
    !is.list(clients) ||
      !length(clients) ||
      is.null(names(clients)) ||
      anyNA(names(clients)) ||
      !all(nzchar(names(clients))) ||
      anyDuplicated(names(clients))
  ) {
    err_input(
      "clients must be a non-empty list with unique module IDs as names."
    )
  }
  for (client in clients) {
    S7::check_is_S7(client, class = OAuthClient)
  }
  if (length(clients) > 1L) {
    for (client in clients) {
      if (identical(client@authorization_server_mode, "single")) {
        err_input(
          "Each registry client must select a multi-server authorization_server_mode."
        )
      }
    }
    for (i in seq_along(clients)) {
      for (j in seq_len(i - 1L)) {
        first <- clients[[i]]
        second <- clients[[j]]
        if (
          identical(
            oauth_callback_route(first@redirect_uri),
            oauth_callback_route(second@redirect_uri)
          )
        ) {
          if (
            !identical(first@authorization_server_mode, "multi_issuer") ||
              !identical(second@authorization_server_mode, "multi_issuer") ||
              identical(first@provider@issuer, second@provider@issuer)
          ) {
            err_input(
              "Shared callback routes require multi_issuer clients with distinct issuers."
            )
          }
        }
      }
    }
  }
  for (id in names(clients)) {
    if (
      resolve_oauth_client_response_mode(clients[[id]])$mode %in%
        c("form_post", "form_post.jwt")
    ) {
      mark_form_post_ui_called(id, clients[[id]])
    }
  }
  clients
}

# Dedicated routing returns occur before the client-specific callback bridge.
# Keep their telemetry independent of unvalidated issuer and state values.
oauth_registry_rejection <- function(req, reason, message) {
  with_otel_span(
    "shinyOAuth.callback.route",
    {
      audit_event(
        "callback_routing_rejected",
        context = list(phase = "callback_registry_routing", reason = reason, status = "error"),
        shiny_session = list(http = build_http_summary(req))
      )
      otel_note_error(simpleError("OAuth callback routing rejected"))
      oauth_get_setup_error(message)
    },
    attributes = list(
      oauth.phase = "callback_registry_routing",
      oauth.reason = reason,
      http.response.status_code = 400L
    ),
    mark_ok = FALSE,
    parent = NA
  )
}

oauth_registry_http_handler <- function(req, clients, request_uri_resolver) {
  # Hosted Request Objects have independent, client-bound handles. Missing
  # handles in another client's store do not consume the requested object.
  if (
    length(oauth_module_query_raw_values(
      req[["QUERY_STRING"]] %||% "",
      shiny_request_object_param
    ))
  ) {
    response <- NULL
    for (client in clients) {
      response <- shiny_request_object_http_handler(req, client)
      if (!is.null(response) && response$status != 410L) return(response)
    }
    return(response)
  }
  method <- req[["REQUEST_METHOD"]] %||% "GET"
  query <- req[["QUERY_STRING"]] %||% ""
  callback <- identical(method, "GET") &&
    any(vapply(
      clients,
      function(client) oauth_get_query_is_callback(query, client),
      logical(1)
    ))
  if (!callback && !identical(method, "POST")) {
    return(NULL)
  }
  tryCatch(
    {
      validate_untrusted_query_string(
        query,
        max_bytes = oauth_callback_limits()$query
      )
      uri <- request_uri_resolver(req)
      if (!is_valid_string(uri)) {
        if (callback) {
          return(oauth_registry_rejection(
            req, "route_unavailable", "OAuth callback route is unavailable."
          ))
        }
        return(NULL)
      }
      actual <- paste0(sub("[?#].*$", "", uri), "?", sub("^\\?", "", query))
      candidates <- clients[vapply(
        clients,
        function(client) {
          oauth_callback_route_matches(actual, client@redirect_uri)
        },
        logical(1)
      )]
      if (!length(candidates)) {
        if (callback) {
          return(oauth_registry_rejection(
            req, "route_unregistered",
            "OAuth callback route is not registered."
          ))
        }
        return(NULL)
      }
      transport <- if (identical(method, "GET")) "query" else "form_post"
      candidates <- candidates[vapply(
        candidates,
        function(client) {
          resolve_oauth_client_response_mode(client)$mode %in%
            c(transport, paste0(transport, ".jwt"))
        },
        logical(1)
      )]
      if (!length(candidates)) {
        return(oauth_registry_rejection(
          req, "unexpected_transport",
          "OAuth callback used an unexpected response transport."
        ))
      }
      payload <- NULL
      if (length(candidates) > 1L) {
        limits <- oauth_callback_limits()
        payload <- if (identical(transport, "query")) {
          reject_duplicate_oauth_module_callback_query(
            query,
            query_jarm_client = TRUE,
            response_is_callback = TRUE
          )
          oauth_form_post_validate_payload(
            shiny::parseQueryString(query),
            limits
          )
        } else {
          oauth_form_post_validate_content_type(req)
          body <- oauth_form_post_read_body(req, limits$form_post_body)
          oauth_form_post_parse_body(body, limits)
        }
        issuer <- payload[["iss"]]
        if (!is_valid_string(issuer) && identical(payload$type, "response")) {
          issuer <- parse_jwt_payload_or_null(payload$response)[["iss"]]
        }
        if (!is_valid_string(issuer)) {
          return(oauth_registry_rejection(
            req, "issuer_missing",
            "Shared OAuth callback route requires issuer identification."
          ))
        }
        candidates <- candidates[vapply(
          candidates,
          function(client) {
            identical(issuer, client@provider@issuer)
          },
          logical(1)
        )]
      }
      if (length(candidates) != 1L) {
        return(oauth_registry_rejection(
          req, "issuer_unrecognized",
          "OAuth callback does not identify one configured provider."
        ))
      }
      oauth_form_post_handle_request(
        req,
        names(candidates)[[1L]],
        candidates[[1L]],
        transport = transport,
        payload = payload
      )
    },
    error = function(e) {
      oauth_get_setup_error("OAuth callback could not be routed or validated.")
    }
  )
}
