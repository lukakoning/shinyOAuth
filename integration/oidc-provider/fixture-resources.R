interop_resource_server <- function(auth, input, client, config) {
  narrowing <- isTRUE(config[["resource_indicators"]][["narrow_scope"]])
  reads <- shiny::reactiveVal(list())
  probes <- shiny::reactiveVal(NULL)
  shiny::observeEvent(
    input[["resource"]],
    {
      result <- tryCatch(
        {
          token <- auth[["token"]]
          connection <- auth[["connection"]]()
          response <- connection[["request"]]("api", "")
          body <- httr2::resp_body_json(response)
          introspection <- shinyOAuth::introspect_token(
            client,
            token,
            async = FALSE
          )
          expected_scopes <- if (narrowing && !length(reads())) {
            c("api.read", "api.write")
          } else {
            "api.read"
          }
          observed_scopes <- introspection[["raw"]][["scope"]]
          evidence <- list(
            done = TRUE,
            status = httr2::resp_status(response),
            subject_matches = identical(
              body[["sub"]],
              token@id_token_claims[["sub"]]
            ),
            audience_matches = identical(
              body[["audience"]],
              config[["resource"]]
            ),
            introspection_active = isTRUE(introspection[["active"]]),
            introspection_audience_matches = identical(
              introspection[["raw"]][["aud"]],
              config[["resource"]]
            ),
            introspection_scope_matches = is.character(observed_scopes) &&
              length(observed_scopes) == 1L &&
              identical(
                sort(strsplit(observed_scopes, " ", fixed = TRUE)[[1L]]),
                expected_scopes
              ),
            connection_usable = isTRUE(connection[["is_usable"]]()),
            api = "connection",
            pid = Sys.getpid(),
            transport = "main_process"
          )
          if (narrowing) {
            write <- tryCatch(
              connection[["request"]]("api", "", method = "POST"),
              shinyOAuth_http_error = identity
            )
            evidence[["scope_narrowing"]] <- list(
              granted_scopes_match = isTRUE(token@granted_scopes_verified) &&
                identical(sort(token@granted_scopes), expected_scopes),
              read_scope = isTRUE(connection[["has_scopes"]]("api.read")),
              write_scope = isTRUE(connection[["has_scopes"]]("api.write")),
              write_succeeded = inherits(write, "httr2_response") &&
                identical(httr2::resp_status(write), 200L),
              write_rejected = inherits(write, "httr2_response") &&
                identical(httr2::resp_status(write), 403L)
            )
          }
          evidence
        },
        error = function(...) list(done = TRUE, failed = TRUE)
      )
      reads(append(reads(), list(result)))
    },
    ignoreInit = TRUE
  )
  shiny::observeEvent(
    input[["resource_probes"]],
    {
      result <- tryCatch(
        {
          token <- auth[["token"]]
          connection <- auth[["connection"]]()
          other <- paste0(
            config[["issuer"]],
            "/resource/",
            if (config[["resource_indicators"]][["target"]] == "a") "b" else "a"
          )
          escaped <- tryCatch(
            connection[["request"]]("api", other),
            error = identity
          )
          raw_request <- function(url, kind, credential = NULL) {
            request <- httr2::request(url) |>
              httr2::req_headers(`X-Fixture-Probe` = kind) |>
              httr2::req_options(
                cainfo = config[["ca"]],
                followlocation = FALSE,
                proxy = ""
              ) |>
              httr2::req_error(is_error = function(...) FALSE) |>
              httr2::req_timeout(10)
            if (!is.null(credential)) {
              request <- httr2::req_headers(
                request,
                Authorization = paste("Bearer", credential)
              )
            }
            httr2::resp_status(httr2::req_perform(request))
          }
          list(
            done = TRUE,
            escape_blocked = inherits(escaped, "shinyOAuth_input_error"),
            wrong_audience = raw_request(
              other,
              "wrong_audience",
              token@access_token
            ),
            missing = raw_request(config[["resource"]], "missing"),
            invalid = raw_request(
              config[["resource"]],
              "invalid",
              "not-an-issued-token"
            ),
            pid = Sys.getpid(),
            transport = "main_process"
          )
        },
        error = function(...) list(done = TRUE, failed = TRUE)
      )
      probes(result)
    },
    ignoreInit = TRUE
  )
  shiny::reactive(list(reads = reads(), probes = probes()))
}
