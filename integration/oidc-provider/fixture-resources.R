interop_resource_server <- function(auth, input, client, config) {
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
          list(
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
            introspection_scope_matches = identical(
              introspection[["raw"]][["scope"]],
              "api.read"
            ),
            connection_usable = isTRUE(connection[["is_usable"]]()),
            api = "connection",
            pid = Sys.getpid(),
            transport = "main_process"
          )
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
