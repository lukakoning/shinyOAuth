interop_advanced_server <- function(auth, input, client, config) {
  resource <- shiny::reactiveVal(NULL)
  probes <- shiny::reactiveVal(NULL)
  lifecycle <- shiny::reactiveVal(NULL)
  request <- function(
    token,
    kind = NULL,
    proof = NULL,
    certificate = NULL,
    forged = FALSE
  ) {
    value <- httr2::request(paste0(
      if (identical(config[["advanced"]][["sender"]], "mtls")) {
        config[["mtls_origin"]]
      } else {
        config[["issuer"]]
      },
      "/userinfo"
    )) |>
      httr2::req_headers(
        Authorization = paste(
          if (is.null(proof)) "Bearer" else "DPoP",
          token@access_token
        )
      ) |>
      httr2::req_options(cainfo = config[["ca"]], followlocation = FALSE) |>
      httr2::req_error(is_error = function(...) FALSE) |>
      httr2::req_timeout(10)
    if (!is.null(kind)) {
      value <- httr2::req_headers(value, `X-Fixture-Probe` = kind)
    }
    if (!is.null(proof)) {
      value <- httr2::req_headers(value, DPoP = proof)
    }
    if (!is.null(certificate)) {
      value <- httr2::req_options(
        value,
        sslcert = certificate[["cert_file"]],
        sslkey = certificate[["key_file"]]
      )
    }
    if (forged) {
      value <- httr2::req_headers(
        value,
        `X-Ssl-Cert` = utils::URLencode(
          paste(readLines(config[["mtls"]][["cert_file"]]), collapse = "\n"),
          reserved = TRUE
        )
      )
    }
    httr2::resp_status(httr2::req_perform(value))
  }
  proof <- function(token, key) {
    public <- jsonlite::fromJSON(
      jose::write_jwk(key[["pubkey"]]),
      simplifyVector = FALSE
    )
    ath <- sub(
      "=+$",
      "",
      chartr(
        "+/",
        "-_",
        as.character(openssl::base64_encode(openssl::sha256(charToRaw(
          token@access_token
        ))))
      )
    )
    jose::jwt_encode_sig(
      jose::jwt_claim(
        htm = "GET",
        htu = paste0(config[["issuer"]], "/userinfo"),
        iat = floor(as.numeric(Sys.time())),
        jti = paste(format(openssl::rand_bytes(16)), collapse = ""),
        ath = ath
      ),
      key,
      header = list(typ = "dpop+jwt", jwk = public)
    )
  }
  shiny::observeEvent(
    input[["resource"]],
    {
      value <- tryCatch(
        {
          connection <- auth[["connection"]]()
          response <- connection[["request"]]("profile", "userinfo")
          list(
            done = TRUE,
            succeeded = identical(httr2::resp_status(response), 200L),
            signed_response = startsWith(
              httr2::resp_header(response, "content-type"),
              "application/jwt"
            ),
            connection_usable = isTRUE(connection[["is_usable"]]()),
            api = "connection",
            pid = Sys.getpid(),
            transport = "main_process"
          )
        },
        error = function(...) list(done = TRUE, succeeded = FALSE)
      )
      resource(value)
    },
    ignoreInit = TRUE
  )
  shiny::observeEvent(
    input[["probes"]],
    {
      value <- tryCatch(
        {
          token <- auth[["token"]]
          statuses <- if (identical(config[["advanced"]][["sender"]], "dpop")) {
            key <- openssl::read_key(client@dpop_private_key)
            replay <- proof(token, key)
            list(
              bearer = request(token, "bearer"),
              wrong_key = request(
                token,
                "wrong_key",
                proof(token, openssl::ec_keygen("P-256"))
              ),
              replay_valid = request(token, "replay_valid", replay),
              replay = request(token, "replay", replay)
            )
          } else if (identical(config[["advanced"]][["sender"]], "mtls")) {
            list(
              missing_cert = request(token, "missing_cert"),
              wrong_cert = request(
                token,
                "wrong_cert",
                certificate = config[["mtls"]][["wrong"]]
              ),
              forged_header = request(
                token,
                "forged_header",
                certificate = config[["mtls"]][["wrong"]],
                forged = TRUE
              )
            )
          } else {
            list()
          }
          list(
            done = TRUE,
            statuses = statuses,
            pid = Sys.getpid(),
            transport = "main_process"
          )
        },
        error = function(...) list(done = TRUE, failed = TRUE)
      )
      probes(value)
    },
    ignoreInit = TRUE
  )
  shiny::observeEvent(
    input[["lifecycle"]],
    {
      value <- tryCatch(
        {
          token <- auth[["token"]]
          before <- shinyOAuth::introspect_token(client, token, async = FALSE)
          revoked <- shinyOAuth::revoke_token(
            client,
            token,
            token_kind = "access",
            async = FALSE
          )
          after <- shinyOAuth::introspect_token(client, token, async = FALSE)
          status <- if (identical(config[["advanced"]][["sender"]], "dpop")) {
            request(
              token,
              "revoked",
              proof(token, openssl::read_key(client@dpop_private_key))
            )
          } else {
            request(token, "revoked", certificate = config[["mtls"]])
          }
          list(
            done = TRUE,
            active_before = isTRUE(before[["active"]]),
            client_matches = identical(
              before[["raw"]][["client_id"]],
              config[["client_id"]]
            ),
            subject_matches = identical(
              before[["raw"]][["sub"]],
              token@id_token_claims[["sub"]]
            ),
            revoked = isTRUE(revoked[["revoked"]]),
            active_after = isTRUE(after[["active"]]),
            resource_status = status,
            pid = Sys.getpid(),
            transport = "main_process"
          )
        },
        error = function(...) list(done = TRUE, failed = TRUE)
      )
      lifecycle(value)
    },
    ignoreInit = TRUE
  )
  shiny::reactive(list(
    resource = resource(),
    probes = probes(),
    lifecycle = lifecycle()
  ))
}
