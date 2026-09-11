# Strict synthetic SMART server for browser integration. This is a local
# protocol fixture, not external conformance evidence or a production server.
smart_ehr_fixture_provider <- function(site, callback) {
  state <- new.env(parent = emptyenv())
  for (name in c("launches", "codes", "access", "refresh")) state[[name]] <- new.env(parent = emptyenv())
  state$metrics <- list(launches = 0L, authorizations = 0L, exchanges = 0L, refreshes = 0L, requests = 0L)
  random <- function() unclass(as.character(openssl::sha256(openssl::rand_bytes(32))))
  base <- function(req) paste0("http://", req$get_header("Host"))
  app <- webfakes::new_app()
  app$use(webfakes::mw_urlencoded())
  app$use(function(req, res) {
    res$set_header("Cache-Control", "no-store")
    res$set_header("Referrer-Policy", "no-referrer")
    "next"
  })
  app$get("/fhir/.well-known/smart-configuration", function(req, res) {
    origin <- base(req)
    res$send_json(list(authorization_endpoint = paste0(origin, "/authorize"),
      token_endpoint = paste0(origin, "/token"),
      capabilities = list("launch-ehr", "client-public", "permission-v2",
        "permission-patient", "permission-online", "context-ehr-patient"),
      grant_types_supported = list("authorization_code", "refresh_token"),
      code_challenge_methods_supported = list("S256"),
      token_endpoint_auth_methods_supported = list("none")), auto_unbox = TRUE)
  })
  app$get("/ehr-launch", function(req, res) {
    id <- random()
    state$launches[[id]] <- list(patient = paste0("synthetic-", site), expires = as.numeric(Sys.time()) + 120)
    state$metrics$launches <- state$metrics$launches + 1L
    app_origin <- sub("/callback/.*$", "", callback)
    url <- paste0(app_origin, "/launch?iss=", utils::URLencode(paste0(base(req), "/fhir"), reserved = TRUE),
      "&launch=", id)
    res$set_status(302L)$set_header("Location", url)$send("")
  })
  app$get("/authorize", function(req, res) {
    query <- req$query
    launch <- if (is.character(query$launch)) state$launches[[query$launch]] else NULL
    if (is.null(launch) || launch$expires <= as.numeric(Sys.time()) ||
        !identical(query$client_id, site) || !identical(query$redirect_uri, callback) ||
        !identical(query$aud, paste0(base(req), "/fhir")) ||
        !identical(query$response_type, "code") || !identical(query$code_challenge_method, "S256") ||
        !is.character(query$code_challenge) || !grepl("^[A-Za-z0-9_-]{43}$", query$code_challenge) ||
        !is.character(query$state) || nchar(query$state) > 16384 ||
        !all(c("launch", "patient/Patient.r", "online_access") %in% strsplit(query$scope, " ", fixed = TRUE)[[1L]])) {
      return(res$set_status(400L)$send("Invalid SMART fixture authorization"))
    }
    rm(list = query$launch, envir = state$launches)
    id <- random()
    state$codes[[id]] <- list(query = query, patient = launch$patient, expires = as.numeric(Sys.time()) + 120)
    state$metrics$authorizations <- state$metrics$authorizations + 1L
    res$set_type("text/html")$send(paste0('<!doctype html><html><body><h1 id="provider">Site ', site,
      '</h1><a id="approve" href="/approve?ticket=', id, '">Approve synthetic access</a></body></html>'))
  })
  app$get("/approve", function(req, res) {
    record <- state$codes[[req$query$ticket]]
    if (is.null(record)) return(res$set_status(400L)$send("Expired fixture authorization"))
    if (identical(record$query$response_mode, "form_post")) {
      escape <- function(value) htmltools::htmlEscape(value, attribute = TRUE)
      return(res$set_type("text/html")$send(paste0('<!doctype html><html><body><form method="post" action="',
        escape(callback), '"><input type="hidden" name="code" value="', escape(req$query$ticket),
        '"><input type="hidden" name="state" value="', escape(record$query$state),
        '"></form><script>document.forms[0].submit()</script></body></html>')))
    }
    res$set_status(302L)$set_header("Location", paste0(callback, "?code=", req$query$ticket,
      "&state=", utils::URLencode(record$query$state, reserved = TRUE)))$send("")
  })
  app$post("/token", function(req, res) {
    body <- req$form
    if (!identical(body$client_id, site)) return(res$set_status(400L)$send_json(list(error = "invalid_client"), auto_unbox = TRUE))
    initial <- identical(body$grant_type, "authorization_code")
    if (initial) {
      record <- state$codes[[body$code]]
      challenge <- if (is.character(body$code_verifier)) {
        sub("=+$", "", chartr("+/", "-_", openssl::base64_encode(openssl::sha256(charToRaw(body$code_verifier)))))
      } else NULL
      if (is.null(record) || record$expires <= as.numeric(Sys.time()) ||
          !identical(body$redirect_uri, callback) || !identical(challenge, record$query$code_challenge)) {
        return(res$set_status(400L)$send_json(list(error = "invalid_grant"), auto_unbox = TRUE))
      }
      rm(list = body$code, envir = state$codes)
      state$metrics$exchanges <- state$metrics$exchanges + 1L
      grant <- list(patient = record$patient, revision = 1L)
    } else if (identical(body$grant_type, "refresh_token")) {
      grant <- state$refresh[[body$refresh_token]]
      if (is.null(grant)) return(res$set_status(400L)$send_json(list(error = "invalid_grant"), auto_unbox = TRUE))
      rm(list = body$refresh_token, envir = state$refresh)
      grant$revision <- grant$revision + 1L
      state$metrics$refreshes <- state$metrics$refreshes + 1L
    } else return(res$set_status(400L)$send_json(list(error = "unsupported_grant_type"), auto_unbox = TRUE))
    access <- random()
    refresh <- random()
    state$access[[access]] <- state$refresh[[refresh]] <- grant
    token <- list(access_token = access, refresh_token = refresh, token_type = "Bearer",
      expires_in = 3600, scope = "launch patient/Patient.r online_access")
    if (initial) {
      token$patient <- grant$patient
      token$encounter <- paste0("encounter-", site)
      token$need_patient_banner <- TRUE
    }
    res$send_json(token, auto_unbox = TRUE)
  })
  app$get("/fhir/Patient/:id", function(req, res) {
    bearer <- sub("^Bearer ", "", req$get_header("Authorization"))
    grant <- if (is.character(bearer) && length(bearer) == 1L) state$access[[bearer]] else NULL
    if (is.null(grant) || !identical(req$params$id, grant$patient)) {
      return(res$set_status(403L)$send("Denied by synthetic fixture"))
    }
    state$metrics$requests <- state$metrics$requests + 1L
    res$send_json(list(resourceType = "Patient", id = grant$patient,
      fixture_site = site, fixture_revision = grant$revision), auto_unbox = TRUE)
  })
  app$get("/metrics", function(req, res) res$send_json(state$metrics, auto_unbox = TRUE))
  webfakes::new_app_process(app, opts = webfakes::server_opts(remote = TRUE,
    interfaces = "127.0.0.1", num_threads = 4L, access_log_file = FALSE, error_log_file = FALSE))
}
