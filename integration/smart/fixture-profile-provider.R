# Synthetic protocol fixture for supported SMART registrations and launch modes.
# Keys and registrations are temporary. This does not replace external testing.
smart_profile_provider <- function(site, callback, registration, launch,
  authorization_method = "GET", extra_scopes = character()) {
  state <- new.env(parent = emptyenv())
  for (name in c("launches", "codes", "access", "refresh", "assertions")) state[[name]] <- new.env(parent = emptyenv())
  state$metrics <- list(exchanges = 0L, refreshes = 0L, assertions = 0L,
    scoped_refreshes = 0L, reads = 0L, users = 0L, searches = 0L,
    authorization_posts = 0L, authorization_gets = 0L, authorization_body_bytes = 0L)
  decode <- function(value) openssl::base64_decode(paste0(chartr("-_", "+/", value),
    strrep("=", (4L - nchar(value) %% 4L) %% 4L)))
  signing_pem <- openssl::write_pem(openssl::rsa_keygen(2048))
  public <- jsonlite::fromJSON(jose::write_jwk(openssl::read_key(signing_pem)$pubkey), simplifyVector = FALSE)
  # jose 1.2.1 may export an ASN.1 sign byte; RFC 7518 needs minimal unsigned integers.
  for (field in c("n", "e")) {
    bytes <- decode(public[[field]])
    while (length(bytes) > 1L && bytes[[1L]] == as.raw(0)) bytes <- bytes[-1L]
    public[[field]] <- sub("=+$", "", chartr("+/", "-_", openssl::base64_encode(bytes)))
  }
  public$kid <- "fixture-id"
  public$alg <- "RS256"
  public$use <- "sig"
  initial_scopes <- c(if (launch == "ehr") "launch" else "launch/patient",
    "patient/Patient.rs", "user/Practitioner.r", "offline_access", "openid", "fhirUser", extra_scopes)
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
    res$send_json(list(issuer = paste0(origin, "/fhir"), jwks_uri = paste0(origin, "/keys"),
      authorization_endpoint = paste0(origin, "/authorize",
        if (authorization_method == "POST") "?tenant=fixture%2Bvalue%26kept" else ""),
      token_endpoint = paste0(origin, "/token"),
      capabilities = as.list(c("launch-ehr", "launch-standalone", "client-public",
        "client-confidential-symmetric", "client-confidential-asymmetric", "sso-openid-connect",
        "permission-v2", "permission-patient", "permission-user", "permission-offline",
        "context-ehr-patient", "context-standalone-patient", "authorize-post")),
      grant_types_supported = list("authorization_code", "refresh_token"),
      scopes_supported = as.list(initial_scopes),
      code_challenge_methods_supported = list("S256"), response_modes_supported = list("query", "form_post"),
      token_endpoint_auth_signing_alg_values_supported = list("RS384", "ES384"),
      token_endpoint_auth_methods_supported = list("client_secret_basic", "private_key_jwt")), auto_unbox = TRUE)
  })
  app$get("/keys", function(req, res) res$send_json(list(keys = list(public)), auto_unbox = TRUE))
  app$get("/ehr-launch", function(req, res) {
    id <- random()
    state$launches[[id]] <- TRUE
    app_origin <- sub("/callback/.*$", "", callback)
    res$set_status(302L)$set_header("Location", paste0(app_origin, "/launch?iss=",
      utils::URLencode(paste0(base(req), "/fhir"), reserved = TRUE), "&launch=", id))$send("")
  })
  authorize <- function(req, res) {
    if (!identical(toupper(req$method), authorization_method)) return(res$set_status(405L)$send("Wrong authorization method"))
    post <- identical(toupper(req$method), "POST")
    if (post && (!identical(req$query, list(tenant = "fixture+value&kept")) ||
        !startsWith(req$get_header("Content-Type"), "application/x-www-form-urlencoded"))) {
      return(res$set_status(400L)$send("Invalid authorization form transport"))
    }
    query <- if (post) req$form else req$query
    scopes <- if (is.character(query$scope)) strsplit(query$scope, " ", fixed = TRUE)[[1L]] else character()
    valid_launch <- if (launch == "ehr") {
      is.character(query$launch) && isTRUE(state$launches[[query$launch]])
    } else is.null(query$launch)
    if (!valid_launch || !identical(query$client_id, site) || !identical(query$redirect_uri, callback) ||
        !identical(query$aud, paste0(base(req), "/fhir")) || !identical(query$response_type, "code") ||
        !identical(query$code_challenge_method, "S256") || !is.character(query$nonce) ||
        !is.character(query$state) || !setequal(scopes, initial_scopes) ||
        !is.character(query$code_challenge) || !grepl("^[A-Za-z0-9_-]{43}$", query$code_challenge)) {
      return(res$set_status(400L)$send("Invalid SMART profile request"))
    }
    if (launch == "ehr") rm(list = query$launch, envir = state$launches)
    metric <- if (post) "authorization_posts" else "authorization_gets"
    state$metrics[[metric]] <- state$metrics[[metric]] + 1L
    if (post) state$metrics$authorization_body_bytes <- as.integer(req$get_header("Content-Length"))
    id <- random()
    state$codes[[id]] <- list(query = query, expires = as.numeric(Sys.time()) + 120)
    res$set_type("text/html")$send(paste0('<!doctype html><html><body><h1 id="provider">Site ', site,
      '</h1><a id="approve" href="/approve?ticket=', id, '">Approve synthetic access</a></body></html>'))
  }
  app$get("/authorize", authorize)
  app$post("/authorize", authorize)
  app$get("/approve", function(req, res) {
    record <- state$codes[[req$query$ticket]]
    if (is.null(record)) return(res$set_status(400L)$send("Unavailable"))
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
    header <- req$get_header("Authorization")
    authenticated <- switch(registration$style,
      public = identical(body$client_id, site) && is.null(header) && is.null(body$client_assertion),
      header = identical(header, paste0("Basic ", openssl::base64_encode(charToRaw(paste0(site, ":", registration$secret))))) &&
        is.null(body$client_secret) && is.null(body$client_assertion),
      private_key_jwt = tryCatch({
        stopifnot(is.null(header), is.null(body$client_secret), is.null(body$client_id),
          identical(body$client_assertion_type, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
        parts <- strsplit(body$client_assertion, ".", fixed = TRUE)[[1L]]
        jwt_header <- jsonlite::fromJSON(rawToChar(decode(parts[[1L]])))
        stopifnot(identical(jwt_header$alg, registration$assertion_alg), identical(jwt_header$kid, "fixture-client"))
        claims <- jose::jwt_decode_sig(body$client_assertion, openssl::read_pubkey(registration$public_pem))
        now <- as.numeric(Sys.time())
        stopifnot(identical(claims$iss, site), identical(claims$sub, site),
          identical(claims$aud, paste0(base(req), "/token")), claims$exp > now,
          claims$exp <= now + 300, is.character(claims$jti), is.null(state$assertions[[claims$jti]]))
        state$assertions[[claims$jti]] <- TRUE
        state$metrics$assertions <- state$metrics$assertions + 1L
        TRUE
      }, error = function(...) FALSE))
    if (!isTRUE(authenticated)) return(res$set_status(400L)$send_json(list(error = "invalid_client"), auto_unbox = TRUE))
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
      grant <- list(revision = 1L, nonce = record$query$nonce)
      scopes <- initial_scopes
    } else if (identical(body$grant_type, "refresh_token")) {
      grant <- state$refresh[[body$refresh_token]]
      if (is.null(grant)) return(res$set_status(400L)$send_json(list(error = "invalid_grant"), auto_unbox = TRUE))
      scopes <- if (is.null(body$scope)) initial_scopes else strsplit(body$scope, " ", fixed = TRUE)[[1L]]
      allowed <- c(initial_scopes, "patient/Patient.r")
      if (!length(scopes) || !all(scopes %in% allowed)) {
        return(res$set_status(400L)$send_json(list(error = "invalid_scope"), auto_unbox = TRUE))
      }
      rm(list = body$refresh_token, envir = state$refresh)
      grant$revision <- grant$revision + 1L
      state$metrics$refreshes <- state$metrics$refreshes + 1L
      if (!is.null(body$scope)) state$metrics$scoped_refreshes <- state$metrics$scoped_refreshes + 1L
    } else return(res$set_status(400L)$send_json(list(error = "unsupported_grant_type"), auto_unbox = TRUE))
    access <- random()
    refresh <- random()
    # Keep the original refresh authorization independently from access scope.
    state$refresh[[refresh]] <- grant
    grant$scopes <- scopes
    state$access[[access]] <- grant
    token <- list(access_token = access, refresh_token = refresh, token_type = "Bearer",
      expires_in = 3600, scope = paste(scopes, collapse = " "))
    if (initial) {
      token$patient <- paste0("synthetic-", site)
      token$encounter <- paste0("encounter-", site)
      token$need_patient_banner <- TRUE
      claims <- jose::jwt_claim(iss = paste0(base(req), "/fhir"), sub = paste0("clinician-", site),
        aud = site, exp = as.numeric(Sys.time()) + 300, iat = as.numeric(Sys.time()),
        nonce = grant$nonce, fhirUser = paste0("Practitioner/clinician-", site))
      token$id_token <- jose::jwt_encode_sig(claims, openssl::read_key(signing_pem), header = list(kid = "fixture-id"))
    }
    res$send_json(token, auto_unbox = TRUE)
  })
  current <- function(req) {
    bearer <- req$get_header("Authorization")
    if (!is.character(bearer) || !startsWith(bearer, "Bearer ")) return(NULL)
    state$access[[substring(bearer, 8L)]]
  }
  app$get("/fhir/Patient/:id", function(req, res) {
    grant <- current(req)
    if (is.null(grant) || !identical(req$params$id, paste0("synthetic-", site)) ||
        !any(c("patient/Patient.rs", "patient/Patient.r") %in% grant$scopes)) return(res$set_status(403L)$send("Denied"))
    state$metrics$reads <- state$metrics$reads + 1L
    res$send_json(list(resourceType = "Patient", id = req$params$id,
      fixture_site = site, fixture_revision = grant$revision), auto_unbox = TRUE)
  })
  app$get("/fhir/Practitioner/:id", function(req, res) {
    grant <- current(req)
    if (is.null(grant) || !identical(req$params$id, paste0("clinician-", site)) ||
        !"user/Practitioner.r" %in% grant$scopes) return(res$set_status(403L)$send("Denied"))
    state$metrics$users <- state$metrics$users + 1L
    res$send_json(list(resourceType = "Practitioner", id = req$params$id, fixture_site = site), auto_unbox = TRUE)
  })
  app$get("/fhir/Patient", function(req, res) {
    grant <- current(req)
    if (is.null(grant) || !"patient/Patient.rs" %in% grant$scopes) return(res$set_status(403L)$send("Denied"))
    state$metrics$searches <- state$metrics$searches + 1L
    res$send_json(list(resourceType = "Bundle", type = "searchset"), auto_unbox = TRUE)
  })
  app$get("/metrics", function(req, res) res$send_json(state$metrics, auto_unbox = TRUE))
  webfakes::new_app_process(app, opts = webfakes::server_opts(remote = TRUE,
    interfaces = "127.0.0.1", num_threads = 4L, access_log_file = FALSE, error_log_file = FALSE))
}
