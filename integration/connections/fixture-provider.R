# Synthetic OAuth provider for the browser-retention gate, bound to loopback.
# This verifies real HTTP, PKCE and credential rotation; it is not conformance tooling.
retention_fixture_provider <- function(site, callback, shared_issuer = FALSE, scope_narrowing = FALSE) {
  registrations <- if (shared_issuer) c("a", "b") else site
  original_scopes <- if (scope_narrowing) c("read", "write") else "read"
  state <- new.env(parent = emptyenv())
  state$codes <- new.env(parent = emptyenv())
  state$access <- new.env(parent = emptyenv())
  state$refresh <- new.env(parent = emptyenv())
  state$metrics <- list(
    exchanges = 0L,
    refreshes = 0L,
    requests = 0L,
    revocations = 0L,
    scoped_refreshes = 0L,
    omitted_refreshes = 0L,
    writes = 0L
  )
  random <- function() {
    unclass(as.character(openssl::sha256(openssl::rand_bytes(32))))
  }
  issue <- function(revision, registration, scopes = original_scopes) {
    access <- random()
    refresh <- random()
    state$access[[access]] <- list(revision = revision, site = registration, scopes = scopes)
    # RFC 6749: narrowing the access token does not reduce refresh-token scope.
    state$refresh[[refresh]] <- list(revision = revision, site = registration)
    list(
      access_token = access,
      refresh_token = refresh,
      token_type = "Bearer",
      expires_in = 3600,
      scope = paste(scopes, collapse = " ")
    )
  }
  app <- webfakes::new_app()
  app$use(webfakes::mw_urlencoded())
  app$use(function(req, res) {
    res$set_header("Cache-Control", "no-store")
    res$set_header("Referrer-Policy", "no-referrer")
    "next"
  })
  app$get("/authorize", function(req, res) {
    query <- req$query
    if (
      !query$client_id %in% registrations ||
        !identical(query$redirect_uri, callback) ||
        !identical(query$response_type, "code") ||
        !identical(query$code_challenge_method, "S256") ||
        !is.character(query$code_challenge) ||
        !grepl("^[A-Za-z0-9_-]{43}$", query$code_challenge) ||
        !is.character(query$state) ||
        nchar(query$state) > 16384
    ) {
      return(res$set_status(400L)$send("Invalid fixture authorization"))
    }
    code <- random()
    state$codes[[code]] <- list(
      query = query,
      expires = as.numeric(Sys.time()) + 120
    )
    res$set_type("text/html")$send(paste0(
      '<!doctype html><html><body><h1 id="provider">Site ',
      query$client_id,
      '</h1><a id="approve" href="/approve?ticket=',
      code,
      '">Approve synthetic access</a></body></html>'
    ))
  })
  app$get("/approve", function(req, res) {
    ticket <- req$query$ticket
    record <- state$codes[[ticket]]
    if (is.null(record) || record$expires <= as.numeric(Sys.time())) {
      return(res$set_status(400L)$send("Expired fixture authorization"))
    }
    issuer <- if (shared_issuer) paste0("http://", req$get_header("Host")) else NULL
    if (identical(record$query$response_mode, "form_post")) {
      escape <- function(value) htmltools::htmlEscape(value, attribute = TRUE)
      return(res$set_type("text/html")$send(paste0(
        '<!doctype html><html><body><form method="post" action="',
        escape(callback),
        '"><input name="code" type="hidden" value="',
        escape(ticket),
        '"><input name="state" type="hidden" value="',
        escape(record$query$state),
        '">',
        if (shared_issuer) paste0('<input name="iss" type="hidden" value="', escape(issuer), '">'),
        '</form><script>document.forms[0].submit()</script></body></html>'
      )))
    }
    location <- paste0(
      callback,
      "?code=",
      ticket,
      "&state=",
      utils::URLencode(record$query$state, reserved = TRUE),
      if (shared_issuer) paste0("&iss=", utils::URLencode(issuer, reserved = TRUE))
    )
    res$set_status(302L)$set_header("Location", location)$send("")
  })
  app$post("/token", function(req, res) {
    body <- req$form
    if (!body$client_id %in% registrations) {
      return(res$set_status(400L)$send_json(
        list(error = "invalid_client"),
        auto_unbox = TRUE
      ))
    }
    if (identical(body$grant_type, "authorization_code")) {
      record <- state$codes[[body$code]]
      challenge <- if (is.character(body$code_verifier)) {
        gsub(
          "=+$",
          "",
          chartr(
            "+/",
            "-_",
            openssl::base64_encode(
              openssl::sha256(charToRaw(body$code_verifier))
            )
          )
        )
      } else {
        NULL
      }
      if (
        is.null(record) ||
          record$expires <= as.numeric(Sys.time()) ||
          !identical(body$client_id, record$query$client_id) ||
          !identical(body$redirect_uri, callback) ||
          !identical(challenge, record$query$code_challenge)
      ) {
        return(res$set_status(400L)$send_json(
          list(error = "invalid_grant"),
          auto_unbox = TRUE
        ))
      }
      rm(list = body$code, envir = state$codes)
      state$metrics$exchanges <- state$metrics$exchanges + 1L
      token <- issue(1L, body$client_id)
    } else if (identical(body$grant_type, "refresh_token")) {
      record <- state$refresh[[body$refresh_token]]
      if (is.null(record) || !identical(body$client_id, record$site)) {
        return(res$set_status(400L)$send_json(
          list(error = "invalid_grant"),
          auto_unbox = TRUE
        ))
      }
      scopes <- if (is.null(body$scope)) original_scopes else strsplit(body$scope, " ", fixed = TRUE)[[1L]]
      if (!length(scopes) || !all(scopes %in% original_scopes)) {
        return(res$set_status(400L)$send_json(list(error = "invalid_scope"), auto_unbox = TRUE))
      }
      metric <- if (is.null(body$scope)) "omitted_refreshes" else "scoped_refreshes"
      state$metrics[[metric]] <- state$metrics[[metric]] + 1L
      rm(list = body$refresh_token, envir = state$refresh)
      state$metrics$refreshes <- state$metrics$refreshes + 1L
      token <- issue(record$revision + 1L, body$client_id, scopes)
    } else {
      return(res$set_status(400L)$send_json(
        list(error = "unsupported_grant_type"),
        auto_unbox = TRUE
      ))
    }
    res$send_json(token, auto_unbox = TRUE)
  })
  resource <- function(req, res) {
    bearer <- sub("^Bearer ", "", req$get_header("Authorization"))
    record <- if (is.character(bearer) && length(bearer) == 1L) {
      state$access[[bearer]]
    } else {
      NULL
    }
    resource_site <- if (shared_issuer) req$params$site else site
    if (is.null(record) || !identical(record$site, resource_site) || !"read" %in% record$scopes) {
      return(res$set_status(401L)$send("Unauthorized"))
    }
    state$metrics$requests <- state$metrics$requests + 1L
    res$send_json(list(site = record$site, revision = record$revision), auto_unbox = TRUE)
  }
  app$get(if (shared_issuer) "/api/:site/records" else "/api/records", resource)
  app$post(if (shared_issuer) "/api/:site/records" else "/api/records", function(req, res) {
    bearer <- sub("^Bearer ", "", req$get_header("Authorization"))
    record <- if (is.character(bearer) && length(bearer) == 1L) state$access[[bearer]] else NULL
    resource_site <- if (shared_issuer) req$params$site else site
    if (is.null(record) || !identical(record$site, resource_site) || !"write" %in% record$scopes) {
      return(res$set_status(403L)$send("Forbidden"))
    }
    state$metrics$writes <- state$metrics$writes + 1L
    res$send_json(list(site = record$site), auto_unbox = TRUE)
  })
  app$post("/revoke", function(req, res) {
    token <- req$form$token
    for (store in list(state$refresh, state$access)) {
      if (is.character(token) && exists(token, store, inherits = FALSE)) {
        rm(list = token, envir = store)
      }
    }
    state$metrics$revocations <- state$metrics$revocations + 1L
    res$send("")
  })
  app$get("/metrics", function(req, res) {
    res$send_json(state$metrics, auto_unbox = TRUE)
  })
  webfakes::new_app_process(
    app,
    opts = webfakes::server_opts(
      remote = TRUE,
      interfaces = "127.0.0.1",
      # Chrome may open speculative idle sockets while R exchanges a code.
      num_threads = 4L,
      access_log_file = FALSE,
      error_log_file = FALSE
    )
  )
}
