# Synthetic OAuth provider for the browser-retention gate, bound to loopback.
# This verifies real HTTP, PKCE and credential rotation; it is not conformance tooling.
retention_fixture_provider <- function(site, callback) {
  state <- new.env(parent = emptyenv())
  state$codes <- new.env(parent = emptyenv())
  state$access <- new.env(parent = emptyenv())
  state$refresh <- new.env(parent = emptyenv())
  state$metrics <- list(
    exchanges = 0L,
    refreshes = 0L,
    requests = 0L,
    revocations = 0L
  )
  random <- function() {
    unclass(as.character(openssl::sha256(openssl::rand_bytes(32))))
  }
  issue <- function(revision) {
    access <- random()
    refresh <- random()
    state$access[[access]] <- revision
    state$refresh[[refresh]] <- revision
    list(
      access_token = access,
      refresh_token = refresh,
      token_type = "Bearer",
      expires_in = 3600,
      scope = "read"
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
      !identical(query$client_id, site) ||
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
      site,
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
    if (identical(record$query$response_mode, "form_post")) {
      escape <- function(value) htmltools::htmlEscape(value, attribute = TRUE)
      return(res$set_type("text/html")$send(paste0(
        '<!doctype html><html><body><form method="post" action="',
        escape(callback),
        '"><input name="code" type="hidden" value="',
        escape(ticket),
        '"><input name="state" type="hidden" value="',
        escape(record$query$state),
        '"></form><script>document.forms[0].submit()</script></body></html>'
      )))
    }
    location <- paste0(
      callback,
      "?code=",
      ticket,
      "&state=",
      utils::URLencode(record$query$state, reserved = TRUE)
    )
    res$set_status(302L)$set_header("Location", location)$send("")
  })
  app$post("/token", function(req, res) {
    body <- req$form
    if (!identical(body$client_id, site)) {
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
      token <- issue(1L)
    } else if (identical(body$grant_type, "refresh_token")) {
      revision <- state$refresh[[body$refresh_token]]
      if (is.null(revision)) {
        return(res$set_status(400L)$send_json(
          list(error = "invalid_grant"),
          auto_unbox = TRUE
        ))
      }
      rm(list = body$refresh_token, envir = state$refresh)
      state$metrics$refreshes <- state$metrics$refreshes + 1L
      token <- issue(revision + 1L)
    } else {
      return(res$set_status(400L)$send_json(
        list(error = "unsupported_grant_type"),
        auto_unbox = TRUE
      ))
    }
    res$send_json(token, auto_unbox = TRUE)
  })
  app$get("/api/records", function(req, res) {
    bearer <- sub("^Bearer ", "", req$get_header("Authorization"))
    revision <- if (is.character(bearer) && length(bearer) == 1L) {
      state$access[[bearer]]
    } else {
      NULL
    }
    if (is.null(revision)) {
      return(res$set_status(401L)$send("Unauthorized"))
    }
    state$metrics$requests <- state$metrics$requests + 1L
    res$send_json(list(site = site, revision = revision), auto_unbox = TRUE)
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
