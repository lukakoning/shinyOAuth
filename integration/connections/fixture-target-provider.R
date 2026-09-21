# Synthetic loopback provider for target acquisition and replacement browser tests.
target_fixture_provider <- function(site, callback) {
  state <- new.env(parent = emptyenv())
  for (name in c("codes", "access", "refresh")) {
    state[[name]] <- new.env(parent = emptyenv())
  }
  state[["delay"]] <- 0
  state[["metrics"]] <- list(
    exchanges = 0L,
    refreshes = 0L,
    requests = 0L,
    authorization_scopes = list()
  )
  random <- function() {
    unclass(as.character(openssl::sha256(openssl::rand_bytes(32))))
  }
  scopes_for <- function(target) {
    switch(
      target,
      calendar = c("calendar.read", "calendar.write"),
      contacts = "contacts.read",
      character()
    )
  }
  issue <- function(target, scopes, grant) {
    access <- random()
    refresh <- random()
    state[["access"]][[access]] <- list(target = target, scopes = scopes)
    state[["refresh"]][[refresh]] <- grant
    list(
      access_token = access,
      refresh_token = refresh,
      token_type = "Bearer",
      expires_in = 3600,
      scope = paste(scopes, collapse = " ")
    )
  }
  redirect <- function(res, query, fields) {
    fields[["state"]] <- query[["state"]]
    if (identical(query[["response_mode"]], "form_post")) {
      inputs <- vapply(
        names(fields),
        function(name) {
          paste0(
            '<input type="hidden" name="',
            name,
            '" value="',
            htmltools::htmlEscape(fields[[name]], attribute = TRUE),
            '">'
          )
        },
        ""
      )
      return(res[["set_type"]]("text/html")[["send"]](paste0(
        '<form method="post" action="',
        callback,
        '">',
        paste(inputs, collapse = ""),
        '</form><script>document.forms[0].submit()</script>'
      )))
    }
    location <- paste0(
      callback,
      "?",
      paste(
        paste0(
          names(fields),
          "=",
          vapply(fields, utils::URLencode, "", reserved = TRUE)
        ),
        collapse = "&"
      )
    )
    res[["set_status"]](302L)[["set_header"]]("Location", location)[["send"]](
      ""
    )
  }
  app <- webfakes::new_app()
  app[["use"]](webfakes::mw_urlencoded())
  app[["get"]]("/authorize", function(req, res) {
    query <- req[["query"]]
    scopes <- strsplit(query[["scope"]], " ", fixed = TRUE)[[1L]]
    if (
      !identical(query[["client_id"]], site) ||
        !identical(query[["redirect_uri"]], callback) ||
        !identical(query[["code_challenge_method"]], "S256") ||
        !all(scopes %in% c(scopes_for("calendar"), scopes_for("contacts")))
    ) {
      return(res[["set_status"]](400L)[["send"]](
        "Invalid fixture authorization"
      ))
    }
    ticket <- random()
    state[["codes"]][[ticket]] <- query
    state[["metrics"]][["authorization_scopes"]] <- c(
      state[["metrics"]][["authorization_scopes"]],
      list(query[["scope"]])
    )
    res[["set_type"]]("text/html")[["send"]](paste0(
      '<h1 id="provider">Site ',
      site,
      '</h1><a id="approve" href="/approve?ticket=',
      ticket,
      '">Approve</a><a id="deny" href="/deny?ticket=',
      ticket,
      '">Deny</a>'
    ))
  })
  app[["get"]]("/approve", function(req, res) {
    ticket <- req[["query"]][["ticket"]]
    redirect(res, state[["codes"]][[ticket]], list(code = ticket))
  })
  app[["get"]]("/deny", function(req, res) {
    ticket <- req[["query"]][["ticket"]]
    query <- state[["codes"]][[ticket]]
    rm(list = ticket, envir = state[["codes"]])
    redirect(res, query, list(error = "access_denied"))
  })
  app[["post"]]("/token", function(req, res) {
    body <- req[["form"]]
    target <- sub("urn:", "", body[["resource"]], fixed = TRUE)
    scopes <- strsplit(body[["scope"]], " ", fixed = TRUE)[[1L]]
    reject <- function() {
      res[["set_status"]](400L)[["send_json"]](
        list(error = "invalid_grant"),
        auto_unbox = TRUE
      )
    }
    if (
      !identical(body[["client_id"]], site) ||
        !length(scopes_for(target)) ||
        !all(scopes %in% scopes_for(target))
    ) {
      return(reject())
    }
    if (identical(body[["grant_type"]], "authorization_code")) {
      query <- state[["codes"]][[body[["code"]]]]
      challenge <- gsub(
        "=+$",
        "",
        chartr(
          "+/",
          "-_",
          openssl::base64_encode(openssl::sha256(charToRaw(body[[
            "code_verifier"
          ]])))
        )
      )
      if (
        is.null(query) ||
          !identical(challenge, query[["code_challenge"]]) ||
          !identical(body[["redirect_uri"]], callback)
      ) {
        return(reject())
      }
      grant <- strsplit(query[["scope"]], " ", fixed = TRUE)[[1L]]
      if (!all(scopes %in% grant)) {
        return(reject())
      }
      rm(list = body[["code"]], envir = state[["codes"]])
      state[["metrics"]][["exchanges"]] <- state[["metrics"]][["exchanges"]] +
        1L
    } else {
      grant <- state[["refresh"]][[body[["refresh_token"]]]]
      if (is.null(grant) || !all(scopes %in% grant)) {
        return(reject())
      }
      rm(list = body[["refresh_token"]], envir = state[["refresh"]])
      state[["metrics"]][["refreshes"]] <- state[["metrics"]][["refreshes"]] +
        1L
      if (target == "contacts") Sys.sleep(state[["delay"]])
    }
    res[["send_json"]](issue(target, scopes, grant), auto_unbox = TRUE)
  })
  app[["get"]]("/api/:target/records", function(req, res) {
    access <- sub("^Bearer ", "", req[["get_header"]]("Authorization"))
    record <- state[["access"]][[access]]
    target <- req[["params"]][["target"]]
    if (
      is.null(record) ||
        !identical(record[["target"]], target) ||
        !paste0(target, ".read") %in% record[["scopes"]]
    ) {
      return(res[["set_status"]](401L)[["send"]]("Unauthorized"))
    }
    state[["metrics"]][["requests"]] <- state[["metrics"]][["requests"]] + 1L
    res[["send_json"]](list(target = target), auto_unbox = TRUE)
  })
  app[["post"]]("/revoke", function(req, res) {
    token <- req[["form"]][["token"]]
    for (name in c("access", "refresh")) {
      if (exists(token, state[[name]], inherits = FALSE)) {
        rm(list = token, envir = state[[name]])
      }
    }
    res[["send"]]("")
  })
  app[["post"]]("/delay", function(req, res) {
    state[["delay"]] <- min(5, max(0, as.numeric(req[["form"]][["seconds"]])))
    res[["send"]]("")
  })
  app[["get"]]("/metrics", function(req, res) {
    res[["send_json"]](state[["metrics"]], auto_unbox = TRUE)
  })
  webfakes::new_app_process(
    app,
    opts = webfakes::server_opts(
      remote = TRUE,
      interfaces = "127.0.0.1",
      num_threads = 4L,
      access_log_file = FALSE,
      error_log_file = FALSE
    )
  )
}
