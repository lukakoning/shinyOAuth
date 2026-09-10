#' Configure ownership of retained OAuth connections
#'
#' Choose who may use saved OAuth connections: the browser that created them,
#' or an account already authenticated by your application. Supply the policy to
#' [oauth_connections()] with the matching retention mode. These factories do not
#' set cookies, authenticate users or enable retention on [oauth_module_server()]
#' calls by themselves.
#'
#' @param idle_timeout Maximum owner inactivity in seconds.
#' @param absolute_timeout Maximum owner lifetime in seconds, independent of
#'   activity. Must be at least `idle_timeout`.
#' @param same_site Owner-cookie policy, `"Lax"` for top-level authorization
#'   navigation or `"Strict"`. Embedded cross-site ownership is not supported.
#' @param allow_http_loopback Explicit development-only exception for HTTP on
#'   localhost or a loopback address. Default `FALSE` requires HTTPS. The exception
#'   cannot provide a Secure, host-prefixed owner cookie.
#' @return An `OAuthOwnerPolicy` configuration object. Browser policies use an
#'   opaque server-issued cookie and server-side owner registry. Account policies
#'   use the trusted local-session resolver described below.
#' @details
#' Browser retention identifies an authorized browser session, not a verified
#' person. The owner cookie is HttpOnly, host-only, has root path and uses Secure
#' and a `__Host-` name on HTTPS. It contains no token or patient data. Server-side
#' idle and absolute limits are authoritative. A cookie is never accepted as an
#' owner without a matching live server record for this application origin.
#'
#' Cookie rotation invalidates the previous session generation immediately and
#' preserves the original absolute lifetime. Local logout removes the live owner
#' session. The manager checks that generation before code exchange and credential
#' commit, with no grace period for pending authorization, and handles credential
#' cleanup after logout. An external provider login cannot
#' establish a local owner or implicitly link browser connections to an account.
#'
#' @seealso [oauth_connection_store_memory()]
#' @export
oauth_browser_owner <- function(
  idle_timeout = 1800,
  absolute_timeout = 28800,
  same_site = c("Lax", "Strict"),
  allow_http_loopback = FALSE
) {
  connection_owner_timeouts(idle_timeout, absolute_timeout)
  same_site <- match.arg(same_site)
  if (
    !is.logical(allow_http_loopback) ||
      length(allow_http_loopback) != 1L ||
      is.na(allow_http_loopback)
  ) {
    err_config("allow_http_loopback must be TRUE or FALSE")
  }
  structure(
    list(
      mode = "browser",
      idle_timeout = idle_timeout,
      absolute_timeout = absolute_timeout,
      same_site = same_site,
      allow_http_loopback = allow_http_loopback
    ),
    class = "OAuthOwnerPolicy"
  )
}

#' @rdname oauth_browser_owner
#' @param resolver Trusted application function accepting the current Shiny
#'   session. On every call it must validate the application's local login and
#'   return `NULL` if unauthenticated, otherwise a plain list containing `subject`,
#'   `session_id`, `generation`, `authenticated_at` and `expires_at`. The first
#'   three are non-empty strings; the timestamps are finite Unix seconds. Subject
#'   is the stable local account ID. Session ID and generation identify the current
#'   local authentication session. Do not derive these from unverified Shiny inputs,
#'   URL values, email addresses or the external provider's token response.
#' @param reauth_after_seconds Maximum age of the verified local authentication,
#'   in seconds. Required for account retention; refresh cannot reset this age.
#' @details
#' Account retention requires finite idle, absolute and local reauthentication
#' lifetimes. The internal session registry re-runs `resolver` when resolving or
#' validating an owner and checks the intended subject/session generation.
#' Expiry or logout retires that generation until a fresh local authentication
#' session is supplied. A resolver error fails closed with a redacted error.
#' The application remains responsible for validating its local session, including
#' signature, expiry, revocation and account changes. Supplying this configuration
#' is not proof that an arbitrary user ID is authenticated.
#' @export
oauth_account_owner <- function(
  resolver,
  idle_timeout,
  absolute_timeout,
  reauth_after_seconds
) {
  connection_owner_timeouts(idle_timeout, absolute_timeout)
  connection_owner_timeouts(reauth_after_seconds, reauth_after_seconds)
  if (!is.function(resolver)) {
    err_config("An account owner requires a trusted session resolver")
  }
  structure(
    list(
      mode = "account",
      resolver = resolver,
      idle_timeout = idle_timeout,
      absolute_timeout = absolute_timeout,
      reauth_after_seconds = reauth_after_seconds
    ),
    class = "OAuthOwnerPolicy"
  )
}

#' @rdname oauth_browser_owner
#' @param x An `OAuthOwnerPolicy` to print.
#' @param ... Unused print arguments.
#' @export
print.OAuthOwnerPolicy <- function(x, ...) {
  cat(
    "<OAuthOwnerPolicy: ",
    x$mode,
    "; local ownership configuration>\n",
    sep = ""
  )
  invisible(x)
}

connection_owner_timeouts <- function(idle, absolute) {
  for (value in list(idle, absolute)) {
    if (
      !is.numeric(value) ||
        length(value) != 1L ||
        !is.finite(value) ||
        value <= 0
    ) {
      err_config("Owner lifetimes must be positive finite seconds")
    }
  }
  if (idle > absolute) {
    err_config("Owner idle timeout cannot exceed absolute timeout")
  }
}

connection_owner_origin <- function(origin, policy) {
  parsed <- resource_binding_components(origin, base = TRUE)
  if (
    parsed$path != "/" ||
      (parsed$scheme != "https" && !isTRUE(policy$allow_http_loopback))
  ) {
    err_config("Owner origin must be HTTPS without a path, query or fragment")
  }
  sub("/$", "", parsed$url)
}

connection_owner_cookie_name <- function(origin, namespace, policy) {
  origin <- connection_owner_origin(origin, policy)
  connection_owner_namespace(namespace)
  suffix <- substr(
    as.character(openssl::sha256(charToRaw(paste(
      origin,
      namespace,
      sep = "\n"
    )))),
    1L,
    24L
  )
  paste0(
    if (startsWith(origin, "https://")) "__Host-" else "",
    "shinyOAuth-owner-",
    suffix
  )
}

connection_owner_namespace <- function(namespace) {
  if (
    !is_valid_string(namespace) ||
      !grepl("^[A-Za-z][A-Za-z0-9_-]{0,63}$", namespace)
  ) {
    err_config("Invalid owner namespace")
  }
  invisible(namespace)
}

connection_owner_cookie_read <- function(req, name) {
  header <- req[["HTTP_COOKIE"]] %||% ""
  if (
    !is.character(header) ||
      length(header) != 1L ||
      is.na(header) ||
      nchar(header, type = "bytes") > 16384L ||
      grepl("[\r\n]", header)
  ) {
    err_token("Invalid owner cookie header")
  }
  parts <- trimws(strsplit(header, ";", fixed = TRUE)[[1L]])
  candidates <- parts[startsWith(parts, paste0(name, "="))]
  if (!length(candidates)) {
    return(NULL)
  }
  if (length(candidates) != 1L) {
    err_token("Ambiguous owner cookie")
  }
  value <- substring(candidates, nchar(name) + 2L)
  if (!grepl("^[A-Za-z0-9_-]{43}$", value)) {
    return(NULL)
  }
  value
}

connection_owner_cookie_header <- function(
  name,
  value,
  origin,
  policy,
  clear = FALSE
) {
  origin <- connection_owner_origin(origin, policy)
  if (
    !is.logical(clear) ||
      length(clear) != 1L ||
      is.na(clear) ||
      !is_valid_string(policy$same_site) ||
      !policy$same_site %in% c("Lax", "Strict") ||
      !is_valid_string(name) ||
      !grepl(
        "^(?:__Host-)?shinyOAuth-owner-[0-9a-f]{24}$",
        name,
        perl = TRUE
      ) ||
      (!clear &&
        (!is_valid_string(value) || !grepl("^[A-Za-z0-9_-]{43}$", value)))
  ) {
    err_input("Invalid owner cookie configuration")
  }
  paste0(
    name,
    "=",
    if (clear) "" else value,
    "; Path=/; HttpOnly; SameSite=",
    policy$same_site,
    if (startsWith(origin, "https://")) "; Secure" else "",
    if (clear) "; Max-Age=0" else ""
  )
}

connection_browser_sessions <- function(
  policy,
  origin,
  namespace,
  key,
  max_entries = 1000L,
  clock = function() as.numeric(Sys.time())
) {
  if (
    !inherits(policy, "OAuthOwnerPolicy") || !identical(policy$mode, "browser")
  ) {
    err_config("Browser sessions require a browser owner policy")
  }
  origin <- connection_owner_origin(origin, policy)
  cookie_name <- connection_owner_cookie_name(origin, namespace, policy)
  if (!is.raw(key) || length(key) != 32L) {
    err_config("Owner sessions require a 32-byte deployment key")
  }
  connection_owner_capacity(max_entries)
  digest_key <- as.raw(openssl::sha256(
    charToRaw(paste(
      "shinyOAuth/owner-cookie/v1",
      origin,
      namespace,
      sep = "\n"
    )),
    key = key
  ))
  key <- NULL
  owners <- new.env(parent = emptyenv())
  cookies <- new.env(parent = emptyenv())
  process <- Sys.getpid()
  now <- function() connection_owner_now(process, clock)
  digest <- function(cookie) {
    as.character(openssl::sha256(charToRaw(cookie), key = digest_key))
  }
  snapshot <- function(record) {
    record[c("id", "generation", "created_at", "expires_at")]
  }
  expire <- function(id) {
    record <- owners[[id]]
    if (!is.null(record)) {
      rm(list = record$cookie_digest, envir = cookies)
      rm(list = id, envir = owners)
    }
    invisible(NULL)
  }
  current <- function(id, touch = FALSE) {
    at <- now()
    record <- owners[[id]]
    if (is.null(record)) {
      return(NULL)
    }
    if (
      at >= record$expires_at || at >= record$last_seen + policy$idle_timeout
    ) {
      expire(id)
      return(NULL)
    }
    if (touch) {
      record$last_seen <- at
      owners[[id]] <- record
    }
    record
  }
  validate <- function(owner, touch = FALSE) {
    if (
      !is.list(owner) ||
        !is_valid_string(owner$id) ||
        !is_valid_string(owner$generation)
    ) {
      return(NULL)
    }
    record <- current(owner$id)
    if (is.null(record) || !identical(record$generation, owner$generation)) {
      return(NULL)
    }
    snapshot(current(owner$id, touch))
  }
  resolve <- function(cookie, touch = FALSE) {
    now()
    if (!is_valid_string(cookie) || !grepl("^[A-Za-z0-9_-]{43}$", cookie)) {
      return(NULL)
    }
    id <- cookies[[digest(cookie)]]
    if (is.null(id)) {
      return(NULL)
    }
    record <- current(id, touch)
    if (is.null(record)) {
      return(NULL)
    }
    snapshot(record)
  }
  issue <- function(record) {
    cookie <- random_urlsafe(43L)
    cookie_digest <- digest(cookie)
    # Prepare randomness before replacing an existing cookie mapping.
    if (!is.null(record$cookie_digest)) {
      rm(list = record$cookie_digest, envir = cookies)
    }
    record$cookie_digest <- cookie_digest
    owners[[record$id]] <- record
    cookies[[record$cookie_digest]] <- record$id
    list(cookie = cookie, owner = snapshot(record))
  }
  create <- function() {
    at <- now()
    for (id in ls(owners, all.names = TRUE)) {
      current(id)
    }
    if (length(owners) >= max_entries) {
      err_token("Owner session capacity reached")
    }
    issue(list(
      id = random_urlsafe(32L),
      generation = random_urlsafe(32L),
      created_at = at,
      last_seen = at,
      expires_at = at + policy$absolute_timeout
    ))
  }
  rotate <- function(owner) {
    verified <- validate(owner)
    if (is.null(verified)) {
      err_token("Owner session is unavailable")
    }
    record <- current(owner$id)
    record$generation <- random_urlsafe(32L)
    record$last_seen <- now()
    issue(record)
  }
  revoke <- function(owner) {
    verified <- validate(owner)
    if (is.null(verified)) {
      return(FALSE)
    }
    expire(owner$id)
    TRUE
  }
  list(
    cookie_name = cookie_name,
    origin = origin,
    create = create,
    resolve = resolve,
    validate = validate,
    rotate = rotate,
    revoke = revoke
  )
}

connection_account_identity <- function(
  policy,
  session,
  origin,
  namespace,
  key,
  clock = function() as.numeric(Sys.time())
) {
  if (
    !inherits(policy, "OAuthOwnerPolicy") || !identical(policy$mode, "account")
  ) {
    err_config("Account ownership requires an account owner policy")
  }
  origin <- connection_owner_origin(origin, policy)
  connection_owner_namespace(namespace)
  if (!is.raw(key) || length(key) != 32L) {
    err_config("Account owners require a 32-byte deployment key")
  }
  identity <- tryCatch(policy$resolver(session), error = function(...) {
    err_token("Local account session validation failed")
  })
  if (is.null(identity)) {
    return(NULL)
  }
  fields <- c(
    "subject",
    "session_id",
    "generation",
    "authenticated_at",
    "expires_at"
  )
  if (
    !is.list(identity) ||
      is.object(identity) ||
      !setequal(names(identity), fields) ||
      anyDuplicated(names(identity))
  ) {
    err_token("Invalid local account session")
  }
  for (name in c("subject", "session_id", "generation")) {
    value <- identity[[name]]
    if (
      !is_valid_string(value) ||
        nchar(value, type = "bytes") > 1024L ||
        grepl("[[:cntrl:]]", value)
    ) {
      err_token("Invalid local account session")
    }
  }
  for (name in c("authenticated_at", "expires_at")) {
    value <- identity[[name]]
    if (!is.numeric(value) || length(value) != 1L || !is.finite(value)) {
      err_token("Invalid local account session")
    }
  }
  at <- clock()
  if (
    identity$authenticated_at > at ||
      identity$authenticated_at < 0 ||
      identity$expires_at <= at ||
      at >= identity$authenticated_at + policy$reauth_after_seconds
  ) {
    return(NULL)
  }
  make_id <- function(values) {
    unclass(as.character(openssl::sha256(
      charToRaw(as.character(
        jsonlite::toJSON(values, auto_unbox = TRUE, digits = NA)
      )),
      key = key
    )))
  }
  list(
    id = make_id(list(
      purpose = "shinyOAuth/account-owner/v1",
      origin = origin,
      namespace = namespace,
      subject = identity$subject
    )),
    generation = make_id(list(
      purpose = "shinyOAuth/account-session/v1",
      origin = origin,
      namespace = namespace,
      subject = identity$subject,
      session = identity$session_id,
      generation = identity$generation,
      authenticated_at = identity$authenticated_at
    )),
    authenticated_at = identity$authenticated_at,
    expires_at = min(
      identity$expires_at,
      identity$authenticated_at + policy$reauth_after_seconds
    )
  )
}

connection_owner_capacity <- function(max_entries) {
  if (
    !is.numeric(max_entries) ||
      length(max_entries) != 1L ||
      !is.finite(max_entries) ||
      max_entries < 1 ||
      max_entries != floor(max_entries)
  ) {
    err_config("Invalid owner session capacity")
  }
}

connection_owner_now <- function(process, clock) {
  if (!identical(process, Sys.getpid())) {
    err_config("Owner sessions are process-local")
  }
  at <- clock()
  if (!is.numeric(at) || length(at) != 1L || !is.finite(at) || at < 0) {
    err_config("Invalid owner session clock")
  }
  at
}

# A retired local login must not be re-enrolled simply because the application's
# resolver still returns it. Keep retirement metadata until that authentication
# is too old to resolve, including when the shorter owner idle lifetime expires.
connection_account_sessions <- function(
  policy,
  origin,
  namespace,
  key,
  max_entries = 1000L,
  clock = function() as.numeric(Sys.time())
) {
  if (
    !inherits(policy, "OAuthOwnerPolicy") || !identical(policy$mode, "account")
  ) {
    err_config("Account sessions require an account owner policy")
  }
  origin <- connection_owner_origin(origin, policy)
  connection_owner_namespace(namespace)
  connection_owner_capacity(max_entries)
  if (!is.raw(key) || length(key) != 32L) {
    err_config("Account owners require a 32-byte deployment key")
  }
  records <- new.env(parent = emptyenv())
  process <- Sys.getpid()
  now <- function() connection_owner_now(process, clock)
  identity <- function(session) {
    now()
    connection_account_identity(policy, session, origin, namespace, key, now)
  }
  snapshot <- function(record) {
    record[c(
      "id",
      "generation",
      "authenticated_at",
      "created_at",
      "expires_at"
    )]
  }
  lookup <- function(verified, touch = FALSE, establish = FALSE) {
    if (is.null(verified)) {
      return(NULL)
    }
    at <- now()
    record <- records[[verified$generation]]
    if (is.null(record)) {
      if (!establish) {
        return(NULL)
      }
      for (generation in ls(records, all.names = TRUE)) {
        if (at >= records[[generation]]$retain_until) {
          rm(list = generation, envir = records)
        }
      }
      if (length(records) >= max_entries) {
        err_token("Owner session capacity reached")
      }
      record <- c(
        verified,
        list(
          created_at = at,
          last_seen = at,
          retain_until = verified$authenticated_at +
            policy$reauth_after_seconds,
          retired = FALSE
        )
      )
      record$expires_at <- min(
        verified$expires_at,
        at + policy$absolute_timeout
      )
    }
    if (!identical(record$id, verified$id)) {
      err_token("Owner session is unavailable")
    }
    record$expires_at <- min(record$expires_at, verified$expires_at)
    if (
      at >= record$expires_at || at >= record$last_seen + policy$idle_timeout
    ) {
      record$retired <- TRUE
    }
    if (touch && !record$retired) {
      record$last_seen <- at
    }
    records[[record$generation]] <- record
    if (record$retired) NULL else snapshot(record)
  }
  resolve <- function(session, touch = FALSE) {
    lookup(identity(session), touch)
  }
  establish <- function(session) {
    lookup(identity(session), touch = TRUE, establish = TRUE)
  }
  validate <- function(owner, session, touch = FALSE) {
    verified <- identity(session)
    if (
      is.null(verified) ||
        !is.list(owner) ||
        !identical(owner$id, verified$id) ||
        !identical(owner$generation, verified$generation)
    ) {
      return(NULL)
    }
    lookup(verified, touch)
  }
  revoke <- function(owner) {
    now()
    if (!is.list(owner) || !is_valid_string(owner$generation)) {
      return(FALSE)
    }
    record <- records[[owner$generation]]
    if (is.null(record) || !identical(record$id, owner$id) || record$retired) {
      return(FALSE)
    }
    record$retired <- TRUE
    records[[record$generation]] <- record
    TRUE
  }
  list(
    establish = establish,
    resolve = resolve,
    validate = validate,
    revoke = revoke
  )
}
