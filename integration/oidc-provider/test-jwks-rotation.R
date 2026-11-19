source(
  if (file.exists("helper-jwks-rotation.R")) {
    "helper-jwks-rotation.R"
  } else {
    "integration/oidc-provider/helper-jwks-rotation.R"
  },
  local = TRUE
)

rotation_example <- function() {
  old <- paste(rep("a", 32), collapse = "")
  new <- paste(rep("b", 32), collapse = "")
  issuer <- "https://localhost:30000"
  uri <- paste0(issuer, "/jwks")
  entry <- function(kid, fetched, observed) {
    list(
      entry_hash = paste0(kid, kid),
      fetched_at = fetched,
      observed_at = observed,
      usable = TRUE,
      origin_freshness_unbounded = TRUE,
      kids = list(kid),
      jwks_uri = uri,
      discovery_issuer = issuer
    )
  }
  login <- function(kid) {
    list(
      authenticated = TRUE,
      id_token_validated = TRUE,
      kid = kid,
      subject_matches = TRUE,
      issuer_matches = TRUE,
      audience_matches = TRUE,
      state_matches = TRUE,
      pending_before = 1L,
      pending_after = 0L
    )
  }
  authorization <- list(
    type = "authorization.accepted",
    client_matches = TRUE,
    code_flow = TRUE,
    pkce_s256 = TRUE,
    state_present = TRUE,
    nonce_present = TRUE
  )
  grant <- list(
    type = "grant.success",
    client_matches = TRUE,
    authentication_valid = TRUE,
    pkce_verified = TRUE,
    code_matches = TRUE,
    access_token_present = TRUE,
    id_token_present = TRUE,
    grant_type = "authorization_code"
  )
  jwks <- function(kid) {
    list(
      type = "jwks",
      status = 200L,
      kids = list(kid),
      cache_control = NULL,
      expires = NULL
    )
  }
  request <- function(kid, cached) {
    list(
      url = uri,
      entry = cached,
      status = 200L,
      cache_control = NULL,
      expires = NULL,
      kids = list(kid)
    )
  }
  first <- entry(old, 100, 101)
  retained <- entry(old, 100, 104)
  list(
    scope = "native_oidc_provider_warm_jwks_rotation_sync",
    run_id = old,
    issuer = issuer,
    jwks_uri = uri,
    backend_max_age = 3600,
    origin_freshness = "absent_default_backend_policy",
    same_cache_identity = TRUE,
    same_issuer = TRUE,
    no_cache_configuration_override = TRUE,
    browser_cookie_check_bypassed = TRUE,
    no_browser_or_worker_credit = TRUE,
    logins = list(login(old), login(old), login(new)),
    provider_before = list(
      run_id = old,
      jwks_rotation = list(
        instance_id = old,
        active_kid = old,
        issuer = issuer
      ),
      events = list(authorization, grant, jwks(old), authorization, grant)
    ),
    provider_after_restart = list(
      run_id = old,
      jwks_rotation = list(
        instance_id = new,
        active_kid = new,
        issuer = issuer
      ),
      events = list()
    ),
    provider_after = list(
      run_id = old,
      jwks_rotation = list(
        instance_id = new,
        active_kid = new,
        issuer = issuer
      ),
      events = list(authorization, grant, jwks(new))
    ),
    populated = first,
    warm = entry(old, 100, 102),
    before_rotated_login = retained,
    refreshed = entry(new, 105, 106),
    fetch_calls = list(
      list(force_refresh = FALSE, entry = NULL),
      list(force_refresh = FALSE, entry = first),
      list(force_refresh = FALSE, entry = retained),
      list(force_refresh = TRUE, entry = retained)
    ),
    requests = list(request(old, NULL), request(new, retained)),
    pre_rotation_requests = 1L,
    post_restart_requests = 0L,
    post_rogue_requests = 1L,
    throttle_before = NULL,
    throttle_after = 104.5,
    rogues = list(
      list(
        kid = old,
        rejected = TRUE,
        error_class = "shinyOAuth_id_token_error",
        reason = "unknown_kid"
      ),
      list(
        kid = new,
        rejected = TRUE,
        error_class = "shinyOAuth_id_token_error",
        reason = "signature"
      )
    )
  )
}

testthat::test_that("warm proof survives JSON but two fresh downloads cannot replace an observed hit", {
  proof <- rotation_example()
  testthat::expect_true(rotation_check(proof))
  serialized <- jsonlite::fromJSON(
    as.character(jsonlite::toJSON(proof, auto_unbox = TRUE, null = "null")),
    simplifyVector = FALSE
  )
  testthat::expect_true(rotation_check(serialized))
  for (mutate in list(
    function(x) {
      x[["warm"]][["entry_hash"]] <- "refetched"
      x
    },
    function(x) {
      x[["warm"]][["fetched_at"]] <- 102
      x
    },
    function(x) {
      x[["pre_rotation_requests"]] <- 2L
      x
    },
    function(x) {
      x[["requests"]] <- append(x[["requests"]], x[["requests"]][1L])
      x
    },
    function(x) {
      x[["before_rotated_login"]][["usable"]] <- FALSE
      x
    },
    function(x) {
      x[["requests"]][[2L]][["entry"]] <- NULL
      x
    },
    function(x) {
      x[["fetch_calls"]][[4L]][["entry"]][["usable"]] <- FALSE
      x
    },
    function(x) {
      x[["fetch_calls"]][[4L]][["force_refresh"]] <- FALSE
      x
    },
    function(x) {
      x[["same_cache_identity"]] <- FALSE
      x
    },
    function(x) {
      x[["backend_max_age"]] <- 999999
      x
    },
    function(x) {
      x[["no_cache_configuration_override"]] <- FALSE
      x
    }
  )) {
    testthat::expect_error(rotation_check(mutate(proof)), "proof failed")
  }
})

testthat::test_that("rotation proof binds native provider observations and trusted fresh-key refresh", {
  proof <- rotation_example()
  for (mutate in list(
    function(x) {
      x[["provider_after"]][["jwks_rotation"]][["instance_id"]] <-
        x[["provider_before"]][["jwks_rotation"]][["instance_id"]]
      x
    },
    function(x) {
      x[["provider_after"]][["jwks_rotation"]][["active_kid"]] <-
        x[["provider_before"]][["jwks_rotation"]][["active_kid"]]
      x
    },
    function(x) {
      x[["provider_after_restart"]][["events"]] <- list(list(type = "jwks"))
      x
    },
    function(x) {
      x[["provider_after_restart"]][["jwks_rotation"]][[
        "issuer"
      ]] <- "https://attacker.invalid"
      x
    },
    function(x) {
      x[["provider_after"]][["run_id"]] <- "unrelated"
      x
    },
    function(x) {
      x[["provider_before"]][["events"]][[3L]][["cache_control"]] <- "no-cache"
      x
    },
    function(x) {
      x[["provider_after"]][["events"]][[3L]][["expires"]] <- "stale"
      x
    },
    function(x) {
      x[["provider_after"]][["events"]][[3L]][["kids"]] <- list("other")
      x
    },
    function(x) {
      x[["provider_before"]][["events"]] <- x[["provider_before"]][["events"]][
        -3L
      ]
      x
    },
    function(x) {
      x[["provider_after"]][["events"]][[2L]][["pkce_verified"]] <- FALSE
      x
    },
    function(x) {
      x[["provider_after"]][["events"]][[1L]][["nonce_present"]] <- FALSE
      x
    },
    function(x) {
      x[["requests"]][[2L]][["url"]] <- "https://attacker.invalid/jwks"
      x
    },
    function(x) {
      x[["requests"]][[2L]][["cache_control"]] <- "no-store"
      x
    },
    function(x) {
      x[["refreshed"]][["kids"]] <- x[["populated"]][["kids"]]
      x
    },
    function(x) {
      x[["refreshed"]][["jwks_uri"]] <- "https://attacker.invalid/jwks"
      x
    },
    function(x) {
      x[["post_restart_requests"]] <- 1L
      x
    },
    function(x) {
      x[["throttle_before"]] <- 99
      x
    },
    function(x) {
      x[["throttle_after"]] <- 103
      x
    },
    function(x) {
      x[["throttle_after"]] <- NULL
      x
    }
  )) {
    testthat::expect_error(rotation_check(mutate(proof)), "proof failed")
  }
})

testthat::test_that("state consumption and both cryptographic rogue controls are required", {
  proof <- rotation_example()
  for (i in seq_len(3L)) {
    for (field in c(
      "authenticated",
      "id_token_validated",
      "state_matches",
      "subject_matches",
      "issuer_matches",
      "audience_matches"
    )) {
      changed <- proof
      changed[["logins"]][[i]][[field]] <- FALSE
      testthat::expect_error(rotation_check(changed), "proof failed")
    }
    changed <- proof
    changed[["logins"]][[i]][["pending_before"]] <- 0L
    testthat::expect_error(rotation_check(changed), "proof failed")
    changed[["logins"]][[i]][["pending_before"]] <- 1L
    changed[["logins"]][[i]][["pending_after"]] <- 1L
    testthat::expect_error(rotation_check(changed), "proof failed")
  }
  for (i in seq_len(2L)) {
    changed <- proof
    changed[["rogues"]][[i]][["rejected"]] <- FALSE
    testthat::expect_error(rotation_check(changed), "proof failed")
    changed <- proof
    changed[["rogues"]][[i]][["error_class"]] <- "unrelated_error"
    testthat::expect_error(rotation_check(changed), "proof failed")
  }
  proof[["post_rogue_requests"]] <- 2L
  testthat::expect_error(rotation_check(proof), "proof failed")
})

testthat::test_that("protocol driver rejects external authorization URLs before making requests", {
  testthat::expect_error(
    rotation_authorize(
      "https://attacker.invalid/authorize",
      list(origin = "https://localhost:30000"),
      "https://localhost:30001/"
    ),
    "trusted provider"
  )
  testthat::expect_error(
    rotation_authorize(
      "https://localhost:30000.evil.invalid/authorize",
      list(origin = "https://localhost:30000"),
      "https://localhost:30001/"
    ),
    "trusted provider"
  )
})

testthat::test_that("cache identity digests and all observation times have strict scalar shapes", {
  proof <- rotation_example()
  replace_at <- function(value, path, replacement) {
    if (length(path) == 1L) {
      value[path[[1L]]] <- list(replacement)
    } else {
      value[[path[[1L]]]] <- replace_at(
        value[[path[[1L]]]],
        path[-1L],
        replacement
      )
    }
    value
  }
  entries <- list(
    list("populated"),
    list("warm"),
    list("before_rotated_login"),
    list("refreshed"),
    list("fetch_calls", 4L, "entry"),
    list("requests", 2L, "entry")
  )
  invalid_times <- list(
    NULL,
    numeric(),
    c(104, 105),
    Inf,
    -Inf,
    NA_real_,
    NaN,
    matrix(104, nrow = 1L)
  )
  for (path in entries) {
    for (field in c("fetched_at", "observed_at")) {
      for (invalid in invalid_times) {
        testthat::expect_error(
          rotation_check(replace_at(proof, c(path, list(field)), invalid)),
          "proof failed"
        )
      }
    }
    for (invalid in list(
      NULL,
      "hash-kid",
      rep(strrep("a", 64L), 2L),
      strrep("A", 64L),
      strrep("g", 64L)
    )) {
      testthat::expect_error(
        rotation_check(replace_at(proof, c(path, list("entry_hash")), invalid)),
        "proof failed"
      )
    }
  }
  for (invalid in invalid_times) {
    testthat::expect_error(
      rotation_check(replace_at(proof, list("throttle_after"), invalid)),
      "proof failed"
    )
  }
  for (provider in c(
    "provider_before",
    "provider_after_restart",
    "provider_after"
  )) {
    for (invalid in list(
      NULL,
      character(),
      c(strrep("a", 32L), strrep("b", 32L)),
      strrep("A", 32L),
      "short"
    )) {
      testthat::expect_error(
        rotation_check(replace_at(
          proof,
          list(provider, "jwks_rotation", "instance_id"),
          invalid
        )),
        "proof failed"
      )
    }
  }
})
