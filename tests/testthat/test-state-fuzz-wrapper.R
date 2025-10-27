test_that("state_decrypt_gcm rejects malformed state wrappers (fuzz)", {
  # Speed up failures in this test by disabling random fail delay
  old <- options(shinyOAuth.state_fail_delay_ms = 0)
  on.exit(options(old), add = TRUE)

  key <- strrep("k", 64)

  # Helper to base64url encode a JSON list as the outer token wrapper
  to_token <- function(obj) {
    raw <- charToRaw(jsonlite::toJSON(obj, auto_unbox = TRUE))
    s <- openssl::base64_encode(raw)
    s <- sub("=+$", "", s)
    chartr("+/", "-_", s)
  }

  # Valid minimal-ish wrapper to start from
  good <- list(
    v = 1L,
    iv = shinyOAuth:::b64url_encode(as.raw(1:12)),
    tg = shinyOAuth:::b64url_encode(as.raw(1:16)),
    ct = shinyOAuth:::b64url_encode(as.raw(1:32))
  )

  # Generator: apply one random mutation to a wrapper object
  mutate_once <- function(obj) {
    choice <- sample(
      c(
        "drop_v",
        "v_wrong_type",
        "v_wrong_val",
        "drop_iv",
        "iv_not_b64",
        "iv_wrong_len",
        "drop_tg",
        "tg_not_b64",
        "tg_wrong_len",
        "drop_ct",
        "ct_not_b64",
        "ct_empty",
        "junk_field",
        "nested_obj",
        "non_json"
      ),
      1
    )

    o <- obj
    switch(
      choice,
      drop_v = {
        o$v <- NULL
      },
      v_wrong_type = {
        o$v <- "1"
      },
      v_wrong_val = {
        o$v <- 999L
      },

      drop_iv = {
        o$iv <- NULL
      },
      iv_not_b64 = {
        o$iv <- "***"
      },
      iv_wrong_len = {
        o$iv <- shinyOAuth:::b64url_encode(as.raw(1:8))
      },

      drop_tg = {
        o$tg <- NULL
      },
      tg_not_b64 = {
        o$tg <- "!@#"
      },
      tg_wrong_len = {
        o$tg <- shinyOAuth:::b64url_encode(as.raw(1:8))
      },

      drop_ct = {
        o$ct <- NULL
      },
      ct_not_b64 = {
        o$ct <- "??"
      },
      ct_empty = {
        o$ct <- shinyOAuth:::b64url_encode(raw(0))
      },

      junk_field = {
        o$junk <- 123
      },
      nested_obj = {
        o$iv <- jsonlite::toJSON(list(x = 1))
      },
      non_json = {
        return("not-json-base64url-token")
      }
    )
    o
  }

  # Run a bunch of trials covering different malformed cases
  set.seed(123)
  n <- 100
  seen <- 0
  for (i in seq_len(n)) {
    obj <- mutate_once(good)
    if (is.character(obj)) {
      tok <- obj
    } else {
      tok <- to_token(obj)
    }
    expect_error(
      shinyOAuth:::state_decrypt_gcm(tok, key = key),
      class = "shinyOAuth_state_error"
    )
    seen <- seen + 1
  }
  expect_gt(seen, 0)
})
