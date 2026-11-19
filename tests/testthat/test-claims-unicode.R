test_that("strict claim comparisons preserve Unicode code points after JSON decoding", {
  composed <- paste0("caf", intToUtf8(0x00e9))
  decomposed <- paste0("caf", intToUtf8(c(0x0065, 0x0301)))
  cases <- list(
    list(
      requested = composed,
      different = decomposed,
      uppercase = paste0("caf", intToUtf8(0x00c9)),
      escaped_json = '{"name":"caf\\u00e9"}'
    ),
    list(
      requested = decomposed,
      different = composed,
      uppercase = paste0("caf", intToUtf8(c(0x0045, 0x0301))),
      escaped_json = '{"name":"caf\\u0065\\u0301"}'
    )
  )
  for (target in c("id_token", "userinfo")) {
    for (constraint in c("value", "values")) {
      for (case in cases) {
        requested <- case[["requested"]]
        policy <- if (identical(constraint, "value")) {
          requested
        } else {
          list(requested, "other")
        }
        client <- make_test_client(
          use_nonce = TRUE,
          claims = setNames(
            list(list(name = setNames(list(policy), constraint))),
            target
          ),
          claims_validation = "strict"
        )
        literal <- jsonlite::fromJSON(
          paste0('{"name":"', enc2utf8(requested), '"}'),
          simplifyVector = FALSE
        )
        escaped <- jsonlite::fromJSON(
          case[["escaped_json"]],
          simplifyVector = FALSE
        )
        expect_identical(escaped, literal)
        expect_no_error(validate_essential_claims(client, literal, target))
        expect_no_error(validate_essential_claims(client, escaped, target))
        for (different in list(case[["different"]], case[["uppercase"]])) {
          expect_error(
            validate_essential_claims(client, list(name = different), target),
            "Requested claim values not satisfied"
          )
        }
      }
    }
  }
})
