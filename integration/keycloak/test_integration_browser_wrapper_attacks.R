# Cookies are independent markers; the binding token lives in origin/tab
# sessionStorage. These tests exercise HTTP admission, the clean callback
# bridge and real Shiny sessions, including browser-retained connections.
for (retained in c(FALSE, TRUE)) {
  testthat::test_that(
    paste(
      "wrapper login-CSRF, callback swap and cookie tampering; retained =",
      retained
    ),
    {
      skip_common()
      f <- keycloak_wrapper_attack_setup(retained)
      attacker <- f[["new_browser"]]()
      victim <- f[["new_browser"]]()
      attacker_url <- keycloak_wrapper_start_login(attacker)
      victim_url <- keycloak_wrapper_start_login(victim)
      bob <- perform_login_form_as(
        attacker_url,
        username = "bob",
        password = "bob",
        redirect_uri = f[["client"]]@redirect_uri
      )
      alice <- perform_login_form_as(
        victim_url,
        username = "alice",
        password = "alice",
        redirect_uri = f[["client"]]@redirect_uri
      )
      # Attacker's independent code+state cannot log the victim into Bob's account.
      victim[["go_to"]](bob[["callback_url"]])
      rejected <- keycloak_wrapper_wait(victim, function(x) {
        length(x[["errors"]]) > 0L
      })
      testthat::expect_equal(rejected[["count"]], 0L)
      testthat::expect_true("invalid_state" %in% unlist(rejected[["errors"]]))

      complete <- function(browser, callback, username) {
        browser[["go_to"]](callback)
        snapshot <- keycloak_wrapper_wait(browser, function(x) {
          identical(x[["count"]], 1L)
        })
        testthat::expect_length(snapshot[["errors"]], 0L)
        identity <- snapshot[["identity"]]
        testthat::expect_identical(
          identity[["userinfo"]][["preferred_username"]],
          username
        )
        testthat::expect_identical(
          identity[["id_token_claims"]][["sub"]],
          identity[["userinfo"]][["sub"]]
        )
        testthat::expect_false(grepl(
          "code=|state=",
          keycloak_wrapper_value(browser, "window.appCallbackQuery")
        ))
        testthat::expect_identical(
          keycloak_wrapper_value(browser, "location.search"),
          ""
        )
        snapshot
      }
      # Each original transaction remains usable. OAuth identifies the user who
      # authenticated at the AS; applications can enforce their expected account.
      bob_state <- complete(attacker, bob[["callback_url"]], "bob")
      alice_state <- complete(victim, alice[["callback_url"]], "alice")
      testthat::expect_false(identical(
        bob_state[["identity"]],
        alice_state[["identity"]]
      ))
      if (retained) {
        victim[["go_to"]](f[["origin"]])
        restored <- keycloak_wrapper_wait(victim, function(x) {
          identical(x[["count"]], 1L)
        })
        testthat::expect_identical(
          restored[["identity"]],
          alice_state[["identity"]]
        )
      }

      tampered <- f[["new_browser"]]()
      url <- keycloak_wrapper_start_login(tampered)
      login <- perform_login_form_as(
        url,
        redirect_uri = f[["client"]]@redirect_uri
      )
      cookies <- tampered[["Network"]][["getCookies"]](
        urls = list(f[["origin"]])
      )[["cookies"]]
      markers <- Filter(
        function(x) startsWith(x[["name"]], "shinyOAuth_sid-"),
        cookies
      )
      testthat::expect_gt(length(markers), 0L)
      for (cookie in markers) {
        tampered[["Network"]][["setCookie"]](
          name = cookie[["name"]],
          value = strrep("cd", 64),
          url = f[["origin"]],
          path = cookie[["path"]]
        )
      }
      tampered[["go_to"]](login[["callback_url"]])
      rejected <- keycloak_wrapper_wait(tampered, function(x) {
        length(x[["errors"]]) > 0L
      })
      testthat::expect_equal(rejected[["count"]], 0L)
      testthat::expect_true("invalid_state" %in% unlist(rejected[["errors"]]))
    }
  )
}
