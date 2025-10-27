test_that("does not warn when TTL is finite positive", {
  prov <- make_test_provider()
  store <- cachem::cache_mem(max_age = 123)
  cli <- oauth_client(
    provider = prov,
    client_id = "abc",
    client_secret = "",
    redirect_uri = "http://localhost:8100",
    scopes = character(0),
    state_store = store
  )

  expect_no_warning({
    v <- client_state_store_max_age(cli)
    expect_equal(v, 123)
  })
})
