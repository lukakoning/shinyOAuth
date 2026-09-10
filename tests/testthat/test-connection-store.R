store_test_fixture <- function(max_entries = 1000L) {
  time <- new.env(parent = emptyenv())
  time$now <- 1000
  store <- connection_store_memory_impl(100, 10, max_entries, function() {
    time$now
  })
  owner <- strrep("a", 32)
  id <- strrep("b", 32)
  tx <- strrep("c", 32)
  create <- function(
    owner_id = owner,
    connection_id = id,
    transaction = tx,
    expires_at = 1100
  ) {
    store$create(
      owner_id,
      connection_id,
      transaction,
      "site_a",
      "sha256:configuration",
      "sealed_original",
      expires_at
    )
  }
  list(store = store, time = time, owner = owner, id = id, create = create)
}

test_that("connection stores isolate owners and reserve transaction identity", {
  f <- store_test_fixture()
  record <- f$create()
  other <- strrep("d", 32)
  expect_identical(f$store$read(f$owner, f$id), record)
  expect_null(f$store$read(other, f$id))
  expect_length(f$store$list(other), 0L)
  expect_null(f$create(connection_id = other))
  expect_null(f$create(transaction = other))
  expect_length(f$store$list(f$owner), 1L)
  expect_false("sealed" %in% names(f$store$list(f$owner)[[1]]))
  expect_false(grepl(
    "sealed_original",
    paste(capture.output(print(f$store)), collapse = "")
  ))
  expect_error(f$store$read("untrusted-input", f$id), "identifier")
  expect_error(oauth_connection_store_memory(max_age = Inf), "positive finite")
  expect_error(oauth_connection_store_memory(max_entries = 1.5), "whole number")
  expect_error(f$create(expires_at = 1101), "store lifetime")
})

test_that("refresh claims coordinate sessions and commit only the winning operation", {
  f <- store_test_fixture()
  original <- f$create()
  claim <- f$store$begin_refresh(f$owner, f$id, original$revision)
  expect_identical(claim$status, "refreshing")
  expect_gt(claim$revision, original$revision)
  expect_null(f$store$begin_refresh(f$owner, f$id, original$revision))
  expect_null(f$store$begin_refresh(f$owner, f$id, claim$revision))
  expect_null(f$store$commit_refresh(
    f$owner,
    f$id,
    strrep("x", 32),
    claim$revision,
    "sealed_rotated"
  ))
  expect_null(f$store$commit_refresh(
    f$owner,
    f$id,
    claim$operation,
    original$revision,
    "sealed_rotated"
  ))
  result <- f$store$commit_refresh(
    f$owner,
    f$id,
    claim$operation,
    claim$revision,
    "sealed_rotated"
  )
  expect_identical(result$status, "active")
  expect_identical(result$sealed, "sealed_rotated")
  expect_gt(result$revision, claim$revision)
  expect_null(result$operation)
  expect_identical(result$expires_at, original$expires_at)
  expect_null(f$store$commit_refresh(
    f$owner,
    f$id,
    claim$operation,
    claim$revision,
    "sealed_late"
  ))
})

test_that("uncertain refresh outcomes never release old credentials for retry", {
  for (outcome in c("not_consumed", "possibly_consumed", "consumed")) {
    f <- store_test_fixture()
    record <- f$create()
    claim <- f$store$begin_refresh(f$owner, f$id, record$revision)
    result <- f$store$fail_refresh(
      f$owner,
      f$id,
      claim$operation,
      claim$revision,
      outcome
    )
    if (outcome == "not_consumed") {
      expect_identical(result$status, "active")
      expect_identical(result$sealed, record$sealed)
      expect_type(f$store$begin_refresh(f$owner, f$id, result$revision), "list")
    } else {
      expect_identical(result$status, "uncertain")
      expect_null(result$sealed)
      expect_null(f$store$begin_refresh(f$owner, f$id, result$revision))
    }
  }
  f <- store_test_fixture()
  record <- f$create()
  claim <- f$store$begin_refresh(f$owner, f$id, record$revision)
  f$time$now <- 1011
  abandoned <- f$store$read(f$owner, f$id)
  expect_identical(abandoned$status, "uncertain")
  expect_null(abandoned$sealed)
  expect_null(f$store$commit_refresh(
    f$owner,
    f$id,
    claim$operation,
    claim$revision,
    "sealed_late"
  ))
  expect_null(f$store$begin_refresh(f$owner, f$id, abandoned$revision))
})

test_that("disconnect and owner logout prevent late refresh completion", {
  f <- store_test_fixture()
  record <- f$create()
  other_owner <- strrep("d", 32)
  other_id <- strrep("e", 32)
  other <- f$create(other_owner, other_id)
  claim <- f$store$begin_refresh(f$owner, f$id, record$revision)
  expect_null(f$store$disconnect(other_owner, f$id, claim$revision))
  expect_null(f$store$disconnect(f$owner, f$id, record$revision))
  removed <- f$store$disconnect(f$owner, f$id, claim$revision)
  expect_identical(removed$record$status, "disconnected")
  expect_null(removed$record$sealed)
  expect_identical(removed$previous$sealed, "sealed_original")
  expect_null(f$store$commit_refresh(
    f$owner,
    f$id,
    claim$operation,
    claim$revision,
    "sealed_late"
  ))
  expect_null(f$create())
  expect_identical(f$store$read(other_owner, other_id), other)
  expect_null(
    f$store$disconnect(f$owner, f$id, removed$record$revision)$previous
  )
  f$store$disconnect_owner(other_owner)
  expect_identical(f$store$read(other_owner, other_id)$status, "disconnected")
})

test_that("expiry, deduplication and capacity do not resurrect or evict credentials", {
  f <- store_test_fixture(max_entries = 1L)
  record <- f$create(expires_at = 1005)
  expect_error(
    f$create(connection_id = strrep("d", 32), transaction = strrep("e", 32)),
    "capacity"
  )
  expect_identical(f$store$read(f$owner, f$id), record)
  f$time$now <- 1006
  expect_null(f$store$read(f$owner, f$id))
  expect_null(f$create())
  f$time$now <- 1101
  replacement <- f$create(expires_at = 1200)
  expect_gt(replacement$revision, record$revision)
  expect_null(f$store$disconnect(f$owner, f$id, record$revision))
  expect_identical(f$store$read(f$owner, f$id), replacement)
})

test_that("memory stores reject a different worker process", {
  f <- store_test_fixture()
  result <- callr::r(
    function(store, owner, id) {
      tryCatch(store$read(owner, id), error = function(e) conditionMessage(e))
    },
    args = list(store = f$store, owner = f$owner, id = f$id)
  )
  expect_match(result, "another R process")
})
