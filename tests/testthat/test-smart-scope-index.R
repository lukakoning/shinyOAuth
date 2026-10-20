test_that("indexed SMART coverage agrees with an independent permission table", {
  # The reference uses predeclared meanings and set operations, without parsing
  # scope strings or using the production index/interaction masks.
  permissions <- expand.grid(
    context = c("patient", "user", "system"),
    resource = c("*", "Patient", "Observation"),
    actions = c("c", "r", "u", "d", "s", "rs", "cud", "cruds"),
    constraint = c("", "code=a", "code=b", "code=a&_id=b", "_id=b&code=a"),
    stringsAsFactors = FALSE
  )
  permissions[["scope"]] <- with(
    permissions,
    paste0(
      context,
      "/",
      resource,
      ".",
      actions,
      ifelse(nzchar(constraint), paste0("?", constraint), "")
    )
  )
  permissions[["kind"]] <- "resource"
  extras <- data.frame(
    context = "patient",
    resource = "Observation",
    actions = c("rs", "cud", "cruds", "", "", "", ""),
    constraint = "",
    scope = c(
      "patient/Observation.read",
      "patient/Observation.write",
      "patient/*.*",
      "patient/Observation.sr",
      "user/Patient.r?code:in=x",
      "openid",
      "fhirUser"
    ),
    kind = c(rep("v1", 3L), rep("unknown", 2L), rep("literal", 2L)),
    stringsAsFactors = FALSE
  )
  extras[["resource"]][[3L]] <- "*"
  permissions <- rbind(permissions, extras)
  reference <- function(requested, granted, allow_v1) {
    table <- permissions
    table[["kind"]][table[["kind"]] == "v1"] <- if (allow_v1) {
      "resource"
    } else {
      "unknown"
    }
    have <- table[match(unique(granted), table[["scope"]]), , drop = FALSE]
    missing <- indeterminate <- character()
    for (scope in sort(unique(requested))) {
      need <- table[match(scope, table[["scope"]]), , drop = FALSE]
      if (need[["kind"]] == "literal") {
        if (!scope %in% granted) {
          missing <- c(missing, scope)
        }
        next
      }
      if (need[["kind"]] == "unknown") {
        indeterminate <- c(indeterminate, scope)
        next
      }
      relevant <- have[
        have[["kind"]] == "resource" &
          have[["context"]] == need[["context"]] &
          have[["resource"]] %in% c("*", need[["resource"]]),
        ,
        drop = FALSE
      ]
      exact <- !nzchar(relevant[["constraint"]]) |
        relevant[["constraint"]] == need[["constraint"]]
      actions <- function(rows) {
        unique(unlist(strsplit(rows[["actions"]], "", fixed = TRUE)))
      }
      required <- actions(need)
      covered <- actions(relevant[exact, , drop = FALSE])
      possible <- if (any(have[["kind"]] == "unknown")) {
        required
      } else if (nzchar(need[["constraint"]])) {
        actions(relevant)
      } else {
        character()
      }
      if (all(required %in% covered)) {
        next
      }
      if (all(required %in% union(covered, possible))) {
        indeterminate <- c(indeterminate, scope)
      } else {
        missing <- c(missing, scope)
      }
    }
    list(
      status = if (length(missing)) {
        "insufficient"
      } else if (length(indeterminate)) {
        "indeterminate"
      } else {
        "covered"
      },
      missing = missing,
      indeterminate = indeterminate
    )
  }
  withr::local_seed(1801)
  for (allow_v1 in c(FALSE, TRUE)) {
    for (i in seq_len(400L)) {
      requested <- sample(permissions[["scope"]], sample(1:8, 1L))
      granted <- sample(permissions[["scope"]], sample(0:20, 1L))
      expect_identical(
        smart_scope_coverage(requested, granted, allow_v1),
        reference(requested, granted, allow_v1)
      )
    }
  }
})

test_that("granular scope indexes keep constraints isolated and grants current", {
  scopes <- paste0("user/Observation.rs?code=", seq_len(140L))
  split_grant <- c(
    sub(".rs?", ".r?", scopes, fixed = TRUE),
    "user/Observation.s"
  )
  expect_identical(
    smart_scope_coverage(scopes, split_grant)[["status"]],
    "covered"
  )
  reduced <- split_grant[-140L]
  result <- smart_scope_coverage(scopes, reduced)
  expect_identical(result[["status"]], "indeterminate")
  expect_identical(result[["indeterminate"]], scopes[[140L]])
  expect_identical(result[["missing"]], character())
  expect_identical(
    smart_scope_coverage("user/Observation.rs", split_grant)[["status"]],
    "insufficient"
  )
  expect_identical(
    smart_scope_coverage(scopes, "user/*.s")[["missing"]],
    sort(scopes)
  )
  expect_identical(
    smart_scope_coverage(scopes, split_grant)[["status"]],
    "covered"
  )
  expect_identical(
    smart_scope_coverage(scopes, "patient/*.cruds")[["missing"]],
    sort(scopes)
  )
  # Configuration changes cannot reuse a result from a previous comparison.
  legacy <- "patient/Observation.read"
  expect_identical(
    smart_scope_coverage(legacy, legacy, TRUE)[["status"]],
    "covered"
  )
  expect_identical(
    smart_scope_coverage(legacy, legacy, FALSE)[["status"]],
    "indeterminate"
  )
})

test_that("indexed SMART comparisons preserve the full scope size budget", {
  long_filter <- paste0("user/Observation.r?code=", strrep("x", 32000L))
  long_resource <- paste0("user/", strrep("X", 12000L), ".r")
  for (scope in c(long_filter, long_resource)) {
    expect_identical(smart_scope_coverage(scope, scope)[["status"]], "covered")
    expect_identical(
      smart_scope_coverage(scope, "user/*.r")[["status"]],
      "covered"
    )
  }
  expect_identical(
    smart_scope_coverage(long_filter, sub("code=x", "code=y", long_filter))[[
      "status"
    ]],
    "indeterminate"
  )
  scopes <- paste0("user/Observation.r?code=", seq_len(256L))
  expect_identical(smart_scope_coverage(scopes, scopes)[["status"]], "covered")
  expect_error(
    smart_scope_coverage(character(), c(scopes, "openid")),
    "size limit"
  )
  too_long <- paste0("user/Observation.r?code=", strrep("x", 33000L))
  expect_error(smart_scope_coverage(too_long, too_long), "size limit")
})
