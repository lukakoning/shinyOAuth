openid_release_key <- function(selection) {
  paste(selection[["profile"]], selection[["transport"]], sep = "/")
}

openid_validate_release_matrix <- function(matrix, manifest) {
  if (
    !is.list(matrix) ||
      !setequal(
        names(matrix),
        c("schema_version", "id", "callback_rejection_policy", "selections")
      ) ||
      anyDuplicated(names(matrix)) ||
      !identical(matrix[["schema_version"]], 1L) ||
      !openid_string(matrix[["id"]]) ||
      !grepl("^[a-z][a-z0-9-]+$", matrix[["id"]]) ||
      !identical(matrix[["callback_rejection_policy"]], "opaque_error_v1") ||
      !is.list(matrix[["selections"]]) ||
      !is.null(names(matrix[["selections"]])) ||
      !length(matrix[["selections"]])
  ) {
    stop("Invalid declared OpenID release matrix")
  }
  for (selection in matrix[["selections"]]) {
    if (
      !is.list(selection) ||
        !setequal(names(selection), c("profile", "transport")) ||
        anyDuplicated(names(selection)) ||
        !openid_string(selection[["profile"]]) ||
        !selection[["profile"]] %in%
          c(names(manifest[["profiles"]]), "shared-pool") ||
        !openid_string(selection[["transport"]]) ||
        !selection[["transport"]] %in% c("sync", "mirai", "future") ||
        (identical(selection[["profile"]], "shared-pool") &&
          !identical(selection[["transport"]], "mirai")) ||
        (identical(selection[["transport"]], "future") &&
          !selection[["profile"]] %in% c("smoke", "refresh"))
    ) {
      stop("Invalid profile or transport in declared OpenID release matrix")
    }
  }
  keys <- vapply(matrix[["selections"]], openid_release_key, character(1))
  if (anyDuplicated(keys)) {
    stop("Duplicate selection in declared OpenID release matrix")
  }
  invisible(keys)
}

openid_release_matrix <- function(root = ".") {
  matrix <- jsonlite::read_json(file.path(
    root,
    "integration/openid/release-matrix.json"
  ))
  openid_validate_release_matrix(matrix, openid_profiles(root))
  matrix
}

openid_release_canonical <- function(value) {
  if (!is.list(value)) {
    return(value)
  }
  if (!is.null(names(value))) {
    if (anyDuplicated(names(value))) {
      stop("Duplicate object field in release evidence")
    }
    value <- value[sort(names(value), method = "radix")]
  }
  lapply(value, openid_release_canonical)
}

openid_release_equal <- function(left, right) {
  encode <- function(value) {
    as.character(jsonlite::toJSON(
      openid_release_canonical(value),
      auto_unbox = TRUE,
      null = "null",
      digits = NA
    ))
  }
  identical(encode(left), encode(right))
}

openid_release_recheck <- function(report, matrix, manifest, selection = NULL) {
  if (
    !identical(
      report[["callback_rejection_policy"]],
      matrix[["callback_rejection_policy"]]
    ) ||
      !identical(
        report[["regression_installation_after"]],
        report[["installation"]]
      )
  ) {
    stop(
      "Missing current callback policy or post-regression installation evidence"
    )
  }
  context <- report
  if (!is.null(selection)) {
    context[["profile"]] <- selection[["profile"]]
    context[["transport"]] <- selection[["transport"]]
  }
  context[["callback_rejection_policy"]] <- matrix[[
    "callback_rejection_policy"
  ]]
  check <- if (identical(report[["profile"]], "shared-pool")) {
    openid_check_shared_report(report, context, manifest)
  } else {
    openid_check_report(report, context, manifest)
  }
  if (
    !isTRUE(check[["gate_passed"]]) || !isTRUE(check[["selection_complete"]])
  ) {
    stop("A release selection failed its protocol evidence gate")
  }
  for (name in names(check)) {
    if (!openid_release_equal(report[[name]], check[[name]])) {
      stop(
        "Stored release assessment differs from independently recomputed evidence"
      )
    }
  }
  for (child in report[["selections"]]) {
    if (!identical(child[["package_version"]], report[["package_version"]])) {
      stop("Unrelated package version in a shared release selection")
    }
    openid_release_recheck(child, matrix, manifest)
  }
  check
}

openid_check_release <- function(
  reports,
  matrix,
  manifest,
  revision,
  tree,
  archive_sha256,
  package_version = NULL
) {
  tryCatch(
    {
      reports <- openid_release_canonical(reports)
      matrix <- openid_release_canonical(matrix)
      manifest <- openid_release_canonical(manifest)
      required <- openid_validate_release_matrix(matrix, manifest)
      if (!is.list(reports) || !length(reports)) {
        stop("No client reports supplied for the declared release matrix")
      }
      keys <- vapply(
        reports,
        function(report) {
          if (
            !is.list(report) ||
              !openid_string(report[["profile"]]) ||
              !openid_string(report[["transport"]])
          ) {
            stop("Invalid release report selection identity")
          }
          openid_release_key(report)
        },
        character(1)
      )
      if (anyDuplicated(keys)) {
        stop("Duplicate client reports for a declared release selection")
      }
      if (length(setdiff(keys, required))) {
        stop("Unexpected client report outside the declared release matrix")
      }
      missing <- setdiff(required, keys)
      if (length(missing)) {
        stop(
          "Missing required release selections: ",
          paste(missing, collapse = ", ")
        )
      }
      if (
        !openid_release_source_matches(reports, revision, tree, archive_sha256)
      ) {
        stop(
          "Release source policy failed for the selected clean revision and archive"
        )
      }
      versions <- vapply(
        reports,
        function(report) report[["package_version"]],
        character(1)
      )
      if (
        !all(vapply(versions, openid_string, logical(1))) ||
          length(unique(versions)) != 1L ||
          (!is.null(package_version) &&
            (!openid_string(package_version) ||
              !identical(versions[[1L]], package_version)))
      ) {
        stop("Release reports do not share one package version")
      }
      entries <- lapply(seq_along(required), function(i) {
        index <- match(required[[i]], keys)
        report <- reports[[index]]
        selection <- matrix[["selections"]][[i]]
        check <- openid_release_recheck(report, matrix, manifest, selection)
        list(
          profile = selection[["profile"]],
          transport = selection[["transport"]],
          report_index = index,
          selection_complete = check[["selection_complete"]],
          upstream_plan_complete = check[["upstream_plan_complete"]],
          coverage_complete = check[["coverage_complete"]],
          coverage_limitations = check[["coverage_limitations"]],
          assessment = check[["assessment"]]
        )
      })
      list(
        schema_version = 1L,
        status = "passed",
        gate_passed = TRUE,
        matrix_complete = TRUE,
        matrix_id = matrix[["id"]],
        scope = "declared_oidf_client_selections",
        checkout_revision = revision,
        checkout_tree = tree,
        archive_sha256 = archive_sha256,
        package_version = versions[[1L]],
        callback_rejection_policy = matrix[["callback_rejection_policy"]],
        required_count = length(required),
        selection_count = length(entries),
        all_upstream_plans_complete = all(vapply(
          entries,
          function(entry) isTRUE(entry[["upstream_plan_complete"]]),
          logical(1)
        )),
        all_coverage_complete = all(vapply(
          entries,
          function(entry) isTRUE(entry[["coverage_complete"]]),
          logical(1)
        )),
        certification_status = "not_assessed",
        artifact_authentication = "not_assessed",
        platform_coverage = "not_assessed",
        durable_retention = "not_assessed",
        entries = entries,
        reason = NULL
      )
    },
    error = function(error) {
      list(
        schema_version = 1L,
        status = "failed",
        gate_passed = FALSE,
        matrix_complete = FALSE,
        certification_status = "not_assessed",
        reason = conditionMessage(error)
      )
    }
  )
}

openid_release_selection_diagnostics <- function(
  reports,
  matrix,
  manifest,
  source,
  input_sha256
) {
  matrix <- openid_release_canonical(matrix)
  manifest <- openid_release_canonical(manifest)
  required <- openid_validate_release_matrix(matrix, manifest)
  keys <- vapply(
    reports,
    function(report) {
      if (
        !is.list(report) ||
          sum(names(report) == "profile", na.rm = TRUE) != 1L ||
          sum(names(report) == "transport", na.rm = TRUE) != 1L ||
          !openid_string(report[["profile"]]) ||
          !openid_string(report[["transport"]])
      ) {
        return(NA_character_)
      }
      openid_release_key(report)
    },
    character(1)
  )

  diagnose <- function(indices, selection) {
    if (!length(indices)) {
      return("missing")
    }
    if (length(indices) > 1L) {
      return("duplicate")
    }
    report <- tryCatch(
      openid_release_canonical(reports[[indices]]),
      error = function(error) NULL
    )
    if (is.null(report)) {
      return("invalid_report")
    }
    if (
      !identical(report[["status"]], "passed") ||
        !isTRUE(report[["gate_passed"]])
    ) {
      return("reported_failure")
    }
    if (!identical(report[["package_version"]], source[["package_version"]])) {
      return("package_version_mismatch")
    }
    if (
      !openid_release_source_matches(
        list(report),
        source[["revision"]],
        source[["tree"]],
        source[["archive_sha256"]]
      )
    ) {
      return("source_mismatch")
    }
    tryCatch(
      {
        openid_release_recheck(report, matrix, manifest, selection)
        "passed"
      },
      error = function(error) "evidence_failed"
    )
  }

  lapply(seq_along(required), function(i) {
    selection <- matrix[["selections"]][[i]]
    indices <- which(keys == required[[i]])
    list(
      profile = selection[["profile"]],
      transport = selection[["transport"]],
      status = diagnose(indices, selection),
      report_sha256 = input_sha256[indices]
    )
  })
}
