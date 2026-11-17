for (alg in c("RS256", "RS384")) {
  testthat::test_that(
    paste(
      "independent resource enforces per-token TLS certificate binding with",
      alg
    ),
    run_mtls_resource(alg)
  )
}
