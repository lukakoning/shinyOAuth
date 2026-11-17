for (alg in c("RS256", "RS384")) {
  testthat::test_that(
    paste(
      "PKI mTLS authentication completes the public resource matrix with",
      alg
    ),
    run_mtls_resource(alg, "tls_client_auth")
  )
  testthat::test_that(
    paste(
      "PKI mTLS rejects invalid authentication before issuing grants with",
      alg
    ),
    run_mtls_auth_denials(alg)
  )
}
