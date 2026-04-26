## Local DPoP-aware protected resource for Keycloak integration tests
##
## The resource server intentionally delegates JWT/JWK/DPoP parsing to
## shinyOAuth internals so the integration suite exercises package code.

`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

verify_signed_access_token <- function(access_token, issuer, jwks) {
  header <- shinyOAuth:::parse_jwt_header(access_token)
  payload <- shinyOAuth:::parse_jwt_payload(access_token)

  alg <- toupper(header$alg %||% "")
  if (!nzchar(alg)) {
    stop("access_token_alg_missing", call. = FALSE)
  }

  keys <- shinyOAuth:::select_candidate_jwks(
    jwks,
    header_alg = alg,
    kid = header$kid %||% NULL
  )
  keys <- shinyOAuth:::filter_jwks_for_alg(keys, alg)
  if (length(keys) == 0L) {
    stop("no_matching_jwks_key", call. = FALSE)
  }

  verified <- FALSE
  for (key in keys) {
    pub <- try(shinyOAuth:::jwk_to_pubkey(key), silent = TRUE)
    if (inherits(pub, "try-error")) {
      next
    }

    decoded <- try(jose::jwt_decode_sig(access_token, pub), silent = TRUE)
    if (!inherits(decoded, "try-error")) {
      verified <- TRUE
      break
    }
  }

  if (!isTRUE(verified)) {
    stop("access_token_signature_invalid", call. = FALSE)
  }

  if (!identical(payload$iss %||% NA_character_, issuer)) {
    stop("access_token_issuer_invalid", call. = FALSE)
  }

  exp <- suppressWarnings(as.numeric(payload$exp %||% NA_real_))
  if (!is.finite(exp) || exp <= as.numeric(Sys.time())) {
    stop("access_token_expired", call. = FALSE)
  }

  payload
}

verify_dpop_jws_signature <- function(proof, pubkey, alg) {
  parts <- strsplit(proof, ".", fixed = TRUE)[[1]]
  if (length(parts) != 3L) {
    stop("dpop_malformed_jws", call. = FALSE)
  }

  alg <- toupper(alg %||% "")
  if (!grepl("^(RS|ES)(256|384|512)$", alg)) {
    stop("dpop_alg_unsupported", call. = FALSE)
  }

  key <- try(openssl::read_pubkey(pubkey), silent = TRUE)
  if (inherits(key, "try-error")) {
    stop("dpop_jwk_invalid", call. = FALSE)
  }

  sig <- shinyOAuth:::base64url_decode_raw(parts[[3]])
  signed_data <- charToRaw(paste(parts[1:2], collapse = "."))
  hash_size <- suppressWarnings(as.integer(sub("^(RS|ES)", "", alg)))
  digest <- openssl::sha2(signed_data, size = hash_size)

  if (startsWith(alg, "ES")) {
    if (!inherits(key, "ecdsa")) {
      stop("dpop_alg_key_mismatch", call. = FALSE)
    }
    r_len <- length(sig) / 2
    if (r_len != floor(r_len)) {
      stop("dpop_signature_invalid", call. = FALSE)
    }
    sig <- openssl::ecdsa_write(
      r = sig[seq_len(r_len)],
      s = sig[seq_len(r_len) + r_len]
    )
  } else if (!inherits(key, "rsa")) {
    stop("dpop_alg_key_mismatch", call. = FALSE)
  }

  ok <- openssl::signature_verify(
    digest,
    sig,
    hash = NULL,
    pubkey = key
  )
  if (!isTRUE(ok)) {
    stop("dpop_signature_invalid", call. = FALSE)
  }

  invisible(TRUE)
}

verify_dpop_proof <- function(
  proof,
  req_method,
  req_url,
  access_token,
  enforce_jti_replay,
  jti_cache,
  iat_leeway = 30
) {
  header <- shinyOAuth:::parse_jwt_header(proof)
  payload <- shinyOAuth:::parse_jwt_payload(proof)

  typ <- tolower(header$typ %||% "")
  if (!identical(typ, "dpop+jwt")) {
    stop("dpop_typ_invalid", call. = FALSE)
  }

  jwk <- header$jwk %||% NULL
  if (!is.list(jwk) || length(jwk) == 0L) {
    stop("dpop_jwk_missing", call. = FALSE)
  }

  pub <- try(shinyOAuth:::jwk_to_pubkey(jwk), silent = TRUE)
  if (inherits(pub, "try-error")) {
    stop("dpop_jwk_invalid", call. = FALSE)
  }

  verified <- try(
    verify_dpop_jws_signature(proof, pub, header$alg %||% NA_character_),
    silent = TRUE
  )
  if (inherits(verified, "try-error")) {
    stop("dpop_signature_invalid", call. = FALSE)
  }

  if (!identical(toupper(payload$htm %||% ""), toupper(req_method))) {
    stop("dpop_htm_mismatch", call. = FALSE)
  }

  expected_htu <- shinyOAuth:::dpop_target_uri(req_url)
  if (!identical(payload$htu %||% NA_character_, expected_htu)) {
    stop("dpop_htu_mismatch", call. = FALSE)
  }

  expected_ath <- shinyOAuth:::dpop_access_token_hash(access_token)
  if (!identical(payload$ath %||% NA_character_, expected_ath)) {
    stop("dpop_ath_mismatch", call. = FALSE)
  }

  iat <- suppressWarnings(as.numeric(payload$iat %||% NA_real_))
  if (!is.finite(iat)) {
    stop("dpop_iat_invalid", call. = FALSE)
  }
  if (abs(as.numeric(Sys.time()) - iat) > as.numeric(iat_leeway)) {
    stop("dpop_iat_out_of_range", call. = FALSE)
  }

  jti <- payload$jti %||% NA_character_
  if (!(is.character(jti) && length(jti) == 1L && nzchar(jti))) {
    stop("dpop_jti_missing", call. = FALSE)
  }
  if (
    isTRUE(enforce_jti_replay) &&
      exists(jti, envir = jti_cache, inherits = FALSE)
  ) {
    stop("dpop_jti_replay", call. = FALSE)
  }
  assign(jti, TRUE, envir = jti_cache)

  list(
    payload = payload,
    jwk_thumbprint = shinyOAuth:::compute_jwk_thumbprint(jwk)
  )
}

resolve_keycloak_helper <- function(name) {
  if (!exists(name, mode = "function", inherits = TRUE)) {
    stop(paste0("Missing required helper: ", name), call. = FALSE)
  }
  get(name, mode = "function", inherits = TRUE)
}

start_dpop_protected_resource <- function(
  resource_path = "/resource",
  issuer = NULL,
  jwks = NULL,
  enforce_jti_replay = TRUE,
  iat_leeway = 30,
  .local_envir = parent.frame()
) {
  testthat::skip_if_not_installed("webfakes")

  if (is.null(issuer)) {
    issuer <- resolve_keycloak_helper("get_issuer")()
  }
  if (is.null(jwks)) {
    jwks <- resolve_keycloak_helper("get_jwks")(force = TRUE)
  }

  coalesce <- `%||%`
  verify_access_token <- verify_signed_access_token
  verify_proof <- verify_dpop_proof

  send_problem <- function(res, status, error_code) {
    res$set_status(status)
    res$set_type("application/json")
    res$send(jsonlite::toJSON(
      list(ok = FALSE, error = error_code),
      auto_unbox = TRUE,
      null = "null"
    ))
  }

  jti_cache <- new.env(parent = emptyenv())

  app <- webfakes::new_app()
  app$get(resource_path, function(req, res) {
    tryCatch(
      {
        auth <- coalesce(req$get_header("authorization"), "")
        if (!grepl("^DPoP\\s+", auth, ignore.case = TRUE)) {
          send_problem(res, 401L, "missing_dpop_authorization")
          return()
        }

        proof <- coalesce(req$get_header("dpop"), "")
        if (!nzchar(proof)) {
          send_problem(res, 401L, "missing_dpop_proof")
          return()
        }

        access_token <- sub("^[Dd][Pp][Oo][Pp]\\s+", "", auth, perl = TRUE)

        access_payload <- try(
          verify_access_token(
            access_token,
            issuer = issuer,
            jwks = jwks
          ),
          silent = TRUE
        )
        if (inherits(access_payload, "try-error")) {
          send_problem(
            res,
            401L,
            conditionMessage(attr(access_payload, "condition"))
          )
          return()
        }

        proof_info <- try(
          verify_proof(
            proof = proof,
            req_method = req$method,
            req_url = as.character(req$url),
            access_token = access_token,
            enforce_jti_replay = enforce_jti_replay,
            jti_cache = jti_cache,
            iat_leeway = iat_leeway
          ),
          silent = TRUE
        )
        if (inherits(proof_info, "try-error")) {
          send_problem(
            res,
            401L,
            conditionMessage(attr(proof_info, "condition"))
          )
          return()
        }

        bound_jkt <- coalesce(
          coalesce(access_payload$cnf, list())$jkt,
          NA_character_
        )
        if (
          !(is.character(bound_jkt) &&
            length(bound_jkt) == 1L &&
            nzchar(bound_jkt))
        ) {
          send_problem(res, 401L, "access_token_missing_cnf_jkt")
          return()
        }

        if (!identical(bound_jkt, proof_info$jwk_thumbprint)) {
          send_problem(res, 401L, "dpop_key_mismatch")
          return()
        }

        res$set_type("application/json")
        res$send(jsonlite::toJSON(
          list(
            ok = TRUE,
            sub = coalesce(access_payload$sub, NA_character_),
            token_jkt = bound_jkt,
            proof_jti = coalesce(proof_info$payload$jti, NA_character_)
          ),
          auto_unbox = TRUE,
          null = "null"
        ))
      },
      error = function(err) {
        send_problem(
          res,
          500L,
          paste0("resource_internal_error:", conditionMessage(err))
        )
      }
    )
  })

  srv <- webfakes::local_app_process(app, .local_envir = .local_envir)
  url <- paste0(sub("/+$", "", srv$url()), resource_path)
  deadline <- Sys.time() + 5

  repeat {
    ready <- tryCatch(
      {
        httr2::request(url) |>
          httr2::req_error(is_error = function(resp) FALSE) |>
          httr2::req_perform()
        TRUE
      },
      error = function(...) FALSE
    )
    if (isTRUE(ready)) {
      break
    }
    if (Sys.time() > deadline) {
      stop("DPoP protected resource did not start in time", call. = FALSE)
    }
    Sys.sleep(0.1)
  }

  list(
    server = srv,
    url = url
  )
}
