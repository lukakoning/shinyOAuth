## Local DPoP-aware protected resource for Keycloak integration tests
##
## The resource server supports two verification modes:
## - `implementation = "package"` exercises shinyOAuth JWT/JWK/DPoP helpers.
## - `implementation = "independent"` mirrors the same checks locally so the
##   test suite also has a protected-resource oracle that does not depend on
##   shinyOAuth internals.

`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

local_base64url_encode <- function(raw_bytes) {
  stopifnot(is.raw(raw_bytes))

  encoded <- openssl::base64_encode(raw_bytes, linebreak = FALSE)
  encoded <- chartr("+/", "-_", encoded)
  gsub("=+$", "", encoded)
}

local_base64url_decode_raw <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("base64url_value_invalid", call. = FALSE)
  }

  value <- chartr("-_", "+/", value)
  pad <- (4L - (nchar(value, type = "bytes") %% 4L)) %% 4L
  decoded <- try(
    openssl::base64_decode(paste0(value, strrep("=", pad))),
    silent = TRUE
  )
  if (inherits(decoded, "try-error")) {
    stop("base64url_decode_failed", call. = FALSE)
  }

  decoded
}

local_parse_compact_jwt_part <- function(jwt, index, label) {
  parts <- strsplit(jwt, ".", fixed = TRUE)[[1]]
  if (length(parts) != 3L) {
    stop(paste0(label, "_jwt_malformed"), call. = FALSE)
  }

  decoded <- try(local_base64url_decode_raw(parts[[index]]), silent = TRUE)
  if (inherits(decoded, "try-error")) {
    stop(paste0(label, "_jwt_segment_invalid"), call. = FALSE)
  }

  parsed <- try(
    jsonlite::fromJSON(rawToChar(decoded), simplifyVector = FALSE),
    silent = TRUE
  )
  if (inherits(parsed, "try-error") || !is.list(parsed)) {
    stop(paste0(label, "_jwt_json_invalid"), call. = FALSE)
  }

  parsed
}

local_parse_jwt_header <- function(jwt, label = "jwt") {
  local_parse_compact_jwt_part(jwt, 1L, paste0(label, "_header"))
}

local_parse_jwt_payload <- function(jwt, label = "jwt") {
  local_parse_compact_jwt_part(jwt, 2L, paste0(label, "_payload"))
}

local_jwk_to_pubkey <- function(jwk) {
  kty <- jwk$kty %||% NA_character_
  if (!kty %in% c("RSA", "EC", "OKP")) {
    stop("jwk_kty_unsupported", call. = FALSE)
  }

  jwk_json <- jsonlite::toJSON(jwk, auto_unbox = TRUE, null = "null")
  key <- try(jose::read_jwk(jwk_json), silent = TRUE)
  if (inherits(key, "try-error")) {
    stop("jwk_parse_failed", call. = FALSE)
  }

  key
}

local_compute_jwk_thumbprint <- function(jwk) {
  if (!is.list(jwk)) {
    stop("jwk_thumbprint_invalid_jwk", call. = FALSE)
  }

  kty <- jwk$kty %||% NA_character_
  canon <- switch(
    kty,
    RSA = list(
      e = jwk$e %||% stop("jwk_thumbprint_missing_e", call. = FALSE),
      kty = "RSA",
      n = jwk$n %||% stop("jwk_thumbprint_missing_n", call. = FALSE)
    ),
    EC = list(
      crv = jwk$crv %||% stop("jwk_thumbprint_missing_crv", call. = FALSE),
      kty = "EC",
      x = jwk$x %||% stop("jwk_thumbprint_missing_x", call. = FALSE),
      y = jwk$y %||% stop("jwk_thumbprint_missing_y", call. = FALSE)
    ),
    OKP = list(
      crv = jwk$crv %||% stop("jwk_thumbprint_missing_crv", call. = FALSE),
      kty = "OKP",
      x = jwk$x %||% stop("jwk_thumbprint_missing_x", call. = FALSE)
    ),
    stop("jwk_thumbprint_kty_unsupported", call. = FALSE)
  )

  canon <- canon[sort(names(canon))]
  json <- jsonlite::toJSON(canon, auto_unbox = TRUE, null = "null", digits = NA)
  local_base64url_encode(openssl::sha256(charToRaw(as.character(json))))
}

local_extract_jwks_keys <- function(jwks) {
  keys <- if (is.list(jwks) && !is.null(jwks$keys)) jwks$keys else jwks

  if (is.data.frame(keys)) {
    return(unname(lapply(seq_len(nrow(keys)), function(i) {
      as.list(keys[i, , drop = FALSE])
    })))
  }

  if (!is.list(keys)) {
    return(list())
  }

  nm <- names(keys)
  if (!is.null(nm) && any(nm %in% c("kty", "kid", "n", "e", "crv", "x", "y"))) {
    return(list(keys))
  }

  Filter(is.list, unname(keys))
}

local_jwk_matches_alg <- function(jwk, alg) {
  kty <- toupper(as.character(jwk$kty %||% ""))
  alg <- toupper(as.character(alg %||% ""))

  if (length(jwk$alg %||% NULL)) {
    key_alg <- toupper(as.character(jwk$alg))
    if (!identical(key_alg, alg)) {
      return(FALSE)
    }
  }

  key_use <- toupper(as.character(jwk$use %||% ""))
  if (nzchar(key_use) && !identical(key_use, "SIG")) {
    return(FALSE)
  }

  key_ops <- as.character(unlist(
    jwk$key_ops %||% character(),
    use.names = FALSE
  ))
  if (length(key_ops) > 0L && !"verify" %in% key_ops) {
    return(FALSE)
  }

  if (startsWith(alg, "RS") || startsWith(alg, "PS")) {
    return(identical(kty, "RSA"))
  }
  if (startsWith(alg, "ES")) {
    return(identical(kty, "EC"))
  }
  if (startsWith(alg, "ED")) {
    return(identical(kty, "OKP"))
  }

  FALSE
}

local_select_candidate_jwks <- function(jwks, header_alg, kid = NULL) {
  keys <- local_extract_jwks_keys(jwks)
  if (length(keys) == 0L) {
    return(list())
  }

  if (is.character(kid) && length(kid) == 1L && !is.na(kid) && nzchar(kid)) {
    keys <- Filter(
      function(key) identical(key$kid %||% NA_character_, kid),
      keys
    )
  }

  Filter(function(key) local_jwk_matches_alg(key, header_alg), keys)
}

local_dpop_target_uri <- function(url) {
  parsed <- try(httr2::url_parse(url), silent = TRUE)
  if (inherits(parsed, "try-error")) {
    stop("dpop_target_uri_invalid", call. = FALSE)
  }

  parsed$query <- NULL
  parsed$fragment <- NULL
  parsed$scheme <- tolower(parsed$scheme %||% "")
  parsed$hostname <- tolower(parsed$hostname %||% "")

  port <- as.character(parsed$port %||% "")
  if (identical(parsed$scheme, "https") && identical(port, "443")) {
    parsed$port <- NULL
  }
  if (identical(parsed$scheme, "http") && identical(port, "80")) {
    parsed$port <- NULL
  }

  httr2::url_build(parsed)
}

local_dpop_access_token_hash <- function(access_token) {
  token_raw <- charToRaw(enc2utf8(access_token))
  if (any(token_raw > as.raw(0x7f))) {
    stop("dpop_access_token_non_ascii", call. = FALSE)
  }

  local_base64url_encode(openssl::sha256(token_raw))
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

  sig <- local_base64url_decode_raw(parts[[3]])
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

verify_signed_access_token_independent <- function(access_token, issuer, jwks) {
  header <- local_parse_jwt_header(access_token, label = "access_token")
  payload <- local_parse_jwt_payload(access_token, label = "access_token")

  alg <- toupper(header$alg %||% "")
  if (!nzchar(alg)) {
    stop("access_token_alg_missing", call. = FALSE)
  }

  keys <- local_select_candidate_jwks(
    jwks,
    header_alg = alg,
    kid = header$kid %||% NULL
  )
  if (length(keys) == 0L) {
    stop("no_matching_jwks_key", call. = FALSE)
  }

  verified <- FALSE
  for (key in keys) {
    pub <- try(local_jwk_to_pubkey(key), silent = TRUE)
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

verify_dpop_proof_independent <- function(
  proof,
  req_method,
  req_url,
  access_token,
  enforce_jti_replay,
  jti_cache,
  iat_leeway = 30
) {
  header <- local_parse_jwt_header(proof, label = "dpop")
  payload <- local_parse_jwt_payload(proof, label = "dpop")

  typ <- tolower(header$typ %||% "")
  if (!identical(typ, "dpop+jwt")) {
    stop("dpop_typ_invalid", call. = FALSE)
  }

  jwk <- header$jwk %||% NULL
  if (!is.list(jwk) || length(jwk) == 0L) {
    stop("dpop_jwk_missing", call. = FALSE)
  }

  pub <- try(local_jwk_to_pubkey(jwk), silent = TRUE)
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

  expected_htu <- local_dpop_target_uri(req_url)
  if (!identical(payload$htu %||% NA_character_, expected_htu)) {
    stop("dpop_htu_mismatch", call. = FALSE)
  }

  expected_ath <- local_dpop_access_token_hash(access_token)
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
    jwk_thumbprint = local_compute_jwk_thumbprint(jwk)
  )
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

bind_independent_dpop_helpers <- function() {
  helper_env <- new.env(parent = baseenv())
  helper_bindings <- list(
    `%||%` = `%||%`,
    local_base64url_encode = local_base64url_encode,
    local_base64url_decode_raw = local_base64url_decode_raw,
    local_parse_compact_jwt_part = local_parse_compact_jwt_part,
    local_parse_jwt_header = local_parse_jwt_header,
    local_parse_jwt_payload = local_parse_jwt_payload,
    local_jwk_to_pubkey = local_jwk_to_pubkey,
    local_compute_jwk_thumbprint = local_compute_jwk_thumbprint,
    local_extract_jwks_keys = local_extract_jwks_keys,
    local_jwk_matches_alg = local_jwk_matches_alg,
    local_select_candidate_jwks = local_select_candidate_jwks,
    local_dpop_target_uri = local_dpop_target_uri,
    local_dpop_access_token_hash = local_dpop_access_token_hash,
    verify_dpop_jws_signature = verify_dpop_jws_signature,
    verify_signed_access_token_independent = verify_signed_access_token_independent,
    verify_dpop_proof_independent = verify_dpop_proof_independent
  )

  for (name in names(helper_bindings)) {
    binding <- helper_bindings[[name]]
    if (is.function(binding)) {
      environment(binding) <- helper_env
    }
    assign(name, binding, envir = helper_env)
  }

  list(
    verify_access_token = get(
      "verify_signed_access_token_independent",
      envir = helper_env,
      inherits = FALSE
    ),
    verify_proof = get(
      "verify_dpop_proof_independent",
      envir = helper_env,
      inherits = FALSE
    )
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
  implementation = c("package", "independent"),
  enforce_jti_replay = TRUE,
  iat_leeway = 30,
  .local_envir = parent.frame()
) {
  testthat::skip_if_not_installed("webfakes")

  implementation <- match.arg(implementation)

  if (is.null(issuer)) {
    issuer <- resolve_keycloak_helper("get_issuer")()
  }
  if (is.null(jwks)) {
    jwks <- resolve_keycloak_helper("get_jwks")(force = TRUE)
  }

  coalesce <- `%||%`
  if (identical(implementation, "independent")) {
    # webfakes runs this app in a child R process; give the independent
    # verifier a self-contained helper environment so nested local helpers are
    # still available after serialization.
    independent_helpers <- bind_independent_dpop_helpers()
    verify_access_token <- independent_helpers$verify_access_token
    verify_proof <- independent_helpers$verify_proof
  } else {
    verify_access_token <- verify_signed_access_token
    verify_proof <- verify_dpop_proof
  }

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
