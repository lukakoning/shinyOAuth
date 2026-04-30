# This file contains the format() and print() helpers for shinyOAuth objects.
# Use them to keep console output readable while still hiding secrets and other
# nested internals that would be noisy or unsafe to print in full.

# 1 Print helpers ----------------------------------------------------------

## 1.1 Shared formatting helpers ------------------------------------------

# Render object-like fields as short labels instead of dumping nested internals.
.shinyoauth_object_label <- function(x) {
  if (S7::S7_inherits(x, OAuthProvider)) {
    provider_name <- x@name %||% NA_character_
    if (
      is.character(provider_name) &&
        length(provider_name) == 1L &&
        !is.na(provider_name) &&
        nzchar(provider_name)
    ) {
      return(paste0(
        "<OAuthProvider ",
        encodeString(provider_name, quote = '"'),
        ">"
      ))
    }
    return("<OAuthProvider>")
  }

  classes <- class(x)
  classes <- classes[!is.na(classes) & nzchar(classes)]

  if (length(classes) == 0L) {
    return(paste0("<", typeof(x), ">"))
  }

  paste0("<", classes[[1]], ">")
}

# Format one field for console output.
# Used by the shared object formatter. Input: one value plus redaction and
# preview settings. Output: one short display string.
# Format one field for console output.
# Secret fields keep only a safe summary or a short preview.
.shinyoauth_format_field <- function(
  x,
  secret = FALSE,
  max_items = 4L,
  preview_chars = 4L
) {
  if (is.null(x)) {
    return("NULL")
  }

  if (isTRUE(secret)) {
    if (is.raw(x)) {
      return(paste0("<redacted raw[", length(x), "]>"))
    }

    if (is.character(x)) {
      if (length(x) == 0L) {
        return("<redacted chr[0]>")
      }

      if (length(x) != 1L) {
        return(paste0("<redacted chr[", length(x), "]>"))
      }

      value <- x[[1]]
      if (is.na(value)) {
        return("NA")
      }

      pem_header <- strsplit(value, "\n", fixed = TRUE)[[1]][[1]]
      pem_header <- sub("\r$", "", pem_header)
      if (
        grepl(
          "BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY",
          pem_header,
          ignore.case = TRUE,
          perl = TRUE
        )
      ) {
        key_label <- sub(
          ".*BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY).*",
          "\\1",
          pem_header,
          ignore.case = TRUE,
          perl = TRUE
        )
        return(paste0("<redacted ", toupper(key_label), ">"))
      }

      chars <- nchar(value, type = "chars")
      if (chars <= (preview_chars * 2L + 3L)) {
        return("<redacted>")
      }

      return(paste0(
        "<redacted ",
        encodeString(
          paste0(
            substr(value, 1L, preview_chars),
            "...",
            substr(value, chars - preview_chars + 1L, chars)
          ),
          quote = '"'
        ),
        ">"
      ))
    }

    return(paste0("<redacted ", .shinyoauth_object_label(x), ">"))
  }

  if (is.raw(x)) {
    return(paste0("raw [", length(x), "]"))
  }

  if (is.character(x)) {
    if (length(x) == 0L) {
      return("chr [0]")
    }

    if (length(x) == 1L) {
      if (is.na(x)) {
        return("NA")
      }
      return(paste0("chr ", encodeString(x, quote = '"')))
    }

    shown <- utils::head(x, max_items)
    suffix <- if (length(x) > max_items) ", ..." else ""
    items <- vapply(
      shown,
      function(item) {
        if (is.na(item)) {
          return("NA")
        }
        encodeString(item, quote = '"')
      },
      character(1)
    )

    return(paste0(
      "chr [",
      length(x),
      "] c(",
      paste(items, collapse = ", "),
      suffix,
      ")"
    ))
  }

  if (is.numeric(x)) {
    if (length(x) == 0L) {
      return("num [0]")
    }
    if (length(x) == 1L) {
      if (is.na(x)) {
        return("NA")
      }
      return(paste0("num ", format(x, scientific = FALSE, trim = TRUE)))
    }
    return(paste0("num [", length(x), "]"))
  }

  if (is.logical(x)) {
    if (length(x) == 0L) {
      return("logi [0]")
    }
    if (length(x) == 1L) {
      if (is.na(x)) {
        return("NA")
      }
      return(paste0("logi ", if (isTRUE(x)) "TRUE" else "FALSE"))
    }
    return(paste0("logi [", length(x), "]"))
  }

  if (is.list(x)) {
    entry_names <- names(x)
    entry_names <- entry_names[!is.na(entry_names) & nzchar(entry_names)]

    if (length(entry_names) == 0L) {
      return(
        if (length(x) == 0L) "list()" else paste0("list [", length(x), "]")
      )
    }

    shown <- utils::head(entry_names, max_items)
    suffix <- if (length(entry_names) > max_items) ", ..." else ""

    return(paste0(
      "list [",
      length(x),
      "] (",
      paste(shown, collapse = ", "),
      suffix,
      ")"
    ))
  }

  .shinyoauth_object_label(x)
}

# Build the aligned multi-line text representation shared by shinyOAuth
# objects.
# Used by format() methods. Input: class name, visible fields, and the list of
# secret field names. Output: a character vector of display lines.
# Build the aligned multi-line output used by both S7 classes.
.shinyoauth_format_object <- function(
  class_name,
  fields,
  secret_fields = character(0)
) {
  rendered <- vapply(
    names(fields),
    function(name) {
      .shinyoauth_format_field(
        fields[[name]],
        secret = name %in% secret_fields
      )
    },
    character(1)
  )
  field_width <- max(nchar(names(rendered), type = "width"))

  c(
    paste0("<shinyOAuth::", class_name, ">"),
    vapply(
      names(rendered),
      function(i) {
        sprintf(
          " @ %-*s: %s",
          field_width,
          i,
          rendered[[i]]
        )
      },
      character(1)
    )
  )
}

# Print an object by delegating to the matching format() method.
# Used by print() methods. Input: object plus extra print args. Output:
# invisible original object.
# Keep print() thin so format() stays the single source of display logic.
.shinyoauth_print_object <- function(x, ...) {
  cat(format(x, ...), sep = "\n")
  invisible(x)
}

# 2 S7 format and print methods -------------------------------------------

## 2.1 OAuthToken methods --------------------------------------------------

# Format an OAuthToken with redacted secrets and short summaries.
# Used when OAuthToken objects are printed or formatted at the console.
# Input: OAuthToken object. Output: character vector of display lines.
method(format, OAuthToken) <- function(x, ...) {
  # Keep the visible field list explicit so the redaction policy is obvious.
  .shinyoauth_format_object(
    "OAuthToken",
    list(
      access_token = x@access_token,
      token_type = x@token_type,
      refresh_token = x@refresh_token,
      id_token = x@id_token,
      expires_at = x@expires_at,
      userinfo = x@userinfo,
      id_token_validated = x@id_token_validated
    ),
    secret_fields = c("access_token", "refresh_token", "id_token")
  )
}

# Print an OAuthToken using the shared formatter.
# Used at the console. Input: OAuthToken object. Output: invisible original
# object.
method(print, OAuthToken) <- function(x, ...) {
  .shinyoauth_print_object(x, ...)
}

## 2.2 OAuthClient methods -------------------------------------------------

# Format an OAuthClient with redacted secrets and short summaries.
# Used when OAuthClient objects are printed or formatted at the console.
# Input: OAuthClient object. Output: character vector of display lines.
method(format, OAuthClient) <- function(x, ...) {
  # Keep the visible field list explicit so the redaction policy is obvious.
  .shinyoauth_format_object(
    "OAuthClient",
    list(
      provider = x@provider,
      client_id = x@client_id,
      client_secret = x@client_secret,
      client_private_key = x@client_private_key,
      client_private_key_kid = x@client_private_key_kid,
      client_assertion_alg = x@client_assertion_alg,
      client_assertion_audience = x@client_assertion_audience,
      dpop_private_key = x@dpop_private_key,
      dpop_private_key_kid = x@dpop_private_key_kid,
      dpop_signing_alg = x@dpop_signing_alg,
      dpop_require_access_token = x@dpop_require_access_token,
      redirect_uri = x@redirect_uri,
      enforce_callback_issuer = x@enforce_callback_issuer,
      scopes = x@scopes,
      claims = x@claims,
      state_store = x@state_store,
      state_payload_max_age = x@state_payload_max_age,
      state_entropy = x@state_entropy,
      state_key = x@state_key,
      scope_validation = x@scope_validation,
      claims_validation = x@claims_validation,
      required_acr_values = x@required_acr_values,
      introspect = x@introspect,
      introspect_elements = x@introspect_elements
    ),
    secret_fields = c(
      "client_secret",
      "client_private_key",
      "dpop_private_key",
      "state_key"
    )
  )
}

# Print an OAuthClient using the shared formatter.
# Used at the console. Input: OAuthClient object. Output: invisible original
# object.
method(print, OAuthClient) <- function(x, ...) {
  .shinyoauth_print_object(x, ...)
}
