# This file contains package-level namespace declarations and roxygen metadata
# Used for whole-package imports and package startup declarations

# 1 Package metadata -----------------------------------------------------------

## 1.1 Namespace and imports ---------------------------------------------------

#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @import httr2
#' @import rlang
#' @import S7
#' @importFrom cli cli_format
#' @importFrom jsonlite fromJSON toJSON
#' @importFrom openssl sha256 base64_encode rand_bytes
#' @importFrom stats runif
## usethis namespace: end
NULL

# enable usage of <S7_object>@name in package code
#' @rawNamespace if (getRversion() < "4.3.0") importFrom("S7", "@")
NULL
