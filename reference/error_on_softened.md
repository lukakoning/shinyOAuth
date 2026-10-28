# Check selected debugging options (deprecated)

**\[deprecated\]**

Raise an error if any of the debugging options listed below are enabled.
This deprecated helper checks only those options. Add explicit startup
checks for the settings your deployment permits or forbids.

## Usage

``` r
error_on_softened()
```

## Value

Invisible `TRUE` if none of those options are enabled; otherwise an
error is thrown.

## Details

It only checks the following options:

- `shinyOAuth.skip_browser_token`: Skips browser cookie presence check

- `shinyOAuth.skip_id_sig`: Skips ID token signature verification

- `shinyOAuth.expose_error_body`: Exposes HTTP response bodies and claim
  values in diagnostics

- `shinyOAuth.allow_unsigned_userinfo_jwt`: Accepts unsigned
  (`alg=none`) UserInfo JWTs

- `shinyOAuth.allow_redirect`: Allows sensitive HTTP flows to follow
  redirects

## Examples

``` r
# error_on_softened() is deprecated and checks only the options in its help page.
# Use startup checks for the exact settings your deployment permits.

# Default options pass this check:
error_on_softened()
#> Warning: [shinyOAuth] - Deprecated API
#> ! `error_on_softened()` was deprecated in shinyOAuth 0.4.0.9000.
#> ✖ This helper only checks a small subset of shinyOAuth's security-relaxing
#>   options
#> ℹ Use explicit startup checks for options like
#>   `shinyOAuth.allow_non_atomic_state_store` and
#>   `shinyOAuth.unblock_auth_params` when they matter to your deployment

# This call would raise an error:
if (interactive()) {
  (function() {
    old <- options(shinyOAuth.skip_id_sig = TRUE)
    on.exit(options(old), add = TRUE)
    error_on_softened()
  })()
}
```
