# Check selected debugging options (deprecated)

**\[deprecated\]**

Deprecated helper that errors when a small subset of shinyOAuth's
options that relax security checks or expose debugging details are
enabled. Use explicit startup checks for the exact options your
deployment permits or forbids instead.

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
# Note: error_on_softened() is deprecated because it only checks a narrow subset
# of shinyOAuth's security-relaxing options

# Throw an error if one of the options listed in ?error_on_softened is enabled.
# Below call does not error if run with default options:
error_on_softened()
#> Warning: [shinyOAuth] - Deprecated API
#> ! `error_on_softened()` was deprecated in shinyOAuth 0.4.0.9000.
#> ✖ This helper only checks a small subset of shinyOAuth's security-relaxing
#>   options
#> ℹ Use explicit startup checks for options like
#>   `shinyOAuth.allow_non_atomic_state_store` and
#>   `shinyOAuth.unblock_auth_params` when they matter to your deployment

# Below call would error (is therefore not run):
if (interactive()) {
  options(shinyOAuth.skip_id_sig = TRUE)
  error_on_softened()
}
```
