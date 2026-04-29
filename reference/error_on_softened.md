# Throw an error if any safety checks have been disabled

This function checks if any safety checks have been disabled via options
that relax shinyOAuth's default safety protections. If any such options
are detected, an error is thrown so callers can fail fast in deployments
that expect the default hardening.

## Usage

``` r
error_on_softened()
```

## Value

Invisible TRUE if no safety checks are disabled; otherwise, an error is
thrown.

## Details

It checks for the following options:

- `shinyOAuth.skip_browser_token`: Skips browser cookie presence check

- `shinyOAuth.skip_id_sig`: Skips ID token signature verification

- `shinyOAuth.expose_error_body`: Exposes HTTP response bodies

- `shinyOAuth.allow_unsigned_userinfo_jwt`: Accepts unsigned
  (`alg=none`) UserInfo JWTs

- `shinyOAuth.allow_redirect`: Allows sensitive HTTP flows to follow
  redirects

## Examples

``` r
# Throw an error if any softening options that relax default safety
# protections are enabled
# Below call does not error if run with default options:
error_on_softened()

# Below call would error (is therefore not run):
if (FALSE) { # \dontrun{
options(shinyOAuth.skip_id_sig = TRUE)
error_on_softened()
} # }
```
