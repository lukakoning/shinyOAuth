# Throw an error if any safety checks have been disabled

This function checks if any safety checks have been disabled via options
intended for local development use only. If any such options are
detected, an error is thrown to prevent accidental use in production
environments.

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

- `shinyOAuth.print_errors`: Enables printing of error messages

- `shinyOAuth.print_traceback`: Enables printing of tracebacks (opt-in
  only; default FALSE)

- `shinyOAuth.expose_error_body`: Exposes HTTP response bodies

Note: Tracebacks are only treated as a "softened" behavior when the
`shinyOAuth.print_traceback` option is explicitly set to `TRUE`. The
default is `FALSE`, even in interactive or test sessions.

## Examples

``` r
# Throw an error if any developer-only softening options are enabled
# Below call does not error if run with default options:
error_on_softened()

# Below call would error (is therefore not run):
if (FALSE) { # \dontrun{
options(shinyOAuth.skip_id_sig = TRUE)
error_on_softened()
} # }
```
