# Local experiments

These scripts are for trying individual providers and advanced configurations
during package development. For a first app, use the
[getting-started guide](../vignettes/usage.Rmd); for a complete Spotify dashboard,
see [the installed example](../inst/examples/spotify-dashboard.R).

Read a script's setup comments and replace its credentials, URLs, and key paths
with your own before running it. Open the app at the exact configured
`redirect_uri` in a regular browser. Keep real secrets out of Git.

- `example-github.R`, `example-github-button.R`, and `example-github-async.R`
  explore automatic login, a login button, and background work.
- The named provider scripts exercise their corresponding service.
- The Keycloak scripts cover local login, POST callbacks, and JWT client
  authentication. The [integration environment](../integration/keycloak/README.md)
  provides a repeatable local provider setup.
- `example-otel-tui.R` explores telemetry with a local collector.

Some scripts use the lower-level `use_shinyOAuth()` UI setup. For a new app,
wrap the complete UI with `oauth_ui()`, or use `oauth_form_post_ui()` for POST
callbacks. These include the browser setup and a callback privacy header.
