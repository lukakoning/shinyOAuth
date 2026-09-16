The wrapper attack gate runs with `oauth_ui()` and with
`oauth_connections_ui()` / `oauth_connections_server()` using browser retention.
It covers independent-flow login CSRF and callback swaps in isolated browser
contexts, legitimate callback recovery, verified Alice/Bob identity access,
cookie-marker tampering, clean callback URLs, and retained-owner restoration.

The browser binding uses a random cookie marker paired with an origin- and
tab-scoped sessionStorage record. It is not cookie/header double-submit.
Tampering with the marker cannot establish a matching local binding record.

`test_integration_browser_wrapper_attacks.R` is included in the ordinary
Keycloak integration runner. The older direct-module fixtures remain useful
for their individual attack cases. Account substitution within the initiating
transaction identifies the user who actually authenticated at the provider;
applications can inspect the verified identity and enforce an expected account.
