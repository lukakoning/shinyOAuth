# Register a SMART EHR launch entry route

Declare which approved SMART clients an EHR launch URL may select. Pass
the result in `launch_routes` to
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md).
The route is separate from OAuth callbacks: `iss` means the FHIR base
only here. Both `iss` and `launch` are required, and callback parameters
are rejected on this route.

## Usage

``` r
smart_launch_route(path, clients, max_age = 120)
```

## Arguments

- path:

  Absolute application path, such as `"/smart/launch"`. Register
  `paste0(manager$app_origin, path)` with the EHR. It must be inside the
  UI's `app_base_path` and distinct from every callback and other launch
  route. Accepted percent-encoded unreserved characters are stored
  decoded.

- clients:

  Character vector of names from the manager's `clients` list, not OAuth
  `client_id` values. Each must select an EHR-mode
  [`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md).
  A route cannot contain two registrations for the same exact FHIR base;
  give those registrations separate launch routes.

- max_age:

  Launch handoff lifetime in seconds, 30 to 300, default 120. The
  handoff must be consumed and its authorization parameters prepared
  before this deadline. Once prepared, login uses the client's
  `state_payload_max_age`, bounded by owner expiry; the handoff deadline
  does not shorten consent time.

## Value

A plain route configuration list, with no credentials or live state.

## Details

Initial entry is untrusted. It selects an already configured client by
exact FHIR base, performs no discovery, and establishes no healthcare
identity. A short-lived encrypted record binds the opaque launch handle
to the browser owner and client. A clean continuation proves that owner
before a fresh OAuth state/PKCE transaction can begin. Consumed handles
cannot be reused to reconnect.

The initial implementation supports top-level GET entry with browser
retention in one R process. Account/session-only retention and iframe
deployments are not supported for EHR entry yet. The ordinary standalone
manager remains usable with its existing retention choices. Up to eight
unconsumed launch records are retained per browser owner across all of a
manager's launch routes, with a total limit of 1,000 per manager.
Further entries are rejected without evicting existing tickets.
Consuming or expiring a ticket releases its capacity. Raw query size is
limited to 8 KiB, launch handles to 2 KiB, and the only allowed initial
parameters are `iss` and `launch`.

Apply ingress rate limits to both launch entry and ordinary pages that
create browser owners. The owner quota isolates an existing browser's
pending work; it is not a per-person or per-network-client rate limit,
since unauthenticated callers can obtain additional browser owners.
Configure these controls at a trusted reverse proxy using its verified
client address, not arbitrary inbound forwarded headers. Size the owner
registry for the admitted traffic window.

The HTTP response uses no-store and no-referrer policy and redirects to
an opaque, owner-bound continuation. The package's external JavaScript
removes that ticket from browser history before Shiny connects. The
ticket alone cannot authorize a connection. No inline script permission
or additional CSP nonce is needed for the handoff. Application access
logs must also avoid recording raw launch query strings. Normal callback
issuer checks and single-use browser/state checks still apply.

## References

[SMART EHR
launch](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html#launch-app-ehr-launch)

## See also

[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md),
[`oauth_connections_ui()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_connections_ui.md)

## Examples

``` r
if (FALSE) { # \dontrun{
# hospital is an EHR-mode SMART client; manager uses browser retention.
ui <- oauth_connections_ui(app_ui, "health", manager,
  launch_routes = list(smart_launch_route("/smart/launch", "hospital")))
} # }
```
