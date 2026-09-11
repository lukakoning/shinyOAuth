# Authorization POST for long requests (P7b)

An authorization request asks the provider to show its login/consent screen.
GET puts that request's parameters in the address. POST puts them in an HTML
form body submitted by the browser. Long SMART scope lists can otherwise run
into URL limits before the provider sees them.

Select `authorization_method = "POST"` in `oauth_client()` or `smart_client()`.
The default remains `"GET"`. For SMART, the discovery snapshot must advertise
`authorize-post`; the factory checks this before creating a client. For ordinary
OAuth, selecting POST means the application has confirmed provider support.
There is no automatic switch based on URL length and no retry using GET.

This fragment illustrates the setting; `discovery` is an approved snapshot and
the callback/client ID must already be registered with that server:

```r
client <- shinyOAuth::smart_client(
  discovery,
  client_id = "registered-app",
  redirect_uri = "https://app.example/callback",
  scopes = c("launch/patient", "patient/Patient.r"),
  authorization_method = "POST"
)
```

Add the client to the existing connection manager and call its normal
`connect()` method. In a single-module app, call `auth$request_login()`.
Both paths submit the browser form automatically. Allow the provider's
authorization endpoint in the application's CSP `form-action` directive.
The current SMART deployment still requires top-level navigation.

`response_mode = "form_post"` is a separate choice: it controls the provider's
return trip to the app. Authorization POST works with query or form POST
callbacks. The latter still needs the normal callback UI/route wrapper.

For a custom application that drives its own browser and callback,
`prepare_authorization_request(client, browser_token)` returns a plain list
with `method`, `url`, and `fields`. POST fields are ordered `{name, value}` pairs,
so repeated `resource` parameters survive. Submit them as hidden inputs through
DOM properties or escaped HTML, with form method POST and
`application/x-www-form-urlencoded`. See the
[generated API help](../../man/prepare_authorization_request.Rd). Do not perform
this user-facing authorization step as an R HTTP request: the user needs their
browser login session. `prepare_call()` and `auth$build_auth_url()` remain
URL-only helpers and reject a POST client before creating login state.

## What stays bound to the login attempt

The common builder still creates state, PKCE and an OIDC nonce where required.
The selected method enters the client policy fingerprint; changing it cannot
reuse an earlier transaction. Managed owner, client, generation, callback and
one-use EHR launch checks use the existing preparation and acceptance paths.
The SMART method also belongs to the client's checked discovery policy.

POST changes the final browser serialization. It preserves fixed endpoint query
bytes and the existing singleton-conflict checks. Ordinary OAuth/OIDC PAR,
signed Request Objects, JARM, DPoP and mTLS retain their configured requirements;
POST does not bypass them. SMART still rejects those optional compositions
until P4c2 supplies its own profile policy and evidence.

The form allows at most 256 fields and 128 KiB of encoded data. Newlines and
the browser-reserved `_charset_` field are rejected because a browser would
rewrite their values. State and callback limits still apply: POST does not
remove the state parameter from the eventual callback. A very large scope set
can therefore still be rejected by the existing state budget.

## Verification and release gates

Install this checkout, then run from the repository root:

```sh
Rscript integration/smart/run-profiles.R --post
Rscript integration/connections/run-tests.R --post
Rscript integration/conformance/run-tests.R
```

- SMART: 24 browser scenarios cover public, Basic and RS384 registrations;
  standalone and EHR launch; query and form POST callbacks; sync and mirai.
  Each request includes 32 additional granular scopes and exceeds 8 KiB in its
  form body. The fixture rejects GET, checks the fixed query separately, and
  verifies all scopes, S256, `aud`, nonce and launch parameters. Both sites then
  complete identity, FHIR access, refresh narrowing, retention and logout checks.
- Ordinary OAuth: four browser scenarios verify POST with both callback
  transports and sync/mirai, navigation between sites, rotation and isolation.
- Independent Python server: both GET and POST run the RS256/RS384 signed
  request combinations over local TLS, including PAR, DPoP, mTLS, signed JARM
  and client assertions. Python verifies signatures and transaction claims.
  These are HTTP interoperability tests; the two browser suites verify the DOM
  form and browser session behavior.
- Package tests cover fixed/repeated/literal fields, policy binding, unsupported
  SMART capability, callback completion, cleanup on preparation failure, form
  limits, PAR expiry and discarded prepared state. Node checks the form handler.

The combined `run-coverage.R` and `smart-ehr.yml` include both new POST browser
gates. Evidence records the selected method and keeps synthetic fixtures
separate from external SMART conformance. Run without `--post` to verify the GET
default. `--quick --post` runs only three SMART scenarios and is diagnostic.

The unmodified Docker sandbox still fails strict discovery because its
asymmetric authentication advertisement omits the required algorithm list.
An external POST app flow has consequently not run. Once a compatible deployment
is available, P4e/P5b must repeat standalone/EHR and retained two-site scenarios
using both outgoing methods; P4f must include POST in independent client
verification. See [coverage and open external gates](coverage.md).

## Protocol references checked during implementation

- [OAuth 2.0, section 3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1):
  GET is required and POST is optional; fixed endpoint queries are retained.
- [OIDC Core, section 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest):
  servers support both browser methods, using query or form serialization.
- [SMART STU 2.2 authorization](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html#obtain-authorization-code)
  and [capabilities](https://hl7.org/fhir/smart-app-launch/STU2.2/conformance.html#capabilities):
  browser form submission and the `authorize-post` support advertisement.
- [WHATWG form serialization](https://url.spec.whatwg.org/#application-x-www-form-urlencoded):
  UTF-8 form encoding, including characters whose encoded size differs from
  ordinary URI encoding. R and JavaScript apply the same form-size budget.
