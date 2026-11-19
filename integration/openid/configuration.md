# Message Signing configuration assessment

The conformance fixture checks its configured client before starting the
`fapi-message-signing` authorization scenarios. This is a local assessment for
the existing OIDC/private-key-JWT/ES256/DPoP/`jwt` selection. It does not change
the package's general OAuth/JAR defaults or create a public FAPI preset.

```r
source("integration/openid/helper-configuration.R")
assessment <- openid_message_signing_configuration(client)
assessment[c("profile", "local_configuration_passed", "issues", "unassessed")]
openid_assert_message_signing_configuration(client)
```

The assertion stops with failed check IDs before the fixture sends PAR. The
result contains named boolean checks, stable issue IDs, explicit unassessed
limits and `certification_status = "not_assessed"`. It includes no client
object, key, client/issuer values, URL, token or raw exception message. The helper is
integration tooling; it does not establish a protocol verdict or certification.

## Selected settings

The application must supply its trusted issuer, registered client/redirect and
registered ES256 authentication key. Those inputs and the provider's acceptance
of them remain outside the local assessment. For example, once `issuer`,
`client_id`, `redirect_uri` and `authentication_key` have been provisioned:

```r
provider <- shinyOAuth::oauth_provider_oidc_discover(
  issuer,
  id_token_profile = "fapi2",
  token_auth_style = "private_key_jwt",
  allowed_token_types = "DPoP",
  authorization_request_front_channel_mode = "minimal",
  userinfo_allowed_algs = c("ES256", "EdDSA", "Ed25519")
)
client <- shinyOAuth::oauth_client(
  provider,
  client_id = client_id,
  redirect_uri = redirect_uri,
  scopes = c("openid", "profile"),
  client_assertion_private_key = authentication_key,
  client_assertion_alg = "ES256",
  client_assertion_audience = issuer,
  dpop_private_key = openssl::ec_keygen("P-256"),
  dpop_signing_alg = "ES256",
  request_object_mode = "request",
  request_object_signing_alg = "ES256",
  request_object_audience = issuer,
  request_object_ttl = 45,
  request_object_nbf_skew = 0,
  response_mode = "jwt",
  jarm_signed_response_alg = "ES256",
  state_transport = "reference"
)
openid_assert_message_signing_configuration(client)
```

The discovered provider must supply HTTPS authorization, token, PAR and JWKS
endpoints. The checks inspect the actual constructed client and effective
endpoint authentication/audiences, including PAR overrides. They check S256,
nonce/ID-token validation, signature/browser-binding policy, TLS configuration,
the configured signing algorithms and DPoP token policy. Reference state,
ES256, DPoP without additional mTLS intent and unencrypted requests/responses
are policies of this selected fixture;
other valid FAPI/OAuth configurations need their own assessment.

The assessment rejects extra mTLS intent on the client or its effective
token/PAR authentication clients. Such intent can select mTLS endpoint aliases,
so checking only the provider's base HTTPS URLs would be insufficient.
Advertised aliases alone do not select mTLS. Mixed DPoP/mTLS configurations
remain available through the general APIs, outside this named selection.

UserInfo has a separate algorithm policy. The fixture explicitly restricts
accepted signed responses to implemented FAPI algorithms; JSON UserInfo remains
supported. If discovery leaves no compatible signed algorithm and signed
UserInfo is not required, the empty list rejects signed JWTs rather than
reintroducing a broader allowlist. Selecting `id_token_profile = "fapi2"` alone
does not configure these independent JWT purposes.

## Request Object timing

The builder emits `iat = floor(now)`, `nbf = iat - skew` and `exp = iat + TTL`.
The assessed validity window is therefore **TTL + skew**, using the
[Message Signing Request Object requirements](https://openid.net/specs/fapi-message-signing-2_0-final.html#section-5.3).
The helper requires explicit `nbf`, a finite positive TTL, a finite nonnegative
skew and a window no longer than 3,600 seconds.

| TTL | Skew | Window | Local timing result |
| --- | --- | --- | --- |
| 45 | 0 | 45 | Pass; the current fixture setting. |
| 3600 | 0 | 3600 | Boundary passes. |
| 45 | 3555 | 3600 | Boundary passes. |
| 45 | omitted | No `nbf` | Fail. General JAR can still omit this optional claim. |
| 3601 | 0 | 3601 | Fail. |
| 45 | 3556 | 3601 | Fail. |

These are configuration boundaries. Provider clocks, delivery delays and
runtime acceptance still require independent evidence. The live selection's
shorter 45-second request window and existing wire-evidence checks remain.
The boundary regressions verify real ES256 Request Objects produced through
public preparation APIs, with only the HTTP response boundary stubbed.

## Remaining evidence

Issuer authority/discovery provenance, registration and key custody, public
TLS/DNS/clocks, initiation consent, actual browser behavior, AS/RS/refresh
enforcement, other Message Signing methods and release-source qualification
remain explicit in `unassessed`. JARM carries its own expected issuer; the
helper does not require a separate outer RFC 9207 parameter for that response.
A passing configuration does not establish unconditional JWT-purpose separation;
the G2 corpus in the requirement map retains its observed compatibility limits.
Use the [requirement map](requirements-jwt-signing.md),
[scope](scope.md), [report assessment](assessment.md) and
[source policy](source-identity.md) alongside the configuration result.
