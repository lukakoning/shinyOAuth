# Read a connection's current SMART context

Return interpreted patient/encounter and validated user references for
the current accepted token. This is sensitive data; keep it out of
general status tables and logs. Raw token extensions remain available
separately on tokens.

## Usage

``` r
smart_context(connection)

smart_patient(connection)

smart_fhir_user(connection)
```

## Arguments

- connection:

  An
  [OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
  for a
  [`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md),
  accessed in its owning Shiny session.

## Value

`smart_context()` returns a list with `version`, `fhir_base`,
`revision`, `changed`, `patient`, `encounter`, `fhirUser` and
`need_patient_banner`. Absent values are `NULL`. `revision` increases
when interpreted context changes; key patient-dependent application data
by connection ID and this revision. Refresh omission carries context
forward, except that a changed or cleared patient clears an omitted
encounter. Explicit null clears a field, unless patient access still
requires patient context. An initial launch query never establishes this
context.

`smart_patient()` and `smart_fhir_user()` return an
[httr2](https://httr2.r-lib.org/reference/httr2-package.html) response.

## Details

`smart_patient()` fetches the contextual Patient only when the current
grant covers `patient/Patient.r` or `user/Patient.r`.
`smart_fhir_user()` fetches the identity reference only from a validated
ID token. It accepts `openid fhirUser`, a matching user read scope, or
patient read permission when the identity is the contextual Patient.
Both stay inside the FHIR base and refuse redirects. Both request JSON
with `Accept: application/fhir+json`. A foreign `fhirUser` reference is
reported as context but is never fetched with this connection's token.
FHIR search, write, batch and pagination helpers are outside these two
convenience methods.

Patient IDs and user identity are different: the first identifies a
chart, the second the authenticated user. Neither changes the local
connection owner. General summaries omit all of this data. The
application remains responsible for displaying patient identity clearly
and discarding data from an older context revision. Experimental
`fhirContext` and styling extensions remain raw data and are not
automatically fetched or interpreted. Location-specific
`authorization_details` apply scope, patient and encounter overrides
only for the configured FHIR base, with omitted fields falling back to
this response's top-level values. Other locations never add
destinations. Malformed details or multiple entries matching this base
are rejected.

## See also

[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md),
[OAuthConnection](https://lukakoning.github.io/shinyOAuth/reference/OAuthConnection.md)
