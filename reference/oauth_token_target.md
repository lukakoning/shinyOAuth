# Declare an API token target

Build one entry for
[`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)'s
`token_targets`. Give the entry a name in that list, such as `calendar`,
then select it with a connection method's `target` argument. Plain named
lists with the same fields are also accepted.

## Usage

``` r
oauth_token_target(
  resource,
  scopes,
  required_scopes = character(),
  resource_ids = character(),
  scope_aliases = character()
)
```

## Arguments

- resource:

  Exact API identifier sent to the authorization provider: an absolute
  URI, such as `"urn:example:calendar"`, or a Microsoft application
  GUID. This identifies the token's audience; HTTP destinations are
  configured separately through client `resource_bases`.

- scopes:

  Non-empty character vector of requested API permissions. A
  space-separated string is also accepted. Identity and refresh-consent
  scopes belong in client `scopes`.

- required_scopes:

  Minimum permissions for this API, default
  [`character()`](https://rdrr.io/r/base/character.html). The default
  permits reduced grants; specify the permissions that every usable
  token for this target must cover.

- resource_ids:

  Names of approved client `resource_bases` associated with this target.
  Optional when only exporting tokens to another R package.

- scope_aliases:

  Optional Microsoft short permission names used in token responses. See
  [`oauth_client()`](https://lukakoning.github.io/shinyOAuth/reference/oauth_client.md)
  for provider-specific restrictions.

## Value

A plain named list suitable for an entry in `token_targets`.

## Details

This helper checks field syntax and size limits. Client construction
checks provider support, scope coverage, API associations and
relationships between targets. It preserves the resource identifier
exactly and normalizes scopes into distinct tokens.

## Examples

``` r
oauth_token_target(
  "urn:example:calendar",
  c("calendar.read", "calendar.write"),
  required_scopes = "calendar.read",
  resource_ids = "calendar_api"
)
#> $resource
#> [1] "urn:example:calendar"
#> 
#> $scopes
#> [1] "calendar.read"  "calendar.write"
#> 
#> $required_scopes
#> [1] "calendar.read"
#> 
#> $resource_ids
#> [1] "calendar_api"
#> 
```
