# Repeated authorization at one client

Install the current checkout, then run from the repository root:

```sh
Rscript integration/connections/run-tests.R --repeated
Rscript integration/connections/run-tests.R --post --repeated
```

The default retention runner includes these scenarios alongside the existing
two-site tests. Each outgoing method covers eight scenarios: query/form POST
callbacks, synchronous/mirai refresh, and distinct/reused provider credentials.
Each scenario follows the provider authorization page and callback twice for
the same client, selects both local connection IDs explicitly, reads the
corresponding synthetic account, and restores both records after navigation.

Distinct grants refresh independently and preserve each account's data. Local
disconnection of one leaves the other usable. With provider-reused credentials,
rotation of one record invalidates the sibling before another token request
can replay its superseded refresh credential. Provider metrics require zero
rejected refreshes and zero revocations for local disconnection.

The runner requires every assertion to pass without skips and records the
selected outgoing method, test files, versions and counts in its ignored
`.artifacts` directory. These tests use a synthetic provider with real HTTP,
PKCE, callbacks, token rotation, Shiny navigation and browser retention. They
do not establish interoperability with an unmodified external SMART server.
