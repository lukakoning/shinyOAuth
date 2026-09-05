# Deploy the example to Posit Connect Cloud

This folder contains two Shiny apps with GitHub login:

- `app.R` starts login when the user clicks a button.
- `app-auto-redirect.R` starts login automatically.

You need a GitHub OAuth App registration, a Connect Cloud account, and this
repository available to the deployment. For local setup first, see
[Getting started](../../vignettes/usage.Rmd).

## Use the app's direct address

OAuth login needs the app to open directly in a browser tab. Use the sharing
URL from the content's **Settings > URL** page, such as
`https://<content-id>.share.connect.posit.cloud`, or a configured custom URL.
See [Connect Cloud URL settings](https://docs.posit.co/connect-cloud/user/manage/content_settings.html#url).
The administrative content page at `connect.posit.cloud/.../content/...` is
not your app's callback address.

## Configure and deploy

1. Generate the manifest below for the app variant you want to publish.
2. Publish the repository as a Shiny app, selecting `integration/posit/app.R`
   or `integration/posit/app-auto-redirect.R` as the primary file.
3. Set `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, and
   `OAUTH_REDIRECT_URI` in the deployment's environment variables.
4. Set `OAUTH_REDIRECT_URI` to the direct app URL and register that exact
   URL as the authorization callback in your GitHub OAuth App.
5. Open the direct URL and test login.

## Manifest generation

Posit Connect Cloud requires a `manifest.json` file for R content. The helper script in this directory generates it with `rsconnect::writeManifest()`.

Install the helper packages locally if needed:

```r
install.packages(c("remotes", "rsconnect"))
```

Then regenerate the manifest from the repository root:

```bash
Rscript integration/posit/write-manifest.R
```

That default command writes `manifest.json` for `app.R`. To target the auto-redirect variant instead:

```bash
SHINYOAUTH_POSIT_PRIMARY_DOC=app-auto-redirect.R Rscript integration/posit/write-manifest.R
```

By default, the script temporarily installs `shinyOAuth` from `lukakoning/shinyOAuth@master` so `rsconnect` records it as a GitHub dependency instead of a local source package. Override that source when needed:

```bash
SHINYOAUTH_GITHUB_REF=<branch-tag-or-sha> Rscript integration/posit/write-manifest.R
```

Only one `manifest.json` can live in this folder at a time, so regenerate it for the app file you plan to publish. Also rerun it whenever app dependencies change or when you want to pin a different `shinyOAuth` GitHub revision.

## Deployment reference

Keep `manifest.json` alongside the selected app file. Regenerate it when
dependencies change. If callbacks can reach different R processes, configure
shared state and a shared key as described in
[Getting started](../../vignettes/usage.Rmd).

- [Connect Cloud Shiny deployment](https://docs.posit.co/connect-cloud/how-to/r/shiny-r.html)
- [Dependency and manifest guide](https://docs.posit.co/connect-cloud/how-to/r/dependencies.html)
- [`rsconnect::writeManifest()`](https://rstudio.github.io/rsconnect/reference/writeManifest.html)
