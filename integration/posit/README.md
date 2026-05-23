# Posit Connect Cloud example

This directory contains a minimal Shiny app that authenticates with GitHub via `shinyOAuth` and is structured for deployment on Posit Connect Cloud.

Available app variants in this folder:

- `app.R`: manual login button using `auth$request_login()`
- `app-auto-redirect.R`: standard `auto_redirect = TRUE` flow

Both variants assume you deploy and test them via a top-level app URL, not an embedded Connect Cloud content URL.

The default content URL looks like `https://connect.posit.cloud/<account>/content/<id>` and is rendered inside the Connect Cloud shell. That default embedded URL is not suitable as an OAuth redirect URI.

The top-level app URL can be either:

- a claimed Posit Connect Cloud URL such as `https://your-app.share.connect.posit.cloud`
- your own custom domain if you have configured one for the app

After publishing the app in Connect Cloud:

1. Open App Settings > URL.
2. Configure a top-level app URL. This can be a claimed Posit URL or your own custom domain.
3. Use that top-level app URL as `OAUTH_REDIRECT_URI`.
4. Register that same top-level URL as the callback URL in your GitHub OAuth app.
5. Open the app via that top-level URL when testing login.

The important part is that the OAuth flow must run with the app at top level, not embedded inside another web page.

## Required environment variables

- `GITHUB_OAUTH_CLIENT_ID`
- `GITHUB_OAUTH_CLIENT_SECRET`
- `OAUTH_REDIRECT_URI`

`OAUTH_REDIRECT_URI` must exactly match the callback URL configured in your GitHub OAuth app.

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

## Deployment notes

- Keep `manifest.json` in this directory with the app file you plan to publish; Posit documents that the manifest can live alongside the primary application file.
- In Connect Cloud, publish the repository as a Shiny app and choose either `integration/posit/app.R` or `integration/posit/app-auto-redirect.R` as the primary file.
- Use a top-level app URL as `OAUTH_REDIRECT_URI` and in the GitHub OAuth callback configuration. This can be a claimed Posit URL or your own custom domain.
- Configure the required environment variables in the Connect Cloud UI before testing login.

## Relevant docs

- Posit Connect Cloud Shiny deployment guide: <https://docs.posit.co/connect-cloud/how-to/r/shiny-r.html>
- Posit Connect Cloud dependency and manifest guide: <https://docs.posit.co/connect-cloud/how-to/r/dependencies.html>
- `rsconnect::writeManifest()` reference: <https://rstudio.github.io/rsconnect/reference/writeManifest.html>
- `rsconnect::appDependencies()` reference: <https://rstudio.github.io/rsconnect/reference/appDependencies.html>