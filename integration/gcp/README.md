# 'shinyOAuth' on Google Cloud Run (GitHub OAuth)

This example deploys a small Shiny app with GitHub login to Google Cloud Run.
You need a GitHub OAuth App registration and a Google Cloud project set up for
Cloud Run. Run the local app first using the
[getting-started guide](../../vignettes/usage.Rmd) if you are new to shinyOAuth.

## 1) Create a GitHub OAuth app

- Go to https://github.com/settings/developers (OAuth Apps) and create a new app.
- Set Authorization callback URL to your Cloud Run service URL (you can update this after deploy):
  - Example: `https://<service>-<hash>-<region>.a.run.app`
- Note the Client ID and Client Secret.

## 2) Build/run

The container runs a plain `shiny::runApp()` listening on `$PORT` and `0.0.0.0`.

Environment variables used by the app:
- `GITHUB_OAUTH_CLIENT_ID`
- `GITHUB_OAUTH_CLIENT_SECRET` 
- `OAUTH_REDIRECT_URI` (must exactly match the URL configured in your GitHub OAuth app (typically your Cloud Run service URL))

### Build and deploy to Cloud Run

Configure the Cloud Run build to use this repository.

Use the repository root (`.`) as the Docker build context and
`integration/gcp/Dockerfile` as the Dockerfile path. This gives the build access
to the package source as well as the example app.

Two ways to do this:

- Use the provided `integration/gcp/cloudbuild.yaml` as the build configuration in your trigger; it runs:
  - docker build -f integration/gcp/Dockerfile .
- Or, if using a Dockerfile trigger, set the Build Context/Root Directory to the repository root (.) and the Dockerfile location to integration/gcp/Dockerfile.

### Build & run locally (to test)

Build the image:

```bash
# From repo root
docker build -t shinyoauth-demo:latest -f integration/gcp/Dockerfile .
```

To test against another reviewed PPM snapshot without editing the Dockerfile,
pass `--build-arg PPM_SNAPSHOT=YYYY-MM-DD`.

Run the image (create integration/gcp/.env based on integration/gcp/.env.example):

```bash
# Run from the repo root
docker run --rm --name shinyoauth-demo \
  -p 127.0.0.1:8100:8100 \
  --env-file integration/gcp/.env \
  -e PORT=8100 \
  shinyoauth-demo:latest
```

Notes:
- A sample environment file is provided at `integration/gcp/.env.example`.
- When deploying to Cloud Run, set these variables in the service configuration UI (Variables & Secrets) and ensure `OAUTH_REDIRECT_URI` matches your Cloud Run service URL exactly.

## Maintaining the image

Its Rocker base image is pinned by digest and its Posit Package Manager
repository defaults to the dated `2026-07-21` snapshot. When updating either
pin, review the resulting dependency changes and update both values
intentionally.


This demo uses in-process login state. If production callbacks can reach a
different process or replica, configure shared state and a shared key as
described in the [deployment guidance](../../vignettes/usage.Rmd).
