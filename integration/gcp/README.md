# shinyOAuth on Google Cloud Run (GitHub OAuth)

This folder contains a minimal Shiny app and Dockerfile to run `shinyOAuth` on Google Cloud Run, configured against a GitHub OAuth app.

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

### Option 1: build and deploy to Cloud Run

You may setup a Google Cloud run app based on the Dockerfile, building from a GitHub repository with this Dockerfile.

### Option 2: build & run locally

Build the image:

```bash
# From repo root
docker build -t shinyoauth-demo:latest -f integration/gcp/Dockerfile .
```

Run the image (create gcp/integration/.env based on gcp/integration/.env.example):

```bash
# Run from the repo root
docker run --rm --name shinyoauth-demo \
  -p 127.0.0.1:8100:8100 \
  --env-file integration/gcp/.env \
  -e PORT=8100 \
  shinyoauth-demo:latest
```
