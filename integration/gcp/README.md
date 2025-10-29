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

### Build and deploy to Cloud Run

You may setup a Google Cloud Run service that builds from this repository.

Important: ensure the Docker build context is the repository root (.) while the Dockerfile path is integration/gcp/Dockerfile. If the build context is set to integration/gcp, the image will not contain the package sources (DESCRIPTION will be missing) and installation will fail.

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

Run the image (create gcp/integration/.env based on gcp/integration/.env.example):

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
- If you use a Dockerfile trigger instead of the provided `cloudbuild.yaml`, double‑check the build context is the repo root (`.`) and the Dockerfile path is `integration/gcp/Dockerfile`.
