# Cloud Run compatible Shiny container for shinyOAuth demo
# - Single process, listens on $PORT, binds 0.0.0.0
# - Installs this repo (shinyOAuth) from the local source copied into the image

FROM rocker/r-ver:4.5.1

# System dependencies for common R packages used by shinyOAuth
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libicu-dev \
    git \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Configure R to use Posit Package Manager (PPM) binaries for this distro
# - Sets HTTPUserAgent so PPM can serve the correct binaries
# - Sets CRAN repo to the appropriate PPM endpoint based on /etc/os-release
RUN set -eux; \
  DISTRO_ID=$(awk -F= '/^ID=/{gsub("\"","",$2);print $2}' /etc/os-release); \
  DISTRO_CODENAME=$(awk -F= '/^VERSION_CODENAME=/{gsub("\"","",$2);print $2}' /etc/os-release); \
  if [ "$DISTRO_ID" = "debian" ]; then \
    PPM_PATH="debian/${DISTRO_CODENAME}"; \
  elif [ "$DISTRO_ID" = "ubuntu" ]; then \
    PPM_PATH="${DISTRO_CODENAME}"; \
  else \
    # Fallback to codename-only; adjust here if you target other distros
    PPM_PATH="${DISTRO_CODENAME}"; \
  fi; \
  RPROFILE_SITE=$(R RHOME)/etc/Rprofile.site; \
  echo 'options(HTTPUserAgent = sprintf("R/%s R (%s)", getRversion(), paste(getRversion(), R.version["platform"], R.version["arch"], R.version["os"])))' >> "$RPROFILE_SITE"; \
  echo "options(repos = c(CRAN = 'https://packagemanager.posit.co/cran/__linux__/${PPM_PATH}/latest'))" >> "$RPROFILE_SITE"

# Install base R packages needed to run the app and install this package
# Uses the configured PPM binary repo
RUN R -e "install.packages(c('shiny','remotes'))"

# Copy the repository and install shinyOAuth from source
WORKDIR /opt/shinyOAuth
COPY . /opt/shinyOAuth
RUN R -e "remotes::install_local('/opt/shinyOAuth', dependencies=TRUE, upgrade='never')"

# Copy the minimal Cloud Run app
WORKDIR /srv/app
COPY integration/gcp/app.R /srv/app/app.R

# For local dev convenience; Cloud Run sets PORT at runtime
ENV PORT=8080

# Expose is informational for local runs; Cloud Run does not rely on it
EXPOSE 8080

# Run the Shiny app, binding to 0.0.0.0 and honoring $PORT
CMD ["R", "-e", "shiny::runApp('/srv/app', host='0.0.0.0', port=as.integer(Sys.getenv('PORT', '8080')))" ]