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

# Install R packages needed to run the app and install this package
RUN R -e "options(repos='https://cloud.r-project.org'); install.packages(c('shiny','remotes'))"

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