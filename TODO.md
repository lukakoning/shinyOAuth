* [High] vignettes/example-spotify.Rmd:38 and vignettes/usage.Rmd:35 load Shiny and call live OAuth providers without eval = FALSE; CRAN will execute these chunks during vignette builds and they will fail (or reach the network), so guard them behind eval = FALSE or environment checks.

* Add references to OAuth 2.0/OIDC documentation (protocol specification)

* Update release version prior to submitting