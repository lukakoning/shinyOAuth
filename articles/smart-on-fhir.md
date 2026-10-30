# Use SMART on FHIR from Shiny

## FHIR and SMART on FHIR

FHIR describes healthcare data and how apps exchange it. A `Patient`
resource describes a patient; an `Observation` can describe a
measurement. A FHIR API is the service your app calls to read or search
those records.

SMART on FHIR defines how an app requests permission to use that API and
receives context such as the selected patient. It also tells the app
where users sign in. A person can open the app directly, or an
electronic health record (EHR) can launch it with a chart already
selected.

Use this guide to connect a hospital and read a patient’s record. Start
with the standalone example, then add searches, user identity or EHR
launch as needed. For the underlying standards, see the [FHIR
overview](https://hl7.org/fhir/R4/overview.html) and [SMART App
Launch](https://hl7.org/fhir/smart-app-launch/STU2.2/app-launch.html).

## Before running the example

Register the app with the server you intend to use. Obtain its FHIR base
URL, client ID, authentication method and permitted scopes. Scopes are
permission names: this example needs permission to read the selected
Patient and optionally search Observations. It uses a shared secret kept
on the Shiny server.

The `.example` addresses below are placeholders. Replace them with
approved server addresses and register
`http://127.0.0.1:8100/callback/fhir` for local development if the
provider permits it. Set `SMART_CLIENT_ID` and `SMART_CLIENT_SECRET` in
your R environment.

For deployment, register matching HTTPS URLs and remove both
`allow_http_loopback` exceptions. On Posit Connect or Connect Cloud,
test at the [direct app
URL](https://lukakoning.github.io/shinyOAuth/articles/usage.html#posit-connect-and-connect-cloud).
Copy the next three code blocks into `app.R`, in order.

### 1. Discover the server and configure the client

Discovery reads the server’s published login settings. Configure it at
startup with a reviewed FHIR base and approved endpoint hosts, so
visitors cannot make your app discover arbitrary servers.

``` r

library(shiny)
library(shinyOAuth)

app_origin <- "http://127.0.0.1:8100"
discovery <- smart_discover(
  "https://ehr.example/fhir/R4",
  endpoint_hosts = c("ehr.example", "login.example"),
  allow_http_loopback = TRUE # Enable the registered local HTTP callback for this demo.
)

client <- smart_client(
  discovery,
  client_id = Sys.getenv("SMART_CLIENT_ID"),
  client_secret = Sys.getenv("SMART_CLIENT_SECRET"),
  token_auth_style = "header",
  redirect_uri = paste0(app_origin, "/callback/fhir"),
  launch = "standalone",
  scopes = c("launch/patient", "patient/Patient.r", "patient/Observation.s"),
  required_scopes = "patient/Patient.r",
  label = "My hospital"
)
```

[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md)
connects the login to this FHIR base and prepares the authorization
request. You do not need to copy tokens into FHIR requests.

| Scope                   | Purpose                                      |
|-------------------------|----------------------------------------------|
| `launch/patient`        | Ask the standalone flow to select a patient. |
| `patient/Patient.r`     | Read that patient’s Patient resource.        |
| `patient/Observation.s` | Search Observations for that patient.        |

Here `.r` means read and `.s` means search. `required_scopes` lets the
app keep working if optional Observation access is declined. The server
decides what to grant; receiving a patient ID alone does not grant
permission to read records.

### 2. Configure retained connections

Browser retention keeps the authorization available when the browser
returns from the hospital’s login page.

``` r

manager <- oauth_connections(
  clients = list(hospital = client),
  app_origin = app_origin,
  retention = "browser",
  owner_policy = oauth_browser_owner(allow_http_loopback = TRUE),
  store = oauth_connection_store_memory(),
  # Temporary keys for this local demo, created once at app startup.
  # For deployment, load independent 32-byte raw keys from secret storage.
  keys = list(
    credentials = openssl::rand_bytes(32),
    owner = openssl::rand_bytes(32)
  )
)
```

`hospital` is your app’s name for this configuration. The cookie
identifies saved browser authorizations, not a person. This memory store
keeps encrypted credentials in one R process and loses them on restart.
See [Multiple
authorizations](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.html#keep-authorizations-when-the-browser-returns)
for retention and deployment choices.

### 3. Authorize and fetch the patient

``` r

base_ui <- fluidPage(
  h2("FHIR patient example"),
  actionButton("connect", "Connect hospital"),
  selectInput("connection_id", "Saved authorization", choices = character()),
  actionButton("load_patient", "Load patient"),
  actionButton("disconnect", "Disconnect selected"),
  textOutput("patient"),
  textOutput("auth_error")
)
ui <- oauth_connections_ui(base_ui, "health", manager)

server <- function(input, output, session) {
  health <- oauth_connections_server("health", manager)
  observeEvent(input[["connect"]], health[["connect"]]("hospital"))

  observe({
    rows <- health[["connections"]]()
    ids <- vapply(rows, function(x) x[["connection_id"]], character(1))
    labels <- vapply(seq_along(rows), function(i) {
      paste(rows[[i]][["client_label"]], i, paste0("(", rows[[i]][["status"]], ")"))
    }, character(1))
    selected <- isolate(input[["connection_id"]])
    if (!length(selected) || !selected %in% ids) selected <- head(ids, 1)
    updateSelectInput(session, "connection_id",
      choices = setNames(ids, labels), selected = selected)
  })

  selected_connection <- reactive({
    rows <- health[["connections"]]()
    ids <- vapply(rows, function(x) x[["connection_id"]], character(1))
    req(input[["connection_id"]], input[["connection_id"]] %in% ids)
    connection <- health[["connection"]](input[["connection_id"]])
    req(connection[["is_usable"]]())
    connection
  })

  patient <- eventReactive(input[["load_patient"]], {
    health[["touch"]]()
    connection <- selected_connection()
    context <- smart_context(connection)
    data <- tryCatch({
      response <- smart_patient(connection)
      httr2::resp_check_status(response)
      httr2::resp_body_json(response, simplifyVector = FALSE)
    }, error = function(e) NULL)
    list(connection_id = connection[["id"]], revision = context[["revision"]], data = data)
  })

  output[["patient"]] <- renderText({
    connection <- selected_connection()
    context <- smart_context(connection)
    value <- patient()
    # Clear the display if the selected grant or accepted context has changed.
    req(identical(value[["connection_id"]], connection[["id"]]),
        identical(value[["revision"]], context[["revision"]]))
    validate(need(!is.null(value[["data"]]), "Could not load this patient's record."))
    paste("Patient resource:", value[["data"]][["id"]])
  })
  observeEvent(input[["disconnect"]], {
    # Allow disconnect even when the connection has become unusable.
    req(input[["connection_id"]])
    health[["disconnect"]](input[["connection_id"]])
  })
  output[["auth_error"]] <- renderText({
    if (length(health[["errors"]]())) "Authorization is unavailable. Try authorizing again."
  })
}

runApp(shinyApp(ui, server, uiPattern = ".*"),
  host = "127.0.0.1", port = 8100, launch.browser = FALSE)
```

Open `http://127.0.0.1:8100`, connect the hospital, complete
authorization and load the patient.
[`smart_patient()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
reads the Patient selected by the accepted context, using that
connection’s credentials and FHIR base.

The example displays only the resource ID. A clinical app needs
appropriate patient identification and must respect
`need_patient_banner` when supplied. Keep patient data out of general
logs and connection tables.

The output checks both connection ID and context revision before
displaying data. Keep these checks and discard patient-dependent caches
when either the authorization or accepted patient context changes.

## Search with the same connection

Add `actionButton("search", "Search observations")` to the UI and this
observer inside `server()`. The patient filter selects the records to
search; the server still enforces access and the connection checks the
required permission.

``` r

observeEvent(input[["search"]], {
  health[["touch"]]()
  connection <- selected_connection()
  context <- smart_context(connection)
  req(context[["patient"]])
  tryCatch({
    response <- connection[["request"]](
      "fhir", "Observation",
      query = list(patient = context[["patient"]], `_count` = 10),
      required_scopes = "patient/Observation.s",
      configure = function(req) httr2::req_headers(req, Accept = "application/fhir+json")
    )
    httr2::resp_check_status(response)
    bundle <- httr2::resp_body_json(response, simplifyVector = FALSE)
    # Process bundle[["entry"]] here, associating data with this ID and revision.
    showNotification("Observation search completed.")
  }, error = function(e) {
    showNotification("Could not search observations. Check the granted permissions.",
      type = "error")
  })
})
```

The `Accept` header asks for FHIR JSON. Pagination must stay within the
connection’s approved FHIR base. If you cache results, associate them
with the connection ID and context revision just as in the Patient
example.

See [granular permissions and
refresh](#granular-permissions-and-refresh) for scope syntax and refresh
behavior.

## Patient context and user identity are different

The selected patient may be someone other than the person who signed in,
such as a clinician viewing a patient’s chart.
`smart_context(connection)[["patient"]]` identifies the chart context;
it does not identify the logged-in user.

If your app needs the user’s validated identity, choose
`identity = "openid"` when creating the client. Use
`identity = "fhirUser"` when it also needs that user’s FHIR reference.
These options require the server’s corresponding support. The default,
`identity = "none"`, does not request identity verification.

Read selected identity fields with `connection[["identity"]]()`. For a
FHIR user reference, use
[`smart_context()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
and
[smart_fhir_user()](https://lukakoning.github.io/shinyOAuth/reference/smart_context.html);
it only fetches within the configured FHIR base. Patient context and
browser retention remain separate from verified user identity.

## Start from an EHR instead

An EHR can open your app with its FHIR base (`iss`) and a temporary
`launch` handle. The app must complete authorization before trusting the
returned context. This supports a workflow where the user starts from
the chart rather than choosing a hospital in your app.

Replace the standalone client with the EHR registration:

``` r

client <- smart_client(
  discovery,
  client_id = Sys.getenv("SMART_EHR_CLIENT_ID"),
  client_secret = Sys.getenv("SMART_EHR_CLIENT_SECRET"),
  token_auth_style = "header",
  redirect_uri = paste0(app_origin, "/callback/fhir"),
  launch = "ehr",
  scopes = c("patient/Patient.r", "patient/Observation.s"),
  required_scopes = "patient/Patient.r",
  label = "My hospital"
)
```

Recreate the manager with that client, then replace the UI wrapper:

``` r

ui <- oauth_connections_ui(base_ui, "health", manager,
  launch_routes = list(smart_launch_route("/smart/launch", "hospital")))
```

Register `http://127.0.0.1:8100/smart/launch` as the local launch URL in
addition to the callback. Use corresponding HTTPS URLs in deployment.
Remove the Connect button and observer; opening the app from the EHR now
starts login. Keep the other server code and `uiPattern = ".*"`.

Use a full browser tab, browser retention with a Lax owner cookie, and
one R process. Embedded iframe launch is unsupported. Reconnect by
launching from the EHR again, and keep launch handles out of logs. The
route accepts only configured FHIR servers, rather than discovering a
server from an incoming URL.

For route limits and proxy requirements, see
[smart_launch_route()](https://lukakoning.github.io/shinyOAuth/reference/smart_launch_route.html).

## More than one hospital

Create a reviewed discovery result and client for each registration,
then pass `list(hospital_a = client_a, hospital_b = client_b)` to the
manager. Use the distinct callbacks and complete callback vector shown
in [Multiple
authorizations](https://lukakoning.github.io/shinyOAuth/articles/multiple-authorizations.html#configure-clients-outside-server).

Each connection has its own FHIR base, credentials and context. Patient
IDs from different hospitals are not interchangeable. Use separate
clients if you need both standalone and EHR-launch entry for the same
server.

## Other registration and refresh options

Choose authentication to match the server registration:

| Registration | [`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md) settings |
|----|----|
| Public | `token_auth_style = "public"`; omit the secret and assertion key. |
| Confidential, shared secret | `token_auth_style = "header"` and `client_secret`. |
| Confidential, asymmetric | `token_auth_style = "private_key_jwt"`, private key, key ID, and supported `RS384` or `ES384`. |

For an asymmetric standalone registration, replace the original client
with this configuration. Register the matching public key and key ID
with the server first; keep the private key on the application server.

``` r

client <- smart_client(
  discovery,
  client_id = Sys.getenv("SMART_ASYMMETRIC_CLIENT_ID"),
  redirect_uri = paste0(app_origin, "/callback/fhir"),
  launch = "standalone",
  scopes = c("launch/patient", "patient/Patient.r"),
  required_scopes = "patient/Patient.r",
  token_auth_style = "private_key_jwt",
  client_assertion_private_key = openssl::read_key(Sys.getenv("SMART_PRIVATE_KEY_FILE")),
  client_assertion_private_key_kid = Sys.getenv("SMART_KEY_ID"),
  client_assertion_alg = "RS384",
  label = "My hospital"
)
```

The server must advertise the chosen method and algorithm. The package
creates and signs the assertion; app code does not assemble JWTs. See
[SMART asymmetric client
authentication](https://hl7.org/fhir/smart-app-launch/STU2.2/client-confidential-asymmetric.html).

Request `offline_access` only when your registration and server allow
it. Browser retention alone does not request a refresh token; if one is
issued, the manager can refresh access.

SMART refresh responses need a positive `expires_in`. If the initial
response omits it, set `initial_expires_in_fallback` only to a lifetime
supplied by the server out of band. The default `NULL` requires an
explicit lifetime; generic OAuth lifetime options do not apply.

`connection[["refresh"]](scopes = ...)` can reduce locally accepted
permissions. Broader access requires new authorization. After refresh,
read
[`smart_context()`](https://lukakoning.github.io/shinyOAuth/reference/smart_context.md)
again and invalidate patient data when its revision changes. This tracks
accepted authorization context, not live changes in the EHR’s open
chart.

Outgoing `authorization_method = "POST"` requires advertised
`authorize-post` support. It is separate from the returning callback’s
`response_mode`.
[`smart_client()`](https://lukakoning.github.io/shinyOAuth/reference/smart_client.md)
does not expose JAR, PAR, JARM, DPoP or mTLS composition.

### Granular permissions and refresh

Granular scopes can restrict simple search parameters such as `_id`,
`_lastUpdated`, `_tag`, `_profile` and `_security`. Constraints match
literally; modifiers, chaining and experimental `_filter` expressions
are unsupported.

Refresh can retain or narrow the grant. After a reduction, shinyOAuth
keeps and sends the latest accepted limit, even if the refresh token did
not rotate. An empty grant cannot gain permissions again without a new
authorization.
