# Regression checks for the two local simulator corrections. These run alongside
# upstream specs; no upstream client-conformance assertion is replaced.
RSpec.describe 'shinyOAuth Inferno simulator compatibility', :request, :runnable do
  let(:suite_id) { 'smart_client_stu2_2' }
  let(:test_session) do
    repo_create(:test_session, suite: suite_id, suite_options: [
      Inferno::DSL::SuiteOption.new(id: :client_type,
        value: SMARTAppLaunch::SMARTClientOptions::SMART_APP_LAUNCH_PUBLIC)
    ])
  end

  it 'publishes its OIDC capability and the same signing-key URL as OIDC discovery' do
    smart = JSON.parse(SMARTAppLaunch::MockSMARTServer.smart_server_metadata(suite_id)[2].first)
    oidc = JSON.parse(SMARTAppLaunch::MockSMARTServer.openid_connect_metadata(suite_id)[2].first)
    expect(smart['capabilities']).to include('sso-openid-connect')
    expect(smart['issuer']).to eq(oidc['issuer'])
    expect(smart['jwks_uri']).to eq(oidc['jwks_uri'])
  end

  it 'binds the signed initial ID token to the requested nonce, omitting it on refresh' do
    client_id = 'nonce-regression'
    redirect_uri = 'https://app.example/callback'
    registration = suite.children[2].children[0]
    access = suite.children[4].children[2]
    expect(run(registration, { client_id:, smart_redirect_uris: redirect_uri }).result).to eq('pass')
    expect(run(access, { client_id:, fhir_user_relative_reference: 'Practitioner/clinician' }).result).to eq('wait')

    verifier = 'a' * 64
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    get "/custom/#{suite_id}#{SMARTAppLaunch::AUTHORIZATION_PATH}", {
      client_id:, redirect_uri:, response_type: 'code', state: 'test-state',
      scope: 'openid fhirUser offline_access', nonce: 'requested-nonce',
      code_challenge: challenge, code_challenge_method: 'S256'
    }
    expect(last_response.status).to be_between(300, 399)
    code = Rack::Utils.parse_query(URI(last_response.headers['location']).query)['code']
    post "/custom/#{suite_id}#{SMARTAppLaunch::TOKEN_PATH}", {
      grant_type: 'authorization_code', client_id:, redirect_uri:, code:, code_verifier: verifier
    }
    expect(last_response.status).to eq(200)
    token = JSON.parse(last_response.body)
    jwks = SMARTAppLaunch::OIDCJWKS.jwks
    claims, = JWT.decode(token.fetch('id_token'), nil, true, algorithms: ['RS256'], jwks: jwks.export)
    expect(claims['nonce']).to eq('requested-nonce')
    expect(claims['aud']).to eq(client_id)
    expect(claims['fhirUser']).to end_with('/Practitioner/clinician')

    post "/custom/#{suite_id}#{SMARTAppLaunch::TOKEN_PATH}", {
      grant_type: 'refresh_token', client_id:, refresh_token: token.fetch('refresh_token')
    }
    expect(last_response.status).to eq(200)
    refreshed, = JWT.decode(JSON.parse(last_response.body).fetch('id_token'), nil, true,
                           algorithms: ['RS256'], jwks: jwks.export)
    expect(refreshed).not_to have_key('nonce')
    expect(refreshed['sub']).to eq(claims['sub'])
  end
end
