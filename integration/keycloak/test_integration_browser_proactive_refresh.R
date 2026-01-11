# Integration test: Proactive refresh with short-lived tokens
#
# This test uses a CONFIDENTIAL client with 5-second access tokens.
# It proves that proactive refresh works by:
#   1. Logging in and capturing the initial token expiry time
#   2. Waiting longer than the token lifespan
#   3. Verifying the session is still authenticated
#   4. Verifying the token's expires_at has INCREASED (proving refresh occurred)

