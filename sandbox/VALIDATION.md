# Sandbox validation

Both Terraform modules validate; the Entra module has 1 passing mock test and AWS has 2. The local Compose configuration was checked for localhost binding, private database networking, OIDC, credential separation and migration ordering.

A connected sandbox subsequently passed 21 live/local checks, including real metadata imports and local restart recovery. See [the sanitized live test summary](../docs/LIVE_TEST_SUMMARY.md) and [current limitations](../docs/IMPLEMENTATION_STATUS.md).

Provider-side revocation, interactive human sign-in, dual agent/user delegation and comprehensive native effective permissions were not verified in that run. This is not production certification. Real IDs, configuration, state, private outputs and credentials are not included in the repository.
