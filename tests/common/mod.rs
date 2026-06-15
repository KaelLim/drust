// Shared test fixtures: each test binary pulls in `common` but uses only a
// subset of the helpers, so per-binary dead_code is expected. The attribute on
// the `mod` declaration propagates the allow into the whole submodule.
#[allow(dead_code)]
pub mod mock_garage_admin;
#[allow(dead_code)]
pub mod oauth_helpers;
