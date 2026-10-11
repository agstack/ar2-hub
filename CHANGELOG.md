# Changelog

## [Unreleased]

### Changed
- **Capabilities come from the operator, not the user**: the `trace-forward` capability was written into a token whenever the user's self-declared `role` was `"authority"`. It is now granted only to accounts listed in `HUB_AUTHORITY_ACCOUNTS`; `role` is descriptive and is no longer an authorisation input. (`capabilities.py`, `hub_main.generate_jwt`)

### Added
- First test suite (`tests/`) and a CI workflow running it. The role test fails against the previous code.

## [v0.9-review]

### Added
- **Hub Gateway Routing**: Separated the identity and authorization layers by introducing the Gateway proxy for handling User registration, JWT minting, and dynamic request routing to upstream Nodes.
- **Role-Based Users**: Added `role` and `country` metadata to the User registration schema and DB model to support farmer/buyer segregation and jurisdictional routing.
- **Credential Passthrough**: The Hub natively parses and forwards the `X-Field-Grant` SD-JWT headers untouched to the backend nodes, adhering to the "route but never authorize" design principle.
- **SQLite Fallback Removed**: Repositories now default to local PostgreSQL.
- **Documentation Overhaul**: Updated the architecture documentation, zero-to-hero manual testing guides, and environment references.
