# Changelog

## [v0.9-review]

### Added
- **Hub Gateway Routing**: Separated the identity and authorization layers by introducing the Gateway proxy for handling User registration, JWT minting, and dynamic request routing to upstream Nodes.
- **Role-Based Users**: Added `role` and `country` metadata to the User registration schema and DB model to support farmer/buyer segregation and jurisdictional routing.
- **Credential Passthrough**: The Hub natively parses and forwards the `X-Field-Grant` SD-JWT headers untouched to the backend nodes, adhering to the "route but never authorize" design principle.
- **SQLite Fallback**: Repositories now gracefully degrade to local SQLite `.db` files if PostgreSQL is unavailable.
- **Documentation Overhaul**: Updated the architecture documentation, zero-to-hero manual testing guides, and environment references.
