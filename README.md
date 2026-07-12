# Asset Registry Hub (ar2-hub) - v0.9-review

The Asset Registry Hub (`ar2-hub`) acts as the **Identity Anchor and Gateway Router** in the AgStack Digital Public Infrastructure (DPI) architecture. 

It handles user onboarding, issues Hub access tokens, and proxies data requests to underlying Asset Registry Nodes (`ar2`). It strictly adheres to two fundamental design rules:
1. **The Hub routes but never authorizes**: The Hub verifies basic user identity and emits JWKS, but the underlying Node is the ultimate authority that verifies the cryptographic Field Grants (L1 access).
2. **L1 requires a grant credential**: High-resolution spatial data is never exposed without a valid ODRL JWT credential. 

## Quickstart (10 Minutes to Run)

Follow these steps to run the Hub Gateway locally alongside an `ar2` Node and the `Pancake` issuer.

1. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv ar2-hub-env
   source ar2-hub-env/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Copy the example environment file and update variables if necessary.
   ```bash
   cp .env.example .env
   ```

4. **Run the Uvicorn Server**:
   ```bash
   uvicorn hub_main:app --host 0.0.0.0 --port 8000 --reload
   ```

*(Note: The `ar2` Node should be run on a separate internal port, e.g., 8001, and defined in your `REGISTRY_SERVERS` config).*

## Environment Variables Reference

| Variable | Description | Default | Demo-Only? |
|----------|-------------|---------|------------|
| `DATABASE_URL` | PostgreSQL connection string. Defaults to local postgres if omitted. | `postgresql://postgres:postgres@localhost:5432/postgres` | No |
| `SERVER_BASE_URL` | Base URL of the Gateway instance. | `http://127.0.0.1:8000` | No |
| `REGISTRY_SERVERS` | JSON string defining backend Nodes and their capabilities (country routing). | `[{"url": "http://127.0.0.1:8001", "countries": ["USA", "India"]}]` | No |
| `WORLD_SHP_FILE` | Path to the `.shp` file used for point-in-polygon country resolution before routing. | *None* | No |

## Endpoints Overview

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/users/register` | Registers a new Hub user (Farmer, Buyer, etc.). | No |
| `POST` | `/users/login` | Returns a JWT Access Token for the user. | No |
| `POST` | `/{path:path}` | Proxies write operations (like `/register-field-boundary`) to the Node. | Yes (JWT) |
| `GET`  | `/{path:path}` | Proxies read operations (like `/fetch-field-wkt/{geoid}`) to the Node. | No |

## Testing

A comprehensive API guide for interacting with the Hub Gateway is provided in [test_curls.txt](./test_curls.txt). 
For the complete 2-Persona flow involving the Hub, Node, and Pancake, refer to the E2E scripts provided in the main `ar2` repository.
