# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import json
import asyncio
import httpx
import secrets
import bcrypt
import jwt
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.backends import default_backend

import geopandas as gpd
from shapely.geometry import Point, shape
from shapely.wkt import loads as load_wkt
from dotenv import load_dotenv

from fastapi import FastAPI, Request, HTTPException, status, Depends, BackgroundTasks
from fastapi import FastAPI, Request, HTTPException, status, Depends, BackgroundTasks, Response
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from user_database import get_user_db, engine, Base
from user_models import User, SigningKey, SystemKey
from user_schemas import UserCreate, UserResponse, UserRegistrationResponse, SigningKeyCreate, SigningKeyResponse

load_dotenv()

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

def get_or_create_rsa_key(db_session):
    system_key = db_session.query(SystemKey).filter(SystemKey.is_active == True).first()
    if not system_key:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        system_key = SystemKey(public_key=pub_pem, private_key=priv_pem)
        db_session.add(system_key)
        db_session.commit()
        db_session.refresh(system_key)
    return system_key

def int_to_base64(num: int) -> str:
    val = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(val).decode('utf-8').rstrip('=')


SERVER_BASE_URL = os.getenv("SERVER_BASE_URL")

WORLD_SHP_FILE = os.getenv("WORLD_SHP_FILE")
if not WORLD_SHP_FILE:
    raise RuntimeError("CRITICAL ERROR: WORLD_SHP_FILE is not set in the .env file.")

servers_json = os.getenv("REGISTRY_SERVERS")
if not servers_json:
    raise RuntimeError("CRITICAL ERROR: REGISTRY_SERVERS is not set in the .env file.")

try:
    REGISTRY_SERVERS = json.loads(servers_json)
except json.JSONDecodeError:
    raise RuntimeError("CRITICAL ERROR: REGISTRY_SERVERS in .env is not a valid JSON string.")

COUNTRY_ALIASES = {
    "United States": "USA",
    "United States of America": "USA",
    "Republic of India": "India"
}

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Asset Registry Hub Gateway")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_user_db)):
    try:
        system_key = get_or_create_rsa_key(db)
        payload = jwt.decode(token, system_key.public_key, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")

        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired. Please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


@app.get("/.well-known/jwks.json", tags=["Authentication"])
def get_jwks(db: Session = Depends(get_user_db)):
    system_key = get_or_create_rsa_key(db)
    jwks = {"keys": []}
    try:
        public_key_obj = serialization.load_pem_public_key(system_key.public_key.encode('utf-8'), backend=default_backend())
        if isinstance(public_key_obj, rsa.RSAPublicKey):
            numbers = public_key_obj.public_numbers()
            jwks["keys"].append({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "hub-key-1",
                "n": int_to_base64(numbers.n),
                "e": int_to_base64(numbers.e)
            })
    except Exception as e:
        pass
    return jwks

@app.post("/auth/signing-key", response_model=SigningKeyResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
def register_signing_key(payload: SigningKeyCreate, current_user: str = Depends(get_current_user), db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.email == current_user).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    try:
        if payload.public_key.startswith("-----BEGIN"):
            public_key_obj = serialization.load_pem_public_key(
                payload.public_key.encode('utf-8'),
                backend=default_backend()
            )
        elif payload.public_key.startswith("ssh-ed25519"):
            public_key_obj = serialization.load_ssh_public_key(
                payload.public_key.encode('utf-8'),
                backend=default_backend()
            )
        else:
            try:
                key_bytes = bytes.fromhex(payload.public_key)
            except ValueError:
                import base64
                padded = payload.public_key + '=' * (-len(payload.public_key) % 4)
                key_bytes = base64.urlsafe_b64decode(padded)
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            
        if not isinstance(public_key_obj, ed25519.Ed25519PublicKey):
            raise ValueError("Not Ed25519")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Ed25519 public key format")

    db.query(SigningKey).filter(SigningKey.user_id == user.id, SigningKey.status == "active").update({"status": "rotated"})

    new_key = SigningKey(
        user_id=user.id,
        public_key=payload.public_key,
        status="active"
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    return new_key

@app.post("/users/register", response_model=UserRegistrationResponse, status_code=status.HTTP_201_CREATED, tags=["User Management"])
def register_user(payload: UserCreate, db: Session = Depends(get_user_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.phone == payload.phone).first():
        raise HTTPException(status_code=400, detail="Phone number already registered")

    new_client_id = f"client_{secrets.token_hex(12)}"
    new_client_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(new_client_secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    new_user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        phone=payload.phone,
        password_hash=payload.get_hashed_password(),
        role=payload.role,
        country=payload.country,
        is_active=True,
        client_id=new_client_id,
        client_secret_hash=hashed_secret
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    response_data = UserResponse.model_validate(new_user).model_dump()
    response_data["client_id"] = new_client_id
    response_data["client_secret"] = new_client_secret
    
    return UserRegistrationResponse(**response_data)

def generate_jwt(email: str, private_key: str, role: str = "farmer") -> dict:
    from datetime import timezone
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    claims = {"sub": email, "type": "access", "exp": expire}
    if role == "authority":
        claims["capabilities"] = ["trace-forward"]
    token = jwt.encode(claims, private_key, algorithm=ALGORITHM, headers={"kid": "hub-key-1"})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/users/login", tags=["Authentication"])
def frontend_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not bcrypt.checkpw(form_data.password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active.")
        
    system_key = get_or_create_rsa_key(db)
    return generate_jwt(user.email, system_key.private_key, role=user.role)


class ApiKeyRequest(BaseModel):
    email: EmailStr

@app.post("/users/request-api-keys", tags=["User Management"])
def request_api_keys(payload: ApiKeyRequest, db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active.")

    new_client_id = f"client_{secrets.token_hex(12)}"
    new_client_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(new_client_secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user.client_id = new_client_id
    user.client_secret_hash = hashed_secret
    db.commit()

    return {
        "client_id": new_client_id,
        "client_secret": new_client_secret
    }

class ClientCredentialPayload(BaseModel):
    client_id: str
    client_secret: str

@app.post("/users/token", tags=["Authentication"])
def programmatic_token(payload: ClientCredentialPayload, db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.client_id == payload.client_id).first()
    
    if not user or not user.client_secret_hash:
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    if not bcrypt.checkpw(payload.client_secret.encode('utf-8'), user.client_secret_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid client credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")
        
    system_key = get_or_create_rsa_key(db)
    return generate_jwt(user.email, system_key.private_key, role=user.role)




def get_country_from_point(coords: list) -> str:
    try:
        p = Point(coords)
        wrs_gdf = gpd.read_file(WORLD_SHP_FILE)
        wrs_gdf = wrs_gdf.to_crs(4326)
        match = wrs_gdf[wrs_gdf.contains(p)]
        if not match.empty:
            return match.reset_index(drop=True).CNTRY_NAME.iloc[0]
        return ""
    except Exception as e:
        print(f"Hub Routing Error: Country detection failed: {e}")
        return ""

def extract_coords_from_payload(payload: dict) -> list:
    try:
        if "latitude" in payload and "longitude" in payload:
            return [float(payload["longitude"]), float(payload["latitude"])]
        if "wkt" in payload:
            geom = load_wkt(payload["wkt"])
            return [geom.x, geom.y] if geom.geom_type == 'Point' else [geom.exterior.coords[0][0], geom.exterior.coords[0][1]]
        elif payload.get("type") == "FeatureCollection" and payload.get("features"):
            first_feature = payload["features"][0]
            geom = shape(first_feature["geometry"])
            return [geom.x, geom.y] if geom.geom_type == 'Point' else [geom.exterior.coords[0][0], geom.exterior.coords[0][1]]
    except Exception:
        pass
    return None

async def find_server_for_geoid(geo_id: str) -> str:
    async def check_server(server_url: str):
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(f"{server_url}/fetch-field-wkt/{geo_id}", timeout=6)
                if resp.status_code == 200:
                    return server_url
            except httpx.RequestError:
                pass
        return None

    tasks = [check_server(url) for url in REGISTRY_SERVERS.values()]
    results = await asyncio.gather(*tasks)
    return next((r for r in results if r), None)


class OverlapRequest(BaseModel):
    geo_id_field_1: str
    geo_id_field_2: str


@app.post("/get-percentage-overlap-two-fields", tags=["Spatial Orchestration"])
async def calculate_cross_region_overlap(payload: OverlapRequest, request: Request, current_user: str = Depends(get_current_user)):
    
    server_1 = await find_server_for_geoid(payload.geo_id_field_1)
    server_2 = await find_server_for_geoid(payload.geo_id_field_2)

    if not server_1:
        raise HTTPException(status_code=404, detail=f"Geo ID 1 ({payload.geo_id_field_1}) not found.")
    if not server_2:
        raise HTTPException(status_code=404, detail=f"Geo ID 2 ({payload.geo_id_field_2}) not found.")

    print(f"\n[ORCHESTRATOR] Field 1: {server_1} | Field 2: {server_2}")

    if server_1 == server_2:
        print("[ORCHESTRATOR] Action: Proxying directly to regional database for high-precision PostGIS math.")
        
        forward_body = json.dumps({
            "geo_id_field_1": payload.geo_id_field_1,
            "geo_id_field_2": payload.geo_id_field_2
        }).encode('utf-8')
        
        target_url = f"{server_1}/get-percentage-overlap-two-fields"
        
        async with httpx.AsyncClient() as client:
            headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "authorization")}
            headers["content-type"] = "application/json"
            headers["content-length"] = str(len(forward_body))
            
            proxy_req = client.build_request("POST", target_url, headers=headers, content=forward_body)
            proxy_resp = await client.send(proxy_req)
            
            headers_to_return = dict(proxy_resp.headers)
            headers_to_return.pop("content-encoding", None)
            headers_to_return.pop("content-length", None)
            
            return Response(
                content=proxy_resp.content,
                status_code=proxy_resp.status_code,
                headers=headers_to_return
            )

    print("[ORCHESTRATOR] Action: Fetching WKTs and calculating cross-border overlap using Shapely.")
    async with httpx.AsyncClient() as client:
        try:
            resp_1 = await client.get(f"{server_1}/fetch-field-wkt/{payload.geo_id_field_1}", timeout=6)
            resp_2 = await client.get(f"{server_2}/fetch-field-wkt/{payload.geo_id_field_2}", timeout=6)
        except httpx.RequestError:
            raise HTTPException(status_code=502, detail="Failed to communicate with regional servers.")

    if resp_1.status_code != 200 or resp_2.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to retrieve geometry data.")

    data_1 = resp_1.json()
    data_2 = resp_2.json()
    
    wkt_1 = data_1.get("WKT") or data_1.get("wkt")
    wkt_2 = data_2.get("WKT") or data_2.get("wkt")

    if not wkt_1 or not wkt_2:
        raise HTTPException(status_code=500, detail="Regional servers did not return valid WKT geometries.")

    try:
        geom1 = load_wkt(wkt_1).buffer(0)
        geom2 = load_wkt(wkt_2).buffer(0)

        intersection_area = geom1.intersection(geom2).area
        
        if geom1.area == 0:
            percentage_overlap = 0.0
        else:
            percentage_overlap = (intersection_area / geom1.area) * 100

        return {"Percentage Overlap": f"{round(percentage_overlap, 4)} %"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Geometry Processing Error: {str(e)}")


@app.api_route("/{endpoint_path:path}", methods=["GET", "POST", "PUT", "DELETE"], tags=["Gateway Routing"])
async def route_to_regional_registry(endpoint_path: str, request: Request, db: Session = Depends(get_user_db)):
    auth_header = request.headers.get("Authorization")
    if request.method == "GET":
        current_user = "anonymous"          # public L0 reads
        if auth_header and auth_header.startswith("Bearer "):
            try:
                current_user = get_current_user(auth_header.split(" ")[1], db)
            except Exception:
                pass
    else:
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        token = auth_header.split(" ")[1]
        current_user = get_current_user(token, db)
    target_server_url = None
    routing_strategy = "Unknown"
    resolved_country = "Unknown"
    
    body_bytes = await request.body()

    explicit_region = request.query_params.get("target_region") or request.headers.get("x-target-region")
    
    if explicit_region:
        country = COUNTRY_ALIASES.get(explicit_region, explicit_region)
        if country in REGISTRY_SERVERS:
            target_server_url = REGISTRY_SERVERS[country]
            resolved_country = country
            routing_strategy = "Explicit Server Override"
        else:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid target region '{explicit_region}'. Valid options: {list(REGISTRY_SERVERS.keys())}"
            )
    

    if not target_server_url and request.method in ["POST", "PUT"] and body_bytes:
        try:
            payload = json.loads(body_bytes.decode('utf-8'))
            if "wkt" in payload or payload.get("type") == "FeatureCollection" or ("latitude" in payload and "longitude" in payload):
                coords = extract_coords_from_payload(payload)
                if coords:
                    raw_country = get_country_from_point(coords)
                    country = COUNTRY_ALIASES.get(raw_country, raw_country)
                    if country in REGISTRY_SERVERS and country != "Common":
                        target_server_url = REGISTRY_SERVERS[country]
                        resolved_country = country
                        routing_strategy = "Geometry Extraction"
                    else:
                        target_server_url = REGISTRY_SERVERS["Common"]
                        resolved_country = f"Common (Original: {raw_country})"
                        routing_strategy = "Geometry Extraction -> Fallback"
        except json.JSONDecodeError:
            pass

    if not target_server_url:
        geo_id = None
        path_parts = endpoint_path.split("/")
        for part in path_parts:
            if len(part) >= 16:
                geo_id = part
                break
        if not geo_id and request.method in ["POST", "PUT"] and body_bytes:
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
                geo_id = payload.get("geo_id") or payload.get("geo_id_field_1") or payload.get("seed_geoid")
            except:
                pass
        if geo_id:
            target_server_url = await find_server_for_geoid(geo_id)
            if target_server_url:
                routing_strategy = "Fan-out GeoID Search"
                for name, url in REGISTRY_SERVERS.items():
                    if url == target_server_url:
                        resolved_country = name

    if not target_server_url:
        target_server_url = REGISTRY_SERVERS["Common"]
        resolved_country = "Common"
        routing_strategy = "Ultimate Fallback (No Match Found)"

    print(f"\n{'='*55}\nAUTHED USER:      {current_user}\nINCOMING REQUEST: {request.method} /{endpoint_path}\nSTRATEGY:         {routing_strategy}\nTARGET REGION:    {resolved_country}\nTARGET SERVER:    {target_server_url}\n{'='*55}\n")

    target_url = f"{target_server_url}/{endpoint_path}"
    query_params = request.url.query.encode("utf-8")
    if query_params:
        target_url = f"{target_url}?{query_params.decode('utf-8')}"
        
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host",)}
            
            proxy_req = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body_bytes
            )
            proxy_resp = await client.send(proxy_req)
            
            headers_to_return = dict(proxy_resp.headers)
            headers_to_return.pop("content-encoding", None)
            headers_to_return.pop("content-length", None)
            
            return Response(
                content=proxy_resp.content,
                status_code=proxy_resp.status_code,
                headers=headers_to_return
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, 
                detail=f"Error communicating with target registry server: {str(exc)}"
            )