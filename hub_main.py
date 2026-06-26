import os
import json
import asyncio
import httpx
import secrets
import smtplib
import bcrypt
import jwt
from datetime import datetime, timedelta
from email.message import EmailMessage

import geopandas as gpd
from shapely.geometry import Point, shape
from shapely.wkt import loads as load_wkt
from dotenv import load_dotenv

from fastapi import FastAPI, Request, HTTPException, status, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from user_database import get_user_db, engine, Base
from user_models import User
from user_schemas import UserCreate, UserResponse

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "my-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

ENABLE_EMAIL = os.getenv("ENABLE_EMAIL", "True").lower() in ("true", "1", "yes")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "agserveralert@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "mdcaibbgocsfwcjc")

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


def send_email(email_to: str, subject: str, content: str):
    if not ENABLE_EMAIL:
        return
    msg = EmailMessage()
    msg.set_content(content)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = email_to
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email to {email_to}: {e}")

def send_verification_email(email_to: str, token: str):
    verification_link = f"{SERVER_BASE_URL}/users/verify?token={token}"
    content = f"Welcome to the Asset Registry!\n\nPlease verify your email address to activate your account by clicking the link below:\n\n{verification_link}\n\nThis link expires in 24 hours."
    send_email(email_to, "Verify Your Account", content)

def send_credentials_email(email_to: str, client_id: str, client_secret: str):
    content = f"Hello,\n\nYour programmatic API credentials have been generated:\n\nClient ID: {client_id}\nClient Secret: {client_secret}\n\nKeep these secure. We only store cryptographic hashes."
    send_email(email_to, "Your API Gateway Credentials", content)


@app.post("/users/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["User Management"])
def register_user(payload: UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_user_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.phone == payload.phone).first():
        raise HTTPException(status_code=400, detail="Phone number already registered")

    new_user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        phone=payload.phone,
        password_hash=payload.get_hashed_password(),
        is_active=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    expire = datetime.utcnow() + timedelta(hours=24)
    verification_token = jwt.encode({"sub": new_user.email, "type": "verification", "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    
    background_tasks.add_task(send_verification_email, payload.email, verification_token)

    return new_user

@app.get("/users/verify", tags=["User Management"])
def verify_email(token: str, background_tasks: BackgroundTasks, db: Session = Depends(get_user_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "verification":
            raise HTTPException(status_code=400, detail="Invalid token type")
            
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_active:
            return {"message": "Account is already active."}
            
        user.is_active = True
        
        new_client_id = f"client_{secrets.token_hex(12)}"
        new_client_secret = secrets.token_urlsafe(32)
        hashed_secret = bcrypt.hashpw(new_client_secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user.client_id = new_client_id
        user.client_secret_hash = hashed_secret
        db.commit()

        background_tasks.add_task(send_credentials_email, user.email, new_client_id, new_client_secret)

        return {
            "message": "Email verified successfully! Your account is now active.",
            "notice": "An email was sent, but here are your keys just in case it goes to spam.",
            "client_id": new_client_id,
            "client_secret": new_client_secret
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Verification link has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid verification link.")

def generate_jwt(email: str) -> dict:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": email, "type": "access", "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/users/login", tags=["Authentication"])
def frontend_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not bcrypt.checkpw(form_data.password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is not active. Please check your email to verify your account.")
        
    return generate_jwt(user.email)


class ApiKeyRequest(BaseModel):
    email: EmailStr

@app.post("/users/request-api-keys", tags=["User Management"])
def request_api_keys(payload: ApiKeyRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_user_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    
    if not user:
        return {"message": "If that email is registered and active, API credentials will be sent to it."}
        
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Please verify your email address before requesting API keys.")

    new_client_id = f"client_{secrets.token_hex(12)}"
    new_client_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(new_client_secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user.client_id = new_client_id
    user.client_secret_hash = hashed_secret
    db.commit()

    background_tasks.add_task(send_credentials_email, user.email, new_client_id, new_client_secret)

    return {"message": "If that email is registered and active, API credentials will be sent to it."}

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
        
    return generate_jwt(user.email)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
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
            proxy_resp = await client.send(proxy_req, stream=True)
            
            return StreamingResponse(
                proxy_resp.aiter_raw(),
                status_code=proxy_resp.status_code,
                headers=proxy_resp.headers
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
async def route_to_regional_registry(endpoint_path: str, request: Request, current_user: str = Depends(get_current_user)):
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
        if len(path_parts) > 1 and len(path_parts[-1]) >= 16: 
            geo_id = path_parts[-1]
        elif request.method in ["POST", "PUT"] and body_bytes:
            try:
                payload = json.loads(body_bytes.decode('utf-8'))
                geo_id = payload.get("geo_id") or payload.get("geo_id_field_1")
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
        
    async with httpx.AsyncClient() as client:
        try:
            headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "authorization")}
            
            proxy_req = client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body_bytes
            )
            proxy_resp = await client.send(proxy_req, stream=True)
            
            return StreamingResponse(
                proxy_resp.aiter_raw(),
                status_code=proxy_resp.status_code,
                headers=proxy_resp.headers
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY, 
                detail=f"Error communicating with target registry server: {str(exc)}"
            )