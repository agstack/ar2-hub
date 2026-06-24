import json
import asyncio
import httpx
import geopandas as gpd
from shapely.geometry import Point, shape
from shapely.wkt import loads as load_wkt
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import StreamingResponse
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Asset Registry Hub Gateway")


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

if "Common" not in REGISTRY_SERVERS:
    print("WARNING: 'Common' fallback server not found in REGISTRY_SERVERS. Routing failures may occur.")

COUNTRY_ALIASES = {
    "United States": "USA",
    "United States of America": "USA",
    "Republic of India": "India"
}

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
            if geom.geom_type == 'Point':
                return [geom.x, geom.y]
            else:
                return [geom.exterior.coords[0][0], geom.exterior.coords[0][1]]
                
        elif payload.get("type") == "FeatureCollection" and payload.get("features"):
            first_feature = payload["features"][0]
            geom = shape(first_feature["geometry"])
            if geom.geom_type == 'Point':
                return [geom.x, geom.y]
            else:
                return [geom.exterior.coords[0][0], geom.exterior.coords[0][1]]
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
    
    for result in results:
        if result:
            return result
    return None

@app.api_route("/{endpoint_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def route_to_regional_registry(endpoint_path: str, request: Request):
    target_server_url = None
    routing_strategy = "Unknown"
    resolved_country = "Unknown"
    
    body_bytes = await request.body()
    
    if request.method in ["POST", "PUT"] and body_bytes:
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

    print(f"\n{'='*55}")
    print(f"INCOMING REQUEST: {request.method} /{endpoint_path}")
    print(f"STRATEGY:         {routing_strategy}")
    print(f"TARGET REGION:    {resolved_country}")
    print(f"TARGET SERVER:    {target_server_url}")
    print(f"{'='*55}\n")

    target_url = f"{target_server_url}/{endpoint_path}"
    query_params = request.url.query.encode("utf-8")
    if query_params:
        target_url = f"{target_url}?{query_params.decode('utf-8')}"
        
    async with httpx.AsyncClient() as client:
        try:
            headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
            
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