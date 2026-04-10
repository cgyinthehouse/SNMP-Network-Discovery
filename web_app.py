import json
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.device_discovery import DeviceDiscovery
from core.graph_manager import GraphManager

from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_AUTH_NONE,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CBC168_3DES,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_CFB192_AES_BLUMENTHAL,
    USM_PRIV_CFB256_AES_BLUMENTHAL,
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
TEMPLATES_DIR = FRONTEND_DIR / "templates"
STATIC_DIR = FRONTEND_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "devices.json"

app = FastAPI(title="SNMP Network Topology", version="0.1.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

graph_manager = GraphManager()

auth_protocol_map = {
    "MD5": USM_AUTH_HMAC96_MD5,
    "SHA": USM_AUTH_HMAC96_SHA,
    "SHA1": USM_AUTH_HMAC96_SHA,
    "SHA224": USM_AUTH_HMAC128_SHA224,
    "SHA256": USM_AUTH_HMAC192_SHA256,
    "SHA384": USM_AUTH_HMAC256_SHA384,
    "SHA512": USM_AUTH_HMAC384_SHA512,
    "NONE": USM_AUTH_NONE,
}

priv_protocol_map = {
    "DES": USM_PRIV_CBC56_DES,
    "3DES": USM_PRIV_CBC168_3DES,
    "AES": USM_PRIV_CFB128_AES,
    "AES128": USM_PRIV_CFB128_AES,
    "AES192": USM_PRIV_CFB192_AES,
    "AES256": USM_PRIV_CFB256_AES,
    "AES192BLUMENTHAL": USM_PRIV_CFB192_AES_BLUMENTHAL,
    "AES256BLUMENTHAL": USM_PRIV_CFB256_AES_BLUMENTHAL,
    "NONE": None,
}


def ensure_data_path():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text("[]", encoding="utf-8")


def load_devices() -> List[dict]:
    if not DATA_FILE.exists():
        return []
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def save_devices(devices: List[dict]):
    DATA_FILE.write_text(json.dumps(devices, indent=2), encoding="utf-8")


def add_or_update_device(device: dict) -> List[dict]:
    devices = load_devices()
    device_ip = device.get("ip_address")
    updated = [d for d in devices if d.get("ip_address") != device_ip]
    updated.append(device)
    save_devices(updated)
    return updated


def get_auth_protocol(value: Optional[str]):
    if value is None:
        return None
    protocol = auth_protocol_map.get(value.upper())
    if protocol is None:
        raise HTTPException(status_code=400, detail=f"Invalid auth_proto: {value}")
    return protocol


def get_priv_protocol(value: Optional[str]):
    if value is None:
        return None
    protocol = priv_protocol_map.get(value.upper())
    if protocol is None:
        raise HTTPException(status_code=400, detail=f"Invalid priv_proto: {value}")
    return protocol


class DiscoverRequest(BaseModel):
    ip: str
    version: int = Field(2, ge=1, le=3)
    community: str = "public"
    user: Optional[str] = None
    auth_key: Optional[str] = None
    priv_key: Optional[str] = None
    auth_proto: Optional[str] = None
    priv_proto: Optional[str] = None

class DeviceModel(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None


@app.on_event("startup")
async def startup_event():
    ensure_data_path()


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = TEMPLATES_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=500, detail="UI template not found")
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


@app.get("/api/devices")
async def get_devices():
    return load_devices()


@app.get("/api/topology")
async def get_topology():
    devices = load_devices()
    return graph_manager.build_topology_json(devices)


@app.post("/api/discover")
async def discover_device(request: DiscoverRequest):
    auth_protocol = None
    priv_protocol = None

    if request.version == 3:
        if not request.user or not request.auth_key or not request.priv_key:
            raise HTTPException(
                status_code=400,
                detail="SNMPv3 requires user, auth_key, and priv_key",
            )
        auth_protocol = get_auth_protocol(request.auth_proto or "SHA")
        priv_protocol = get_priv_protocol(request.priv_proto or "AES")

    discovery = DeviceDiscovery(
        ip=request.ip,
        version=request.version,
        community=request.community,
        user=request.user,
        auth_key=request.auth_key,
        priv_key=request.priv_key,
        auth_protocol=auth_protocol,
        priv_protocol=priv_protocol,
    )

    result = await discovery.discover()
    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    if not isinstance(result, dict):
        raise HTTPException(status_code=500, detail="Invalid discovery result")

    device = DeviceModel.model_validate(result)
    devices = add_or_update_device(device.model_dump())
    return {"status": "ok", "device": result, "devices": devices}


@app.post("/api/reset")
async def reset_devices():
    save_devices([])
    return {"status": "ok", "devices": []}


if __name__ == "__main__":
    import uvicorn

    ensure_data_path()
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, log_level="info")
