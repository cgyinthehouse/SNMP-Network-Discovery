import json
import subprocess
import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.device_discovery import DeviceDiscovery
from core.graph_manager import GraphManager
from core.nmap_scanner import NmapScanner
from core.network_discovery_integration import NetworkDiscoveryIntegration
from core.network_utils import NetworkUtils

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
DIST_DIR = FRONTEND_DIR / "dist"
DATA_DIR = BASE_DIR / "data"
DATA_FILE = DATA_DIR / "devices.json"

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_data_path()

    # Startup enrichment: attempt to discover MAC addresses for existing
    # devices using an ARP discovery pass. Enabled by default except when
    # running under pytest (to avoid slowing tests) or when explicitly
    # disabled via STARTUP_ENRICH_MACS=0.
    try:
        enabled = os.getenv("STARTUP_ENRICH_MACS", "1") != "0" and "PYTEST_CURRENT_TEST" not in os.environ
        if enabled:
            try:
                ip = NetworkUtils.get_local_ip()
                if ip:
                    parts = ip.split(".")
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else f"{ip}/24"
                else:
                    subnet = None

                if subnet:
                    loop = asyncio.get_running_loop()
                    updated = await loop.run_in_executor(None, enrich_devices_with_macs, subnet, 30)
                    if updated:
                        print(f"Startup ARP enrichment updated {updated} device(s)")
            except Exception as e:
                print(f"Startup ARP enrichment failed: {e}")
    except Exception:
        # Best-effort: don't break app startup if enrichment check fails
        pass

    yield

app = FastAPI(title="SNMP Network Topology", version="0.1.0", lifespan=lifespan)

# Mount API routes first (higher priority)
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
    # Determine the canonical IP for the provided device
    device_ip = device.get("ip_address") or device.get("ip") or device.get("IP Address")

    # If no IP provided, append as-is
    if not device_ip:
        devices.append(device)
        save_devices(devices)
        return devices

    # Try to find an existing device record by IP
    existing = None
    for d in devices:
        if d.get("ip_address") == device_ip or d.get("ip") == device_ip or d.get("IP Address") == device_ip:
            existing = d
            break

    # Normalize incoming MAC synonyms onto the canonical `mac_address` key
    if device.get("mac") and not device.get("mac_address"):
        device["mac_address"] = device.get("mac")
    if device.get("MAC") and not device.get("mac_address"):
        device["mac_address"] = device.get("MAC")

    if existing:
        merged = existing.copy()
        # Merge non-empty values from the incoming device into the existing record
        for k, v in device.items():
            if v is None:
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            merged[k] = v

        # Ensure canonical IP field is present
        merged["ip_address"] = device_ip

        updated = [d for d in devices if not (d.get("ip_address") == device_ip or d.get("ip") == device_ip or d.get("IP Address") == device_ip)]
        updated.append(merged)
    else:
        # Ensure canonical IP and mac normalization on new records
        device["ip_address"] = device_ip
        updated = [d for d in devices]
        updated.append(device)

    save_devices(updated)
    return updated


def get_auth_protocol(value: Optional[str]):
    if value is None:
        return None
    if value.upper() not in auth_protocol_map:
        raise HTTPException(status_code=400, detail=f"Invalid auth_proto: {value}")
    return auth_protocol_map[value.upper()]


def get_priv_protocol(value: Optional[str]):
    if value is None:
        return None
    if value.upper() not in priv_protocol_map:
        raise HTTPException(status_code=400, detail=f"Invalid priv_proto: {value}")
    return priv_protocol_map[value.upper()]


def _get_system_arp_mapping():
    """Return a mapping of ip -> mac from the system ARP table (`ip neigh` or /proc/net/arp)."""
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], text=True)
    except Exception:
        try:
            content = Path("/proc/net/arp").read_text()
            lines = content.splitlines()[1:]
            mapping = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        mapping[ip] = mac
            return mapping
        except Exception:
            return {}

    mapping = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        if "lladdr" in parts:
            try:
                idx = parts.index("lladdr")
                mac = parts[idx + 1]
                if mac and mac != "00:00:00:00:00:00":
                    mapping[ip] = mac
            except Exception:
                continue
    return mapping


def enrich_devices_with_macs(subnet: str | None = None, timeout: int = 30) -> int:
    """Discover MAC addresses for devices in data/devices.json and save them.

    Returns number of records updated.
    """
    ensure_data_path()
    devices = load_devices()
    if not devices:
        return 0

    mac_map = {}
    if subnet:
        try:
            scanner = NmapScanner()
            mac_map = scanner.discover_macs(subnet, timeout=timeout) or {}
        except Exception:
            mac_map = {}

    if not mac_map:
        try:
            mac_map = _get_system_arp_mapping() or {}
        except Exception:
            mac_map = {}

    updated = 0
    for dev in devices:
        ip = dev.get("ip_address") or dev.get("ip")
        if not ip:
            continue
        mac = mac_map.get(ip)
        if mac and dev.get("mac_address") != mac:
            dev["mac_address"] = mac
            updated += 1

    if updated:
        save_devices(devices)

    return updated


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
    mac_address: Optional[str] = None


class NmapScanRequest(BaseModel):
    subnet: str = Field(..., description="Subnet in CIDR notation (e.g., 192.168.1.0/24)")
    ports: Optional[str] = Field(None, description="Port specification (e.g., 161,22,23)")
    arguments: str = Field("-sV", description="Additional nmap arguments")


class NmapHostScanRequest(BaseModel):
    host: str = Field(..., description="IP address to scan")
    ports: Optional[str] = Field(None, description="Port specification")
    arguments: str = Field("-sV", description="Additional nmap arguments")


class NmapSnmpScanRequest(BaseModel):
    subnet: str = Field(..., description="Subnet in CIDR notation")
    additional_ports: Optional[str] = Field(None, description="Additional ports to scan")


class IntegratedDiscoveryRequest(BaseModel):
    subnet: str = Field(..., description="Subnet in CIDR notation")
    snmp_version: int = Field(2, ge=1, le=3, description="SNMP version (1, 2, or 3)")
    snmp_community: str = Field("public", description="SNMP community string")
    additional_ports: Optional[str] = Field(None, description="Additional ports to scan")
    udp_scan: bool = Field(False, description="Enable UDP (-sU) scan for SNMP (may require root)")


class MultiSubnetDiscoveryRequest(BaseModel):
    subnets: List[str] = Field(..., description="List of subnets in CIDR notation")
    snmp_version: int = Field(2, ge=1, le=3, description="SNMP version")
    snmp_community: str = Field("public", description="SNMP community string")
    udp_scan: bool = Field(False, description="Enable UDP (-sU) scan for SNMP (may require root)")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = FRONTEND_DIR / "dist/index.html"
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


@app.get("/api/nmap/status")
async def nmap_status():
    """Check if nmap is installed and get version."""
    is_installed = NmapScanner.check_nmap_installed()
    version = NmapScanner.get_nmap_version() if is_installed else None
    return {
        "installed": is_installed,
        "version": version,
    }


@app.get("/api/local_network")
async def get_local_network():
    """Return a sensible local subnet to scan based on the host's IP.

    This helper lets the frontend request an "auto" subnet so it can
    perform discovery without the user entering a CIDR.
    """
    try:
        ip = NetworkUtils.get_local_ip()
        if not ip:
            raise HTTPException(status_code=500, detail="Unable to determine local IP")

        parts = ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            subnet = f"{ip}/24"

        return {"local_ip": ip, "default_subnet": subnet}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/nmap/scan-subnet")
async def nmap_scan_subnet(request: NmapScanRequest):
    """
    Scan a subnet for active hosts and services using nmap.
    
    This endpoint discovers devices on a network using nmap,
    and can be followed up with SNMP discovery on found hosts.
    """
    try:
        scanner = NmapScanner()
        result = scanner.scan_subnet(
            subnet=request.subnet,
            ports=request.ports,
            arguments=request.arguments,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")


@app.post("/api/nmap/scan-host")
async def nmap_scan_host(request: NmapHostScanRequest):
    """
    Scan a single host for open ports and services.
    """
    try:
        scanner = NmapScanner()
        result = scanner.scan_host(
            host=request.host,
            ports=request.ports,
            arguments=request.arguments,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")


@app.post("/api/nmap/scan-snmp")
async def nmap_scan_snmp(request: NmapSnmpScanRequest):
    """
    Specialized scan to find SNMP-enabled devices on a subnet.
    
    This endpoint scans for SNMP port 161 and returns only hosts
    with SNMP service detected, making it easy to identify devices
    for SNMP discovery.
    """
    try:
        scanner = NmapScanner()
        result = scanner.scan_for_snmp_devices(
            subnet=request.subnet,
            additional_ports=request.additional_ports,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SNMP scan failed: {str(e)}")


@app.post("/api/discovery/integrated-scan")
async def integrated_discovery_scan(request: IntegratedDiscoveryRequest):
    """
    Integrated nmap + SNMP discovery in a single endpoint.
    
    This endpoint:
    1. Scans the subnet with nmap to find active hosts and SNMP services
    2. Automatically performs SNMP discovery on SNMP-capable hosts
    3. Returns merged results with both nmap and SNMP information
    
    This is the recommended endpoint for discovering networks when
    SNMP devices need to be identified and queried automatically.
    """
    try:
        integration = NetworkDiscoveryIntegration()
        result = await integration.scan_and_discover_snmp(
            subnet=request.subnet,
            snmp_version=request.snmp_version,
            snmp_community=request.snmp_community,
            additional_ports=request.additional_ports,
            use_udp=request.udp_scan,
        )

        # Save discovered devices to the database. If SNMP discovery found
        # nothing, fall back to saving minimal device records from nmap
        # results (ip + optional hostname/mac) so the topology can render.
        if result.get("success"):
            discovered = result.get("discovered_devices", [])
            if discovered:
                for device in discovered:
                    add_or_update_device(device)
            else:
                nmap_result = result.get("nmap_result", {}) or {}
                hosts = nmap_result.get("hosts", []) or []

                # Try to use any discovery MACs collected by the integration's
                # NmapScanner instance (it runs a host-discovery ARP pass).
                discovery_mac_map = {}
                try:
                    discovery_mac_map = getattr(integration, "nmap_scanner", None)
                    if discovery_mac_map:
                        discovery_mac_map = getattr(integration.nmap_scanner, "discovery_mac_map", {}) or {}
                    else:
                        discovery_mac_map = {}
                except Exception:
                    discovery_mac_map = {}

                # If we still have no MACs, try the system ARP table as a fallback.
                if not discovery_mac_map:
                    try:
                        discovery_mac_map = _get_system_arp_mapping()
                    except Exception:
                        discovery_mac_map = {}

                for host in hosts:
                    ip = host.get("ip_address") or host.get("ip") or host.get("IP Address")
                    if not ip:
                        continue
                    hostname = host.get("hostname") or host.get("hostnames")
                    # hostnames may be a list or a string
                    if isinstance(hostname, list) and hostname:
                        hostname = hostname[0]

                    # Prefer explicit host mac fields, else check discovery map
                    mac = host.get("mac_address") or host.get("mac") or host.get("MAC") or discovery_mac_map.get(ip)

                    device = {"ip_address": ip}
                    if hostname:
                        device["hostname"] = hostname
                    # Store MAC explicitly rather than mis-using `model`.
                    if mac:
                        device["mac_address"] = mac

                    add_or_update_device(device)

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Integrated discovery failed: {str(e)}")


@app.post("/api/discovery/multi-subnet")
async def multi_subnet_discovery(request: MultiSubnetDiscoveryRequest):
    """
    Scan and discover SNMP devices across multiple subnets.
    
    This endpoint performs integrated discovery across multiple subnets
    and consolidates all results. Useful for discovering entire networks.
    """
    try:
        integration = NetworkDiscoveryIntegration()
        result = await integration.discover_multiple_subnets(
            subnets=request.subnets,
            snmp_version=request.snmp_version,
            snmp_community=request.snmp_community,
            use_udp=request.udp_scan,
        )

        # Save all discovered devices to the database
        for subnet_result in result.get("results", []):
            if subnet_result.get("success"):
                for device in subnet_result.get("discovered_devices", []):
                    add_or_update_device(device)

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Multi-subnet discovery failed: {str(e)}")


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


# Mount static files from dist directory (lowest priority, after all API routes)
app.mount("/", StaticFiles(directory=DIST_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    ensure_data_path()
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, log_level="info", reload=True)
