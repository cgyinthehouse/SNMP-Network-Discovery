import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from fastapi.testclient import TestClient

from web_app import (
    add_or_update_device,
    ensure_data_path,
    get_auth_protocol,
    get_priv_protocol,
    load_devices,
    save_devices,
    app,
)


@pytest.fixture
def temp_data_file():
    """Create a temporary data file for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_file = Path(tmpdir) / "devices.json"
        temp_file.write_text("[]", encoding="utf-8")
        
        with patch("web_app.DATA_FILE", temp_file):
            with patch("web_app.DATA_DIR", Path(tmpdir)):
                yield temp_file


@pytest.fixture
def sample_device():
    """Provide a sample device dictionary."""
    return {
        "ip_address": "192.168.1.1",
        "hostname": "router-1",
        "device_type": "Router",
        "model": "Cisco 2900",
    }


@pytest.fixture
def sample_devices_list():
    """Provide a list of sample devices."""
    return [
        {
            "ip_address": "192.168.1.1",
            "hostname": "router-1",
            "device_type": "Router",
            "model": "Cisco 2900",
        },
        {
            "ip_address": "192.168.1.2",
            "hostname": "switch-1",
            "device_type": "Switch",
            "model": "Cisco 3650",
        },
    ]


class TestDataManagement:
    """Test data management functions."""

    def test_ensure_data_path_creates_directory(self, temp_data_file):
        """Test that ensure_data_path creates the data directory."""
        with patch("web_app.DATA_DIR", temp_data_file.parent):
            with patch("web_app.DATA_FILE", temp_data_file):
                ensure_data_path()
                assert temp_data_file.parent.exists()

    def test_ensure_data_path_creates_empty_file(self, temp_data_file):
        """Test that ensure_data_path creates an empty devices file."""
        temp_file = temp_data_file.parent / "new_devices.json"
        with patch("web_app.DATA_FILE", temp_file):
            ensure_data_path()
            assert temp_file.exists()
            assert temp_file.read_text(encoding="utf-8") == "[]"

    def test_load_devices_empty_file(self, temp_data_file):
        """Test loading devices from an empty file."""
        with patch("web_app.DATA_FILE", temp_data_file):
            devices = load_devices()
            assert devices == []

    def test_load_devices_with_devices(self, temp_data_file, sample_devices_list):
        """Test loading devices from a file with data."""
        with patch("web_app.DATA_FILE", temp_data_file):
            temp_data_file.write_text(
                json.dumps(sample_devices_list), encoding="utf-8"
            )
            devices = load_devices()
            assert devices == sample_devices_list
            assert len(devices) == 2

    def test_load_devices_invalid_json(self, temp_data_file):
        """Test loading devices from a file with invalid JSON."""
        with patch("web_app.DATA_FILE", temp_data_file):
            temp_data_file.write_text("invalid json {", encoding="utf-8")
            devices = load_devices()
            assert devices == []

    def test_load_devices_missing_file(self):
        """Test loading devices when file doesn't exist."""
        with patch("web_app.DATA_FILE", Path("/nonexistent/path/devices.json")):
            devices = load_devices()
            assert devices == []

    def test_save_devices(self, temp_data_file, sample_devices_list):
        """Test saving devices to file."""
        with patch("web_app.DATA_FILE", temp_data_file):
            save_devices(sample_devices_list)
            saved_data = json.loads(temp_data_file.read_text(encoding="utf-8"))
            assert saved_data == sample_devices_list

    def test_save_devices_formats_json(self, temp_data_file, sample_device):
        """Test that save_devices formats JSON with indentation."""
        with patch("web_app.DATA_FILE", temp_data_file):
            save_devices([sample_device])
            content = temp_data_file.read_text(encoding="utf-8")
            assert "\n" in content  # Check for indentation
            assert json.loads(content) == [sample_device]

    def test_add_or_update_device_new_device(self, temp_data_file, sample_device):
        """Test adding a new device."""
        with patch("web_app.DATA_FILE", temp_data_file):
            result = add_or_update_device(sample_device)
            assert len(result) == 1
            assert result[0] == sample_device

    def test_add_or_update_device_update_existing(self, temp_data_file):
        """Test updating an existing device."""
        devices = [
            {"ip_address": "192.168.1.1", "hostname": "old-name"},
        ]
        updated_device = {"ip_address": "192.168.1.1", "hostname": "new-name"}
        
        with patch("web_app.DATA_FILE", temp_data_file):
            temp_data_file.write_text(json.dumps(devices), encoding="utf-8")
            result = add_or_update_device(updated_device)
            assert len(result) == 1
            assert result[0]["hostname"] == "new-name"

    def test_add_or_update_device_adds_to_existing(self, temp_data_file, sample_devices_list):
        """Test adding a device to existing devices."""
        new_device = {
            "ip_address": "192.168.1.3",
            "hostname": "firewall-1",
            "device_type": "Firewall",
        }
        
        with patch("web_app.DATA_FILE", temp_data_file):
            temp_data_file.write_text(
                json.dumps(sample_devices_list), encoding="utf-8"
            )
            result = add_or_update_device(new_device)
            assert len(result) == 3
            assert result[2] == new_device


class TestProtocolMapping:
    """Test protocol mapping functions."""

    def test_get_auth_protocol_md5(self):
        """Test MD5 auth protocol mapping."""
        protocol = get_auth_protocol("MD5")
        assert protocol is not None

    def test_get_auth_protocol_sha(self):
        """Test SHA auth protocol mapping."""
        protocol = get_auth_protocol("SHA")
        assert protocol is not None

    def test_get_auth_protocol_sha256(self):
        """Test SHA256 auth protocol mapping."""
        protocol = get_auth_protocol("SHA256")
        assert protocol is not None

    def test_get_auth_protocol_none(self):
        """Test NONE auth protocol mapping."""
        protocol = get_auth_protocol("NONE")
        assert protocol is not None

    def test_get_auth_protocol_case_insensitive(self):
        """Test that auth protocol mapping is case-insensitive."""
        protocol1 = get_auth_protocol("sha")
        protocol2 = get_auth_protocol("SHA")
        assert protocol1 == protocol2

    def test_get_auth_protocol_none_input(self):
        """Test get_auth_protocol with None input."""
        protocol = get_auth_protocol(None)
        assert protocol is None

    def test_get_priv_protocol_des(self):
        """Test DES privacy protocol mapping."""
        protocol = get_priv_protocol("DES")
        assert protocol is not None

    def test_get_priv_protocol_aes(self):
        """Test AES privacy protocol mapping."""
        protocol = get_priv_protocol("AES")
        assert protocol is not None

    def test_get_priv_protocol_aes256(self):
        """Test AES256 privacy protocol mapping."""
        protocol = get_priv_protocol("AES256")
        assert protocol is not None

    def test_get_priv_protocol_none(self):
        """Test NONE privacy protocol mapping."""
        protocol = get_priv_protocol("NONE")
        assert protocol is None

    def test_get_priv_protocol_case_insensitive(self):
        """Test that priv protocol mapping is case-insensitive."""
        protocol1 = get_priv_protocol("aes")
        protocol2 = get_priv_protocol("AES")
        assert protocol1 == protocol2

    def test_get_priv_protocol_none_input(self):
        """Test get_priv_protocol with None input."""
        protocol = get_priv_protocol(None)
        assert protocol is None


class TestHTTPExceptionHandling:
    """Test HTTP exception handling for invalid protocols."""

    def test_get_auth_protocol_raises_on_invalid(self):
        """Test that invalid auth protocol raises HTTPException."""
        from fastapi import HTTPException
        
        with pytest.raises(HTTPException) as exc_info:
            get_auth_protocol("INVALID_PROTOCOL")
        assert exc_info.value.status_code == 400
        assert "Invalid auth_proto" in str(exc_info.value.detail)

    def test_get_priv_protocol_raises_on_invalid(self):
        """Test that invalid priv protocol raises HTTPException."""
        from fastapi import HTTPException
        
        with pytest.raises(HTTPException) as exc_info:
            get_priv_protocol("INVALID_PROTOCOL")
        assert exc_info.value.status_code == 400
        assert "Invalid priv_proto" in str(exc_info.value.detail)


class TestDataModel:
    """Test Pydantic data models."""

    def test_discover_request_model_valid(self):
        """Test DiscoverRequest model with valid data."""
        from web_app import DiscoverRequest
        
        request = DiscoverRequest(
            ip="192.168.1.1",
            version=2,
            community="public",
        )
        assert request.ip == "192.168.1.1"
        assert request.version == 2
        assert request.community == "public"

    def test_discover_request_model_snmpv3(self):
        """Test DiscoverRequest model with SNMPv3 data."""
        from web_app import DiscoverRequest
        
        request = DiscoverRequest(
            ip="192.168.1.1",
            version=3,
            user="admin",
            auth_key="authkey",
            priv_key="privkey",
            auth_proto="SHA",
            priv_proto="AES",
        )
        assert request.version == 3
        assert request.user == "admin"
        assert request.auth_proto == "SHA"
        assert request.priv_proto == "AES"

    def test_device_model_valid(self):
        """Test DeviceModel with valid data."""
        from web_app import DeviceModel
        
        device = DeviceModel(
            ip_address="192.168.1.1",
            hostname="router-1",
            device_type="Router",
            model="Cisco 2900",
        )
        assert device.ip_address == "192.168.1.1"
        assert device.hostname == "router-1"

    def test_device_model_minimal(self):
        """Test DeviceModel with minimal required data."""
        from web_app import DeviceModel
        
        device = DeviceModel(ip_address="192.168.1.1")
        assert device.ip_address == "192.168.1.1"
        assert device.hostname is None
        assert device.device_type is None


class TestDiscoverRequestModel:
    """Test DiscoverRequest model validation."""

    def test_discover_request_snmpv3_validation(self):
        """Test DiscoverRequest validates SNMPv3 requirements."""
        from web_app import DiscoverRequest
        
        # Valid SNMPv3
        request = DiscoverRequest(
            ip="192.168.1.1",
            version=3,
            user="admin",
            auth_key="key",
            priv_key="key",
        )
        assert request.version == 3
        assert request.user == "admin"


@pytest.fixture
def client():
    """Provide a TestClient for API testing."""
    # Use the app directly - TestClient handles async properly
    return TestClient(app)


@pytest.fixture
def sample_devices_in_db(temp_data_file, sample_devices_list):
    """Provide sample devices saved in the database."""
    with patch("web_app.DATA_FILE", temp_data_file):
        temp_data_file.write_text(json.dumps(sample_devices_list), encoding="utf-8")
        yield sample_devices_list


class TestAPIBasicEndpoints:
    """Test basic API endpoints."""

    def test_get_devices_empty(self, client):
        """Test getting devices when database is empty."""
        with patch("web_app.load_devices", return_value=[]):
            response = client.get("/api/devices")
            assert response.status_code == 200
            assert response.json() == []

    def test_get_devices_with_data(self, client, sample_devices_list):
        """Test getting devices when database has data."""
        with patch("web_app.load_devices", return_value=sample_devices_list):
            response = client.get("/api/devices")
            assert response.status_code == 200
            assert len(response.json()) == 2
            assert response.json()[0]["ip_address"] == "192.168.1.1"

    def test_reset_devices(self, client):
        """Test resetting devices database."""
        with patch("web_app.save_devices") as mock_save:
            response = client.post("/api/reset")
            assert response.status_code == 200
            assert response.json()["status"] == "ok"
            assert response.json()["devices"] == []
            mock_save.assert_called_once_with([])


class TestAPITopologyEndpoint:
    """Test topology endpoint."""

    def test_get_topology_empty(self, client):
        """Test getting topology when no devices exist."""
        with patch("web_app.load_devices", return_value=[]):
            response = client.get("/api/topology")
            assert response.status_code == 200
            result = response.json()
            assert isinstance(result, dict)

    def test_get_topology_with_devices(self, client, sample_devices_list):
        """Test getting topology with devices in database."""
        with patch("web_app.load_devices", return_value=sample_devices_list):
            response = client.get("/api/topology")
            assert response.status_code == 200
            assert isinstance(response.json(), dict)


class TestAPINmapStatusEndpoint:
    """Test nmap status endpoint."""

    def test_nmap_status_endpoint(self, client):
        """Test nmap status endpoint."""
        with patch("core.nmap_scanner.NmapScanner.check_nmap_installed", return_value=True):
            with patch("core.nmap_scanner.NmapScanner.get_nmap_version", return_value="Nmap version 7.93"):
                response = client.get("/api/nmap/status")
                assert response.status_code == 200
                result = response.json()
                assert result["installed"] is True
                assert result["version"] == "Nmap version 7.93"

    def test_nmap_status_not_installed(self, client):
        """Test nmap status when nmap is not installed."""
        with patch("core.nmap_scanner.NmapScanner.check_nmap_installed", return_value=False):
            response = client.get("/api/nmap/status")
            assert response.status_code == 200
            result = response.json()
            assert result["installed"] is False
            assert result["version"] is None


class TestAPINmapScanEndpoints:
    """Test nmap scanning endpoints."""

    def test_nmap_scan_subnet(self, client):
        """Test nmap subnet scanning endpoint."""
        mock_scan_result = {
            "success": True,
            "subnet": "192.168.1.0/24",
            "hosts_found": 2,
            "hosts": [
                {
                    "ip_address": "192.168.1.1",
                    "state": "up",
                    "status": "up",
                    "ports": [{"port": 22, "state": "open"}],
                    "services": ["ssh"],
                }
            ],
        }
        
        with patch("core.nmap_scanner.NmapScanner.scan_subnet", return_value=mock_scan_result):
            response = client.post(
                "/api/nmap/scan-subnet",
                json={
                    "subnet": "192.168.1.0/24",
                    "ports": "22,80,443",
                    "arguments": "-sV",
                },
            )
            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True
            assert result["subnet"] == "192.168.1.0/24"

    def test_nmap_scan_host(self, client):
        """Test nmap single host scanning endpoint."""
        mock_scan_result = {
            "success": True,
            "host": "192.168.1.1",
            "data": {
                "ip_address": "192.168.1.1",
                "state": "up",
                "ports": [
                    {"port": 22, "state": "open", "name": "ssh"},
                    {"port": 80, "state": "open", "name": "http"},
                ],
            },
        }
        
        with patch("core.nmap_scanner.NmapScanner.scan_host", return_value=mock_scan_result):
            response = client.post(
                "/api/nmap/scan-host",
                json={
                    "host": "192.168.1.1",
                    "ports": "22,80",
                    "arguments": "-sV",
                },
            )
            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True
            assert result["host"] == "192.168.1.1"

    def test_nmap_scan_snmp(self, client):
        """Test nmap SNMP-specific scanning endpoint."""
        mock_scan_result = {
            "success": True,
            "subnet": "192.168.1.0/24",
            "snmp_hosts_count": 1,
            "snmp_hosts": [
                {
                    "ip_address": "192.168.1.1",
                    "state": "up",
                    "ports": [{"port": 161, "state": "open", "name": "snmp"}],
                }
            ],
        }
        
        with patch("core.nmap_scanner.NmapScanner.scan_for_snmp_devices", return_value=mock_scan_result):
            response = client.post(
                "/api/nmap/scan-snmp",
                json={
                    "subnet": "192.168.1.0/24",
                    "additional_ports": "22,23",
                },
            )
            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True
            assert result["snmp_hosts_count"] == 1


class TestAPIDiscoveryEndpoints:
    """Test SNMP discovery endpoints."""

    def test_discover_device_snmpv2(self, client):
        """Test discovering a single device with SNMPv2."""
        mock_discovery_result = {
            "ip_address": "192.168.1.1",
            "hostname": "router-1",
            "device_type": "Router",
            "model": "Cisco 2900",
        }
        
        with patch("web_app.add_or_update_device", return_value=[mock_discovery_result]):
            with patch("web_app.DeviceDiscovery") as MockDiscovery:
                mock_instance = MagicMock()
                mock_instance.discover = AsyncMock(return_value=mock_discovery_result)
                MockDiscovery.return_value = mock_instance
                
                response = client.post(
                    "/api/discover",
                    json={
                        "ip": "192.168.1.1",
                        "version": 2,
                        "community": "public",
                    },
                )
                assert response.status_code == 200
                result = response.json()
                assert result["status"] == "ok"
                assert result["device"]["ip_address"] == "192.168.1.1"

    def test_discover_device_snmpv3_missing_params(self, client):
        """Test SNMPv3 discovery with missing required parameters."""
        response = client.post(
            "/api/discover",
            json={
                "ip": "192.168.1.1",
                "version": 3,
                "user": "admin",
            },
        )
        assert response.status_code == 400
        assert "SNMPv3 requires" in response.json()["detail"]

    def test_integrated_scan_and_discover(self, client):
        """Test integrated nmap scan and SNMP discovery."""
        mock_result = {
            "success": True,
            "subnet": "192.168.1.0/24",
            "discovered_devices": [
                {
                    "ip_address": "192.168.1.1",
                    "hostname": "router-1",
                    "device_type": "Router",
                    "discovery_source": "nmap+snmp",
                }
            ],
            "discovery_count": 1,
        }
        
        with patch("web_app.add_or_update_device"):
            with patch("web_app.NetworkDiscoveryIntegration") as MockIntegration:
                mock_instance = MagicMock()
                mock_instance.scan_and_discover_snmp = AsyncMock(return_value=mock_result)
                MockIntegration.return_value = mock_instance
                
                response = client.post(
                    "/api/discovery/integrated-scan",
                    json={
                        "subnet": "192.168.1.0/24",
                        "snmp_version": 2,
                        "snmp_community": "public",
                    },
                )
                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["discovery_count"] == 1

    def test_multi_subnet_discovery(self, client):
        """Test multi-subnet discovery endpoint."""
        mock_result = {
            "success": True,
            "subnets_scanned": 2,
            "total_devices_discovered": 2,
            "results": [
                {
                    "success": True,
                    "subnet": "192.168.1.0/24",
                    "discovered_devices": [
                        {
                            "ip_address": "192.168.1.1",
                            "hostname": "device-1",
                        }
                    ],
                }
            ],
        }
        
        with patch("web_app.add_or_update_device"):
            with patch("web_app.NetworkDiscoveryIntegration") as MockIntegration:
                mock_instance = MagicMock()
                mock_instance.discover_multiple_subnets = AsyncMock(return_value=mock_result)
                MockIntegration.return_value = mock_instance
                
                response = client.post(
                    "/api/discovery/multi-subnet",
                    json={
                        "subnets": ["192.168.1.0/24", "192.168.2.0/24"],
                        "snmp_version": 2,
                        "snmp_community": "public",
                    },
                )
                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["subnets_scanned"] == 2


class TestAPIErrorHandling:
    """Test error handling in API endpoints."""

    def test_nmap_scan_error(self, client):
        """Test nmap scan endpoint error handling."""
        error_result = {
            "success": False,
            "subnet": "invalid-subnet",
            "error": "Invalid subnet format",
        }
        
        with patch("core.nmap_scanner.NmapScanner.scan_subnet", return_value=error_result):
            response = client.post(
                "/api/nmap/scan-subnet",
                json={"subnet": "invalid-subnet"},
            )
            assert response.status_code == 200

    def test_discover_device_error(self, client):
        """Test discover endpoint with SNMP error."""
        with patch("web_app.DeviceDiscovery") as MockDiscovery:
            mock_instance = MagicMock()
            mock_instance.discover = AsyncMock(return_value={"error": "SNMP timeout"})
            MockDiscovery.return_value = mock_instance
            
            response = client.post(
                "/api/discover",
                json={
                    "ip": "192.168.1.1",
                    "version": 2,
                },
            )
            assert response.status_code == 400
            detail = response.json()["detail"].lower()
            assert "snmp" in detail or "timeout" in detail


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
