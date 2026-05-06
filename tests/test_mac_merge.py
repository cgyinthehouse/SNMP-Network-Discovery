import pytest

from core.network_discovery_integration import NetworkDiscoveryIntegration


def test_merge_uses_nmap_mac_if_present():
    nmap_host = {
        "ip_address": "192.168.1.100",
        "mac_address": "aa:bb:cc:11:22:33",
        "hostname": "host1",
    }

    snmp_device = {
        "hostname": "host1",
        "Details": {
            "Network Adapters": [
                {"MAC Address": "aa:bb:cc:11:22:44"}
            ]
        }
    }

    merged = NetworkDiscoveryIntegration._merge_device_data(nmap_host, snmp_device)
    assert merged.get("mac_address") == "aa:bb:cc:11:22:33"


def test_merge_uses_snmp_adapter_mac_when_nmap_missing():
    nmap_host = {"ip_address": "192.168.1.101"}

    snmp_device = {
        "hostname": "host2",
        "Details": {
            "Network Adapters": [
                {"MAC Address": "AA:BB:CC:DD:EE:FF"}
            ]
        }
    }

    merged = NetworkDiscoveryIntegration._merge_device_data(nmap_host, snmp_device)
    assert merged.get("mac_address") == "AA:BB:CC:DD:EE:FF"
