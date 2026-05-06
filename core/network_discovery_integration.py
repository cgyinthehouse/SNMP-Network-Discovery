"""
Network Discovery Integration Module

This module integrates nmap scanning with SNMP discovery to provide
a complete network discovery workflow: first scan networks with nmap
to find active hosts, then perform SNMP discovery on identified devices.
"""

import logging
import asyncio
from typing import List, Dict, Optional
from core.nmap_scanner import NmapScanner
from core.device_discovery import DeviceDiscovery
from pysnmp.hlapi.v3arch.asyncio import (
    USM_AUTH_HMAC96_SHA,
    USM_PRIV_CFB128_AES,
)

logger = logging.getLogger(__name__)


class NetworkDiscoveryIntegration:
    """
    Integrates nmap scanning with SNMP discovery for comprehensive
    network device discovery and information gathering.
    """

    def __init__(self):
        """Initialize the integration module."""
        self.nmap_scanner = NmapScanner()
        self.discovery_results = []

    async def scan_and_discover_snmp(
        self,
        subnet: str,
        snmp_version: int = 2,
        snmp_community: str = "public",
        additional_ports: Optional[str] = None,
        use_udp: bool = False,
    ) -> Dict:
        """
        Perform a complete discovery workflow:
        1. Scan subnet with nmap to find SNMP-enabled devices
        2. Attempt SNMP discovery on each found device

        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            snmp_version: SNMP version to use (default: 2)
            snmp_community: SNMP community string (default: "public")
            additional_ports: Additional ports to scan with nmap

        Returns:
            Dictionary with nmap scan results and SNMP discovery results
        """
        logger.info(f"Starting integrated scan and discovery for {subnet}")

        # Step 1: Scan for SNMP devices using nmap
        scan_result = self.nmap_scanner.scan_for_snmp_devices(
            subnet=subnet,
            additional_ports=additional_ports,
            use_udp=use_udp,
        )

        if not scan_result.get("success"):
            logger.error(f"Nmap scan failed: {scan_result.get('error')}")
            return {
                "success": False,
                "error": scan_result.get("error"),
                "nmap_result": scan_result,
            }

        # Step 2: Attempt SNMP discovery on each SNMP-capable host
        snmp_hosts = scan_result.get("snmp_hosts", [])
        logger.info(f"Found {len(snmp_hosts)} SNMP-capable hosts, attempting SNMP discovery")

        discovered_devices = []
        for host in snmp_hosts:
            host_ip = host.get("ip_address")
            try:
                device = await self._snmp_discover_host(
                    ip=host_ip,
                    version=snmp_version,
                    community=snmp_community,
                )
                if device:
                    # Merge nmap data with SNMP discovery data
                    merged_device = self._merge_device_data(host, device)
                    discovered_devices.append(merged_device)
                    logger.info(f"Successfully discovered SNMP device at {host_ip}")
                else:
                    logger.warning(f"SNMP discovery failed for {host_ip}")
            except Exception as e:
                logger.error(f"Error discovering {host_ip}: {e}")

        self.discovery_results = discovered_devices

        return {
            "success": True,
            "subnet": subnet,
            "nmap_result": scan_result,
            "discovered_devices": discovered_devices,
            "discovery_count": len(discovered_devices),
            "total_snmp_capable": len(snmp_hosts),
        }

    async def discover_multiple_subnets(
        self,
        subnets: List[str],
        snmp_version: int = 2,
        snmp_community: str = "public",
        use_udp: bool = False,
    ) -> Dict:
        """
        Scan and discover SNMP devices across multiple subnets.

        Args:
            subnets: List of subnets in CIDR notation
            snmp_version: SNMP version to use
            snmp_community: SNMP community string

        Returns:
            Dictionary with results for all subnets
        """
        logger.info(f"Starting discovery for {len(subnets)} subnets")

        all_results = []
        total_discovered = 0

        for subnet in subnets:
            try:
                result = await self.scan_and_discover_snmp(
                    subnet=subnet,
                    snmp_version=snmp_version,
                    snmp_community=snmp_community,
                    use_udp=use_udp,
                )
                all_results.append(result)
                if result.get("success"):
                    total_discovered += result.get("discovery_count", 0)
            except Exception as e:
                logger.error(f"Error processing subnet {subnet}: {e}")
                all_results.append({
                    "success": False,
                    "subnet": subnet,
                    "error": str(e),
                })

        return {
            "success": True,
            "subnets_scanned": len(subnets),
            "total_devices_discovered": total_discovered,
            "results": all_results,
        }

    async def _snmp_discover_host(
        self,
        ip: str,
        version: int = 2,
        community: str = "public",
        user: Optional[str] = None,
        auth_key: Optional[str] = None,
        priv_key: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Perform SNMP discovery on a single host.

        Args:
            ip: IP address of the host
            version: SNMP version
            community: SNMP community string (for v1/v2c)
            user: SNMP username (for v3)
            auth_key: Authentication key (for v3)
            priv_key: Privacy key (for v3)

        Returns:
            Dictionary with SNMP discovery results or None if failed
        """
        try:
            auth_protocol = None
            priv_protocol = None

            if version == 3:
                auth_protocol = USM_AUTH_HMAC96_SHA
                priv_protocol = USM_PRIV_CFB128_AES

            discovery = DeviceDiscovery(
                ip=ip,
                version=version,
                community=community,
                user=user,
                auth_key=auth_key,
                priv_key=priv_key,
                auth_protocol=auth_protocol,
                priv_protocol=priv_protocol,
            )

            result = await discovery.discover()

            if isinstance(result, dict) and not result.get("error"):
                return result

        except Exception as e:
            logger.debug(f"SNMP discovery error for {ip}: {e}")

        return None

    @staticmethod
    def _merge_device_data(nmap_host: Dict, snmp_device: Dict) -> Dict:
        """
        Merge nmap host data with SNMP discovery data.

        Args:
            nmap_host: Host data from nmap scan
            snmp_device: Device data from SNMP discovery

        Returns:
            Merged dictionary with combined information
        """
        merged = {
            "ip_address": nmap_host.get("ip_address"),
            "hostname": snmp_device.get("hostname") or nmap_host.get("hostname", ""),
            "device_type": snmp_device.get("device_type"),
            "model": snmp_device.get("model"),
            "system_description": snmp_device.get("system_description"),
            "system_object_id": snmp_device.get("system_object_id"),
            "nmap_services": nmap_host.get("services", []),
            "nmap_ports": nmap_host.get("ports", []),
            "nmap_state": nmap_host.get("state"),
            "discovery_source": "nmap+snmp",
        }

        # Preserve MAC address information if present from nmap or SNMP details
        mac = nmap_host.get("mac_address") or nmap_host.get("mac") or None
        if not mac:
            # Try to find a MAC in SNMP device details (Network Adapters / Ports)
            details = snmp_device.get("Details") if isinstance(snmp_device, dict) else None
            if isinstance(details, dict):
                adapters = details.get("Network Adapters") or []
                for ad in adapters:
                    mac_val = ad.get("MAC Address") or ad.get("mac")
                    if mac_val:
                        mac = mac_val
                        break

        if mac:
            merged["mac_address"] = mac

        # Add any additional SNMP data
        for key, value in snmp_device.items():
            if key not in merged:
                merged[key] = value

        return merged

    def get_discovered_devices(self) -> List[Dict]:
        """
        Get the list of discovered devices from the last operation.

        Returns:
            List of discovered device dictionaries
        """
        return self.discovery_results

    def export_results(self, filepath: str) -> bool:
        """
        Export discovery results to a JSON file.

        Args:
            filepath: Path to save the results

        Returns:
            True if export was successful, False otherwise
        """
        try:
            import json
            with open(filepath, "w") as f:
                json.dump(self.discovery_results, f, indent=2)
            logger.info(f"Discovery results exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            return False
