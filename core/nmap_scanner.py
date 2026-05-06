"""
NMap Scanner Integration Module

This module provides utilities for scanning local networks using nmap,
identifying active hosts and services (especially SNMP), and integrating
the results with SNMP discovery capabilities.
"""

import logging
import subprocess
import json
from typing import List, Dict, Optional, Set
import nmap
from pathlib import Path

logger = logging.getLogger(__name__)


class NmapScanner:
    """
    A wrapper around nmap to scan networks for active hosts and services.
    Particularly useful for identifying SNMP-enabled devices.
    """

    def __init__(self, timeout: int = 300):
        """
        Initialize the NmapScanner.

        Args:
            timeout: Timeout for nmap scan in seconds (default: 300)
        """
        self.nm = nmap.PortScanner()
        self.timeout = timeout
        self.scan_results = {}
        # Map of ip -> mac discovered by a dedicated host-discovery pass
        self.discovery_mac_map: Dict[str, str] = {}

    def scan_subnet(self, subnet: str, ports: Optional[str] = None, 
                   arguments: str = "-sV") -> Dict:
        """
        Scan a subnet for active hosts and services.

        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            ports: Port specification string (e.g., "161,22,23" for SNMP/SSH/Telnet)
                   If None, common ports are scanned
            arguments: Additional nmap arguments (default: "-sV" for version detection)

        Returns:
            Dictionary containing scan results with host information
        """
        if ports is None:
            # Default ports: SNMP (161), SSH (22), Telnet (23), HTTP (80), HTTPS (443)
            ports = "161,22,23,80,443"

        try:
            # First: run a lightweight host-discovery (ARP) pass to collect
            # MAC addresses on the local LAN. We use a separate PortScanner
            # instance so we don't lose these results when running the
            # subsequent service/port scan.
            self.discovery_mac_map = {}
            try:
                discovery_scanner = nmap.PortScanner()
                discovery_args = "-sn -PR"
                logger.debug(f"Running discovery pass on {subnet} with args: {discovery_args}")
                discovery_scanner.scan(hosts=subnet, arguments=discovery_args, timeout=min(60, max(10, int(self.timeout // 5))))
                for h in discovery_scanner.all_hosts():
                    try:
                        addr = discovery_scanner[h].get("addresses", {})
                        mac = None
                        if isinstance(addr, dict):
                            mac = addr.get("mac") or addr.get("MAC")
                        if not mac:
                            mac = getattr(discovery_scanner[h], "mac", None)
                        if mac:
                            self.discovery_mac_map[h] = mac
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Discovery pass failed: {e}")

            # Build nmap command for service/port scanning. If the discovery
            # pass found hosts, scan only those hosts to speed things up and
            # preserve MACs. Otherwise scan the full subnet.
            nmap_args = f"-p {ports} {arguments}"
            target = " ".join(self.discovery_mac_map.keys()) if self.discovery_mac_map else subnet
            logger.info(f"Starting nmap scan on {target} with args: {nmap_args}")

            # Run the main scan
            self.nm.scan(hosts=target, arguments=nmap_args, timeout=self.timeout)

            # Process results
            hosts_data = self._process_scan_results()

            # If no hosts found with the requested ports/arguments, fall back
            # to a simple host-discovery (ping) scan (use ARP) so we can at
            # least enumerate live hosts for topology rendering and capture MACs.
            if not hosts_data:
                logger.info("No hosts found in port/service scan; running ping scan fallback (-sn -PR)")
                try:
                    self.nm.scan(hosts=subnet, arguments="-sn -PR", timeout=max(60, self.timeout))
                    # Update discovery map from this fallback run as well
                    try:
                        for h in self.nm.all_hosts():
                            addr = self.nm[h].get("addresses", {})
                            mac = None
                            if isinstance(addr, dict):
                                mac = addr.get("mac") or addr.get("MAC")
                            if not mac:
                                mac = getattr(self.nm[h], "mac", None)
                            if mac and h not in self.discovery_mac_map:
                                self.discovery_mac_map[h] = mac
                    except Exception:
                        pass
                    hosts_data = self._process_scan_results()
                except Exception as e:
                    logger.debug(f"Ping-scan fallback failed: {e}")

            # Merge discovery MACs into host entries when nmap didn't include them
            for h in hosts_data:
                if not h.get("mac_address"):
                    ip = h.get("ip_address")
                    if ip and ip in self.discovery_mac_map:
                        h["mac_address"] = self.discovery_mac_map[ip]

            self.scan_results[subnet] = hosts_data

            return {
                "success": True,
                "subnet": subnet,
                "hosts_found": len(hosts_data),
                "hosts": hosts_data,
            }

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error: {e}")
            return {
                "success": False,
                "subnet": subnet,
                "error": str(e),
            }
        except Exception as e:
            logger.error(f"Unexpected error during nmap scan: {e}")
            return {
                "success": False,
                "subnet": subnet,
                "error": str(e),
            }

    def scan_host(self, host: str, ports: Optional[str] = None,
                 arguments: str = "-sV") -> Dict:
        """
        Scan a single host for services.

        Args:
            host: IP address to scan
            ports: Port specification string
            arguments: Additional nmap arguments

        Returns:
            Dictionary containing scan results for the host
        """
        if ports is None:
            ports = "161,22,23,80,443"

        try:
            logger.info(f"Starting nmap scan on {host}")
            nmap_args = f"-p {ports} {arguments}"
            self.nm.scan(hosts=host, arguments=nmap_args, timeout=self.timeout)

            host_data = self._process_single_host(host)

            return {
                "success": True,
                "host": host,
                "data": host_data,
            }

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan error for {host}: {e}")
            return {
                "success": False,
                "host": host,
                "error": str(e),
            }

    def scan_for_snmp_devices(self, subnet: str,
                             additional_ports: Optional[str] = None,
                             use_udp: bool = False) -> Dict:
        """
        Specialized scan to find SNMP-enabled devices on a subnet.

        Args:
            subnet: Subnet in CIDR notation
            additional_ports: Additional ports to scan along with SNMP (161)

        Returns:
            Dictionary with SNMP-capable hosts
        """
        ports_to_scan = "161"  # SNMP port
        if additional_ports:
            ports_to_scan = f"{ports_to_scan},{additional_ports}"

        # Use service detection; allow UDP (-sU) when requested.
        arguments = "-sV --open"
        if use_udp:
            # UDP scans require elevated privileges on many systems. This
            # will attempt an -sU scan; if the process lacks privileges,
            # nmap may still run but results can vary.
            arguments = "-sU -sV --open"

        result = self.scan_subnet(subnet, ports=ports_to_scan, arguments=arguments)

        if result.get("success"):
            # Filter only hosts with SNMP port open
            snmp_hosts = [
                host for host in result.get("hosts", [])
                if self._has_snmp_port_open(host)
            ]

            result["snmp_hosts"] = snmp_hosts
            result["snmp_hosts_count"] = len(snmp_hosts)

        return result

    def _process_scan_results(self) -> List[Dict]:
        """
        Process nmap scan results and extract relevant information.

        Returns:
            List of dictionaries containing host information
        """
        hosts_data = []

        for host in self.nm.all_hosts():
            host_data = self._process_single_host(host)
            if host_data:
                hosts_data.append(host_data)

        return hosts_data

    def _process_single_host(self, host: str) -> Optional[Dict]:
        """
        Process information for a single host from nmap results.

        Args:
            host: IP address of the host

        Returns:
            Dictionary with host information or None if host is down
        """
        if host not in self.nm.all_hosts():
            return None

        host_info = self.nm[host]

        # Skip if host is down
        if host_info.state() == "down":
            return None

        # Extract basic host information
        host_data = {
            "ip_address": host,
            "state": host_info.state(),
            "status": host_info["status"]["state"],
            "reason": host_info["status"].get("reason", ""),
            "ports": [],
            "services": [],
        }

        # Extract MAC address if available
        try:
            addresses = host_info.get('addresses', {})
            mac = None
            if isinstance(addresses, dict):
                mac = addresses.get('mac') or addresses.get('MAC')
            # nmap PortScanner may also expose mac via host_info.mac() in some versions
            if not mac:
                mac = getattr(host_info, 'mac', None)
            if mac:
                host_data['mac_address'] = mac
        except Exception:
            # best-effort, ignore problems extracting MAC
            pass

        # Extract hostname if available
        if "hostnames" in host_info:
            hostnames = host_info["hostnames"]
            if hostnames and len(hostnames) > 0:
                host_data["hostname"] = hostnames[0].get("name", "")

        # Extract port and service information
        for protocol in host_info.all_protocols():
            ports = host_info[protocol].keys()
            for port in ports:
                port_info = host_info[protocol][port]
                port_data = {
                    "port": port,
                    "protocol": protocol,
                    "state": port_info["state"],
                    "name": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                }

                host_data["ports"].append(port_data)
                if port_info.get("name"):
                    host_data["services"].append(port_info.get("name"))

        return host_data

    def _has_snmp_port_open(self, host: Dict) -> bool:
        """
        Check if a host has SNMP port (161) open.

        Args:
            host: Host dictionary from scan results

        Returns:
            True if SNMP port is open, False otherwise
        """
        for port_info in host.get("ports", []):
            if port_info.get("port") == 161 and port_info.get("state") == "open":
                return True
        return False

    def get_scan_summary(self) -> Dict:
        """
        Get a summary of all scans performed.

        Returns:
            Dictionary with scan summary statistics
        """
        total_hosts = sum(len(hosts) for hosts in self.scan_results.values())
        total_subnets = len(self.scan_results)

        return {
            "total_subnets_scanned": total_subnets,
            "total_hosts_found": total_hosts,
            "scanned_subnets": list(self.scan_results.keys()),
        }

    def export_scan_results(self, filepath: str) -> bool:
        """
        Export scan results to a JSON file.

        Args:
            filepath: Path to save the results

        Returns:
            True if export was successful, False otherwise
        """
        try:
            with open(filepath, "w") as f:
                json.dump(self.scan_results, f, indent=2)
            logger.info(f"Scan results exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error exporting scan results: {e}")
            return False

    def discover_macs(self, subnet: str, timeout: int = 60) -> Dict[str, str]:
        """
        Perform a lightweight ARP host-discovery pass to collect MAC addresses
        on the local network. Uses a fresh PortScanner to avoid disturbing
        existing scan state.

        Returns a mapping of ip -> mac for hosts where a MAC was discovered.
        """
        mac_map: Dict[str, str] = {}
        try:
            scanner = nmap.PortScanner()
            args = "-sn -PR"
            logger.info(f"Running ARP discovery on {subnet} with args: {args}")
            scanner.scan(hosts=subnet, arguments=args, timeout=min(timeout, 120))
            for h in scanner.all_hosts():
                try:
                    addr = scanner[h].get("addresses", {})
                    mac = None
                    if isinstance(addr, dict):
                        mac = addr.get("mac") or addr.get("MAC")
                    if not mac:
                        mac = getattr(scanner[h], "mac", None)
                    if mac:
                        mac_map[h] = mac
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"ARP discovery failed: {e}")

        return mac_map

    @staticmethod
    def check_nmap_installed() -> bool:
        """
        Check if nmap is installed on the system.

        Returns:
            True if nmap is installed, False otherwise
        """
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_nmap_version() -> Optional[str]:
        """
        Get the installed nmap version.

        Returns:
            Version string or None if nmap is not installed
        """
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Output format: "Nmap version 7.93 ( https://nmap.org )"
                lines = result.stdout.strip().split("\n")
                return lines[0] if lines else None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None
