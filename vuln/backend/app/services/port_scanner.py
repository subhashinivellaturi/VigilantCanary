"""
Port scanning service for vulnerability detection.
Uses python-nmap if available, otherwise falls back to socket-based scanning.
"""

import socket
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

@dataclass
class PortScanResult:
    """Result of a port scan."""
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: str
    protocol: str = 'tcp'

class PortScanner:
    """Port scanner with nmap fallback to socket scanning."""

    COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]

    def __init__(self):
        self.nmap_available = NMAP_AVAILABLE
        self.nm = None
        if self.nmap_available:
            try:
                self.nm = nmap.PortScanner()
            except Exception:
                self.nmap_available = False

    def scan_ports(self, target: str, ports: Optional[List[int]] = None,
                   timeout: float = 1.0, max_workers: int = 10) -> List[PortScanResult]:
        """
        Scan ports on target host.

        Args:
            target: IP address or hostname
            ports: List of ports to scan (default: COMMON_PORTS)
            timeout: Timeout for each port scan
            max_workers: Maximum concurrent connections

        Returns:
            List of PortScanResult objects
        """
        if ports is None:
            ports = self.COMMON_PORTS

        if self.nmap_available and self.nm:
            return self._scan_with_nmap(target, ports)
        else:
            return self._scan_with_socket(target, ports, timeout, max_workers)

    def _scan_with_nmap(self, target: str, ports: List[int]) -> List[PortScanResult]:
        """Scan using python-nmap (safe, non-aggressive)."""
        try:
            port_str = ','.join(map(str, ports))
            # Use safe nmap options: -T3 (normal timing), -sS (SYN scan)
            self.nm.scan(target, port_str, arguments='-T3 -sS --max-retries 1')

            results = []
            if target in self.nm.all_hosts():
                for port in ports:
                    if self.nm[target].has_tcp(port):
                        port_info = self.nm[target]['tcp'][port]
                        results.append(PortScanResult(
                            port=port,
                            state=port_info['state'],
                            service=port_info.get('name', 'unknown'),
                            protocol='tcp'
                        ))
                    else:
                        results.append(PortScanResult(
                            port=port,
                            state='closed',
                            service='unknown',
                            protocol='tcp'
                        ))
            return results
        except Exception as e:
            # Fallback to socket scanning if nmap fails
            print(f"Nmap scan failed: {e}, falling back to socket scanning")
            return self._scan_with_socket(target, ports, 1.0, 10)

    def _scan_with_socket(self, target: str, ports: List[int],
                         timeout: float, max_workers: int) -> List[PortScanResult]:
        """Fallback socket-based port scanning."""
        results = []

        def check_port(port: int) -> PortScanResult:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    # Try to identify service
                    service = self._identify_service(port)
                    return PortScanResult(
                        port=port,
                        state='open',
                        service=service,
                        protocol='tcp'
                    )
                else:
                    return PortScanResult(
                        port=port,
                        state='closed',
                        service='unknown',
                        protocol='tcp'
                    )
            except Exception:
                return PortScanResult(
                    port=port,
                    state='filtered',
                    service='unknown',
                    protocol='tcp'
                )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in ports}
            for future in as_completed(future_to_port):
                results.append(future.result())

        # Sort by port number
        results.sort(key=lambda x: x.port)
        return results

    def _identify_service(self, port: int) -> str:
        """Basic service identification based on port number."""
        services = {
            21: 'ftp',
            22: 'ssh',
            80: 'http',
            443: 'https',
            3306: 'mysql',
            8080: 'http-alt'
        }
        return services.get(port, 'unknown')

    def get_open_ports(self, target: str, ports: Optional[List[int]] = None) -> List[PortScanResult]:
        """Get only open ports."""
        results = self.scan_ports(target, ports)
        return [result for result in results if result.state == 'open']

# Global instance
port_scanner = PortScanner()