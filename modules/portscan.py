"""
Port Scanner Module
Independent, reusable port scanning functionality
"""

import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

# Service mapping for common ports
SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}

# Default ports to scan if not specified
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]


def _resolve_target(target: str) -> Optional[str]:
    """
    Resolve domain name to IP address
    
    Args:
        target: Domain name or IP address
        
    Returns:
        IP address string or None if resolution fails
    """
    try:
        ip = socket.gethostbyname(target)
        logging.info(f"Resolved {target} to {ip}")
        return ip
    except socket.gaierror as e:
        logging.error(f"Failed to resolve {target}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error resolving {target}: {e}")
        return None


def _scan_port(ip: str, port: int, timeout: float) -> Optional[int]:
    """
    Scan a single port using TCP connect method
    
    Args:
        ip: Target IP address
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Port number if open, None otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            logging.debug(f"Port {port} is OPEN on {ip}")
            return port
        return None
    except socket.timeout:
        return None
    except socket.error as e:
        logging.debug(f"Socket error on port {port}: {e}")
        return None
    except Exception as e:
        logging.debug(f"Unexpected error scanning port {port}: {e}")
        return None
    finally:
        sock.close()


def _get_service_name(port: int) -> str:
    """
    Get service name for a port number
    
    Args:
        port: Port number
        
    Returns:
        Service name or 'unknown'
    """
    return SERVICE_MAP.get(port, "unknown")


def _parse_config(config: Optional[Dict]) -> Dict:
    """
    Parse and validate configuration dictionary
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Validated configuration with defaults
    """
    default_config = {
        "timeout": 1.5,
        "ports": DEFAULT_PORTS.copy(),
        "max_workers": 50,
        "scan_type": "tcp_connect"
    }
    
    if config is None:
        return default_config
    
    # Merge with defaults
    merged_config = default_config.copy()
    
    # Handle timeout
    if "timeout" in config:
        try:
            merged_config["timeout"] = float(config["timeout"])
        except (ValueError, TypeError):
            logging.warning(f"Invalid timeout value, using default: {default_config['timeout']}")
    
    # Handle ports
    if "ports" in config:
        if isinstance(config["ports"], list):
            merged_config["ports"] = config["ports"]
        elif isinstance(config["ports"], tuple) and len(config["ports"]) == 2:
            # Port range (start, end)
            try:
                start, end = int(config["ports"][0]), int(config["ports"][1])
                merged_config["ports"] = list(range(start, end + 1))
            except (ValueError, TypeError):
                logging.warning("Invalid port range, using default ports")
    
    # Handle max_workers
    if "max_workers" in config:
        try:
            merged_config["max_workers"] = int(config["max_workers"])
        except (ValueError, TypeError):
            logging.warning(f"Invalid max_workers value, using default: {default_config['max_workers']}")
    
    return merged_config


def run(target: str, config: Optional[Dict] = None) -> Dict:
    """
    Execute port scan on target
    
    Args:
        target: Domain name or IP address
        config: Optional configuration dictionary
                {
                    "timeout": float (seconds),
                    "ports": list or tuple(start, end),
                    "max_workers": int
                }
    
    Returns:
        Dictionary containing scan results:
        {
            "port_scan": {
                "resolved_ip": str,
                "scan_type": str,
                "open_ports": [
                    {"port": int, "service": str},
                    ...
                ],
                "scan_time": str,
                "error": str (only if error occurred)
            }
        }
    """
    logging.info(f"Starting port scan for target: {target}")
    
    # Parse configuration
    scan_config = _parse_config(config)
    
    # Resolve target to IP
    resolved_ip = _resolve_target(target)
    
    if resolved_ip is None:
        return {
            "port_scan": {
                "resolved_ip": None,
                "scan_type": scan_config["scan_type"],
                "open_ports": [],
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": f"Failed to resolve target: {target}"
            }
        }
    
    # Prepare result structure
    open_ports = []
    
    try:
        # Perform threaded port scanning
        with ThreadPoolExecutor(max_workers=scan_config["max_workers"]) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(_scan_port, resolved_ip, port, scan_config["timeout"]): port
                for port in scan_config["ports"]
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result is not None:
                        open_ports.append({
                            "port": result,
                            "service": _get_service_name(result)
                        })
                except Exception as e:
                    logging.error(f"Error scanning port {port}: {e}")
        
        # Sort results by port number
        open_ports.sort(key=lambda x: x["port"])
        
        logging.info(f"Port scan completed. Found {len(open_ports)} open ports")
        
        return {
            "port_scan": {
                "resolved_ip": resolved_ip,
                "scan_type": scan_config["scan_type"],
                "open_ports": open_ports,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
    except KeyboardInterrupt:
        logging.warning("Port scan interrupted by user")
        return {
            "port_scan": {
                "resolved_ip": resolved_ip,
                "scan_type": scan_config["scan_type"],
                "open_ports": open_ports,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": "Scan interrupted by user"
            }
        }
    except Exception as e:
        logging.error(f"Unexpected error during port scan: {e}")
        return {
            "port_scan": {
                "resolved_ip": resolved_ip,
                "scan_type": scan_config["scan_type"],
                "open_ports": open_ports,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e)
            }
        }