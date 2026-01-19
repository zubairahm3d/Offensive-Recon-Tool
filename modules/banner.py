"""
Banner Grabbing Module
Service fingerprinting through banner analysis
"""

import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

# Common ports for banner grabbing
BANNER_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080]


def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[Dict]:
    """
    Grab banner from a specific port
    
    Args:
        ip: Target IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary with port and banner info, or None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # Connect to the port
        result = sock.connect_ex((ip, port))
        
        if result != 0:
            return None
        
        logging.debug(f"Connected to {ip}:{port}, attempting banner grab")
        
        # Try to receive banner (some services send it immediately)
        banner = None
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            # If no immediate banner, try sending a generic request
            pass
        
        # If no banner received, try sending HTTP request for web servers
        if not banner and port in [80, 443, 8080, 8443]:
            try:
                http_request = b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
                sock.send(http_request)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
        
        # If still no banner, try generic probe
        if not banner:
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
        
        if banner:
            # Clean up banner (limit length)
            banner = banner[:500] if len(banner) > 500 else banner
            logging.info(f"Banner grabbed from {ip}:{port}")
            
            return {
                "port": port,
                "banner": banner,
                "service": _identify_service(banner, port)
            }
        else:
            logging.debug(f"No banner received from {ip}:{port}")
            return None
            
    except socket.timeout:
        logging.debug(f"Timeout connecting to {ip}:{port}")
        return None
    except socket.error as e:
        logging.debug(f"Socket error on {ip}:{port}: {e}")
        return None
    except Exception as e:
        logging.debug(f"Error grabbing banner from {ip}:{port}: {e}")
        return None
    finally:
        sock.close()


def _identify_service(banner: str, port: int) -> str:
    """
    Identify service based on banner content
    
    Args:
        banner: Banner string
        port: Port number
        
    Returns:
        Identified service name
    """
    banner_lower = banner.lower()
    
    # Web servers
    if 'apache' in banner_lower:
        return 'Apache HTTP Server'
    elif 'nginx' in banner_lower:
        return 'Nginx'
    elif 'microsoft-iis' in banner_lower or 'iis' in banner_lower:
        return 'Microsoft IIS'
    elif 'lighttpd' in banner_lower:
        return 'lighttpd'
    
    # SSH
    elif 'ssh' in banner_lower:
        if 'openssh' in banner_lower:
            return 'OpenSSH'
        return 'SSH Server'
    
    # FTP
    elif 'ftp' in banner_lower:
        if 'vsftpd' in banner_lower:
            return 'vsftpd'
        elif 'proftpd' in banner_lower:
            return 'ProFTPD'
        return 'FTP Server'
    
    # Mail servers
    elif 'smtp' in banner_lower or 'mail' in banner_lower:
        if 'postfix' in banner_lower:
            return 'Postfix'
        elif 'exim' in banner_lower:
            return 'Exim'
        return 'Mail Server'
    
    # Databases
    elif 'mysql' in banner_lower:
        return 'MySQL'
    elif 'postgresql' in banner_lower or 'postgres' in banner_lower:
        return 'PostgreSQL'
    elif 'redis' in banner_lower:
        return 'Redis'
    elif 'mongodb' in banner_lower or 'mongo' in banner_lower:
        return 'MongoDB'
    
    # Default to unknown with port hint
    else:
        port_hints = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy'
        }
        return port_hints.get(port, 'Unknown')


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


def run(target: str, ports: Optional[List[int]] = None, timeout: float = 3.0, max_workers: int = 10) -> Dict:
    """
    Execute banner grabbing on target
    
    Args:
        target: Domain name or IP address
        ports: List of ports to grab banners from (default: common ports)
        timeout: Connection timeout in seconds
        max_workers: Maximum concurrent threads
    
    Returns:
        Dictionary containing banner grabbing results:
        {
            "banner_grab": {
                "target": str,
                "resolved_ip": str,
                "banners": [
                    {
                        "port": int,
                        "banner": str,
                        "service": str
                    },
                    ...
                ],
                "scan_time": str,
                "error": str (only if error occurred)
            }
        }
    """
    logging.info(f"Starting banner grabbing for target: {target}")
    
    # Use default ports if not specified
    if ports is None:
        ports = BANNER_PORTS
    
    # Resolve target to IP
    resolved_ip = _resolve_target(target)
    
    if resolved_ip is None:
        return {
            "banner_grab": {
                "target": target,
                "resolved_ip": None,
                "banners": [],
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": f"Failed to resolve target: {target}"
            }
        }
    
    # Collect banners
    banners = []
    
    try:
        # Perform threaded banner grabbing
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all banner grab tasks
            future_to_port = {
                executor.submit(_grab_banner, resolved_ip, port, timeout): port
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result is not None:
                        banners.append(result)
                except Exception as e:
                    logging.error(f"Error grabbing banner from port {port}: {e}")
        
        # Sort results by port number
        banners.sort(key=lambda x: x["port"])
        
        logging.info(f"Banner grabbing completed. Grabbed {len(banners)} banners")
        
        return {
            "banner_grab": {
                "target": target,
                "resolved_ip": resolved_ip,
                "banners": banners,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
    except KeyboardInterrupt:
        logging.warning("Banner grabbing interrupted by user")
        return {
            "banner_grab": {
                "target": target,
                "resolved_ip": resolved_ip,
                "banners": banners,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": "Scan interrupted by user"
            }
        }
    except Exception as e:
        logging.error(f"Unexpected error during banner grabbing: {e}")
        return {
            "banner_grab": {
                "target": target,
                "resolved_ip": resolved_ip,
                "banners": banners,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e)
            }
        }


if __name__ == "__main__":
    import sys
    
    # Simple CLI for testing
    if len(sys.argv) < 2:
        print("Usage: python banner.py <target> [ports]")
        print("Example: python banner.py example.com")
        print("Example: python banner.py example.com 80,443,8080")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = None
    
    if len(sys.argv) > 2:
        ports = [int(p.strip()) for p in sys.argv[2].split(',')]
    
    # Setup basic logging
    logging.basicConfig(level=logging.INFO)
    
    # Run banner grabbing
    results = run(target, ports=ports)
    
    # Print results
    banner_data = results['banner_grab']
    print(f"\nTarget: {banner_data['target']}")
    print(f"IP: {banner_data['resolved_ip']}")
    print(f"\nBanners found: {len(banner_data['banners'])}\n")
    
    for banner_info in banner_data['banners']:
        print(f"Port {banner_info['port']} - {banner_info['service']}")
        print(f"Banner: {banner_info['banner'][:100]}...")
        print()

