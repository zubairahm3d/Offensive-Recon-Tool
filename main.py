import sys
import os
import logging
import argparse
import json
from datetime import datetime
from modules import portscan
from modules import subdomains
from modules.dns import DNSModule
from modules import whois
from modules import banner


def setup_logging(verbose: bool = False):
    """
    Configure logging for the application
    
    Args:
        verbose: Enable debug logging if True
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def ensure_results_directory():
    """
    Ensure Results directory exists, create if not
    
    Returns:
        Path to Results directory
    """
    results_dir = os.path.join(os.getcwd(), "Results")
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
        logging.debug(f"Created Results directory: {results_dir}")
    return results_dir


def generate_filename(prefix: str = "scan", extension: str = "json"):
    """
    Generate timestamped filename
    
    Args:
        prefix: Filename prefix
        extension: File extension
        
    Returns:
        Filename string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{prefix}_{timestamp}.{extension}"


def save_results(results: dict, custom_filename: str = None):
    """
    Save results to JSON file in Results directory
    
    Args:
        results: Scan results dictionary
        custom_filename: Custom filename if provided
        
    Returns:
        Path to saved file or None
    """
    results_dir = ensure_results_directory()
    
    if custom_filename:
        filename = custom_filename if custom_filename.endswith('.json') else f"{custom_filename}.json"
    else:
        filename = generate_filename()
    
    filepath = os.path.join(results_dir, filename)
    
    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        logging.info(f"Results saved to: {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Failed to save results: {e}")
        return None


def print_results(results: dict, output_format: str = "text"):
    """
    Print scan results in specified format
    
    Args:
        results: Scan results dictionary
        output_format: Output format ('text' or 'json')
    """
    if output_format == "json":
        print(json.dumps(results, indent=2))
        return
    
    # Text format - handle different result types
    if "port_scan" in results:
        print_portscan_results(results)
    elif "subdomain_enum" in results:
        print_subdomain_results(results)
    elif "dns_enum" in results:
        print_dns_results(results)
    elif "whois_lookup" in results:
        print_whois_results(results)
    elif "banner_grab" in results:
        print_banner_results(results)
    elif "validation" in results:
        validation = results["validation"]
        print("\n[+] TARGET VALIDATION\n")
        print(f"Valid Target : {validation.get('is_valid')}")
        if "error" in validation:
            print(f"Error        : {validation.get('error')}")

def print_portscan_results(results: dict):
    """Print port scan results in text format"""
    scan_data = results.get("port_scan", {})
    
    print("\n[+] Port Scan Results\n")
    print(f"Target        : {scan_data.get('target', 'N/A')}")
    print(f"Resolved IP   : {scan_data.get('resolved_ip', 'N/A')}")
    print(f"Scan Type     : {scan_data.get('scan_type', 'N/A')}")
    print(f"Scan Time     : {scan_data.get('scan_time', 'N/A')}")
    
    if "error" in scan_data:
        print(f"\n[-] ERROR: {scan_data['error']}\n")
        return
    
    open_ports = scan_data.get("open_ports", [])
    
    if not open_ports:
        print(f"\n[-] No open ports found\n")
    else:
        print(f"\nOpen Ports ({len(open_ports)}):")
        print("-" * 30)
        print(f"{'PORT':<10} {'SERVICE':<20}")
        print("-" * 30)
        for port_info in open_ports:
            port = port_info.get("port")
            service = port_info.get("service", "unknown")
            print(f"{port:<10} {service:<20}")
        print()


def print_subdomain_results(results: dict):
    """Print subdomain enumeration results in text format"""
    subdomain_data = results.get("subdomain_enum", {})
    
    print("\n[+] Subdomain Enumeration Results\n")
    print(f"Target Domain : {subdomain_data.get('target', 'N/A')}")
    print(f"Scan Time     : {subdomain_data.get('scan_time', 'N/A')}")
    
    if "error" in subdomain_data:
        print(f"\n[-] ERROR: {subdomain_data['error']}\n")
        return
    
    subdomains_list = subdomain_data.get("subdomains", [])
    
    if not subdomains_list:
        print(f"\n[-] No subdomains found\n")
    else:
        print(f"\nFound {len(subdomains_list)} unique subdomains:")
        print("-" * 50)
        for subdomain in subdomains_list:
            print(f"  {subdomain}")
        print()


def print_dns_results(results: dict):
    """Print DNS enumeration results in text format"""
    dns_data = results.get("dns_enum", {})
    
    print("\n[+] DNS Enumeration Results\n")
    print(f"Target Domain : {dns_data.get('target', 'N/A')}")
    print(f"Scan Time     : {dns_data.get('scan_time', 'N/A')}")
    
    if "error" in dns_data:
        print(f"\n[-] ERROR: {dns_data['error']}\n")
        return
    
    records = dns_data.get("records", {})
    
    if not records:
        print(f"\n[-] No DNS records found\n")
    else:
        print(f"\nDNS Records:")
        print("-" * 50)
        for record_type, values in records.items():
            print(f"\n{record_type}:")
            for value in values:
                print(f"  {value}")
        print()


def print_whois_results(results: dict):
    """Print WHOIS lookup results in text format"""
    whois_data = results.get("whois_lookup", {})
    
    print("\n[+] WHOIS Lookup Results\n")
    print(f"Target Domain : {whois_data.get('target', 'N/A')}")
    print(f"Scan Time     : {whois_data.get('scan_time', 'N/A')}")
    
    if "error" in whois_data:
        print(f"\n[-] ERROR: {whois_data['error']}\n")
        return
    
    whois_info = whois_data.get("whois_data", "")
    if whois_info:
        print("\nWHOIS Information:")
        print("-" * 50)
        print(whois_info)
    else:
        print("\n[-] No WHOIS data available\n")


def print_banner_results(results: dict):
    """Print banner grabbing results in text format"""
    banner_data = results.get("banner_grab", {})
    
    print("\n[+] Banner Grabbing Results\n")
    print(f"Target        : {banner_data.get('target', 'N/A')}")
    print(f"Resolved IP   : {banner_data.get('resolved_ip', 'N/A')}")
    print(f"Scan Time     : {banner_data.get('scan_time', 'N/A')}")
    
    if "error" in banner_data:
        print(f"\n[-] ERROR: {banner_data['error']}\n")
        return
    
    banners_list = banner_data.get("banners", [])
    
    if not banners_list:
        print(f"\n[-] No banners grabbed\n")
    else:
        print(f"\nBanners Grabbed ({len(banners_list)}):")
        print("-" * 80)
        for banner_info in banners_list:
            port = banner_info.get("port")
            service = banner_info.get("service", "Unknown")
            banner_text = banner_info.get("banner", "")
            
            print(f"\nPort {port} - {service}")
            print("-" * 80)
            # Limit banner display to first 200 chars for readability
            if len(banner_text) > 200:
                print(f"{banner_text[:200]}...")
            else:
                print(banner_text)
        print()


def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Offensive Recon Tool - Comprehensive reconnaissance framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Port Scanning:
    python main.py example.com --portscan
    python main.py 192.168.1.1 --portscan -p 1-1000
    python main.py example.com --portscan -p 80,443,8080
  
  Subdomain Enumeration:
    python main.py example.com --subdomains
  
  DNS Enumeration:
    python main.py example.com --dns
    python main.py example.com --dns --dns-types A,MX,NS
  
  WHOIS Lookup:
    python main.py example.com --whois
  
  Banner Grabbing:
    python main.py example.com --banner
    python main.py example.com --banner --portscan
  
  Multiple Modules:
    python main.py example.com --subdomains --dns --portscan
        """
    )
    
    parser.add_argument(
        "target",
        help="Target domain name or IP address"
    )
    
    # Module selection
    parser.add_argument(
        "--portscan",
        action="store_true",
        help="Run port scan module"
    )
    
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Run subdomain enumeration module"
    )
    
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Run DNS enumeration module"
    )
    
    parser.add_argument(
        "--whois",
        action="store_true",
        help="Run WHOIS lookup module"
    )
    
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Run banner grabbing module"
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available modules"
    )
    
    # Port scan specific options
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan: '80,443,8080' or '1-1000' (default: common ports)",
        default=None
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        help="Connection timeout in seconds for port scan (default: 1.5)",
        default=1.5
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        help="Maximum concurrent threads for port scan (default: 50)",
        default=50
    )
    
    # DNS specific options
    parser.add_argument(
        "--dns-types",
        help="DNS record types to query (comma-separated, default: A,AAAA,MX,NS,TXT,SOA,CNAME)",
        default=None
    )
    
    parser.add_argument(
        "--nameserver",
        help="Custom nameserver for DNS queries",
        default=None
    )
    
    # General options
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        help="Output format (default: text)",
        default="text"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Custom filename for results in Results/ folder",
        default=None
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )
    
    return parser.parse_args()

def run_validation(args) -> dict:
    """
    Run target validation (domain/IP checks)
    """
    try:
        from modules import validator
        return validator.run(args)
    except Exception as e:
        return {
            "validation": {
                "is_valid": False,
                "error": str(e),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }

def parse_ports(port_string: str):
    """
    Parse port string into list or range
    
    Args:
        port_string: Port specification (e.g., "80,443" or "1-1000")
        
    Returns:
        List of ports or tuple (start, end) for range
    """
    if not port_string:
        return None
    
    # Check if it's a range
    if "-" in port_string:
        try:
            start, end = port_string.split("-")
            return (int(start.strip()), int(end.strip()))
        except ValueError:
            logging.error(f"Invalid port range: {port_string}")
            sys.exit(1)
    
    # Otherwise, treat as comma-separated list
    try:
        ports = [int(p.strip()) for p in port_string.split(",")]
        return ports
    except ValueError:
        logging.error(f"Invalid port list: {port_string}")
        sys.exit(1)


def run_portscan(target: str, args) -> dict:
    """
    Run port scan module
    
    Args:
        target: Target domain or IP
        args: Parsed command line arguments
        
    Returns:
        Port scan results dictionary
    """
    logging.info(f"Starting port scan: {target}")
    
    config = {
        "timeout": args.timeout,
        "max_workers": args.workers
    }
    
    if args.ports:
        config["ports"] = parse_ports(args.ports)
    
    results = portscan.run(target, config)
    results["port_scan"]["target"] = target
    
    return results


def run_subdomain_enum(target: str) -> dict:
    """
    Run subdomain enumeration module
    
    Args:
        target: Target domain
        
    Returns:
        Subdomain enumeration results dictionary
    """
    logging.info(f"Starting subdomain enumeration: {target}")
    
    try:
        subdomains_list = subdomains.get_subdomains(target)
        
        return {
            "subdomain_enum": {
                "target": target,
                "subdomains": subdomains_list,
                "count": len(subdomains_list),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
    except Exception as e:
        logging.error(f"Subdomain enumeration failed: {e}")
        return {
            "subdomain_enum": {
                "target": target,
                "error": str(e),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }


def run_dns_enum(target: str, args) -> dict:
    """
    Run DNS enumeration module
    
    Args:
        target: Target domain
        args: Parsed command line arguments
        
    Returns:
        DNS enumeration results dictionary
    """
    logging.info(f"Starting DNS enumeration: {target}")
    
    try:
        dns_module = DNSModule(nameserver=args.nameserver)
        
        dns_types = None
        if args.dns_types:
            dns_types = [t.strip().upper() for t in args.dns_types.split(",")]
        
        records = dns_module.run(target, types=dns_types)
        
        return {
            "dns_enum": {
                "target": target,
                "records": records,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
    except Exception as e:
        logging.error(f"DNS enumeration failed: {e}")
        return {
            "dns_enum": {
                "target": target,
                "error": str(e),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }


def run_whois_lookup(target: str) -> dict:
    """
    Run WHOIS lookup module
    
    Args:
        target: Target domain
        
    Returns:
        WHOIS lookup results dictionary
    """
    logging.info(f"Starting WHOIS lookup: {target}")
    
    try:
        import subprocess
        
        # Run whois command
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return {
                "whois_lookup": {
                    "target": target,
                    "whois_data": result.stdout,
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
        else:
            return {
                "whois_lookup": {
                    "target": target,
                    "error": f"WHOIS command failed: {result.stderr}",
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
    except FileNotFoundError:
        logging.error("WHOIS command not found. Please install whois utility.")
        return {
            "whois_lookup": {
                "target": target,
                "error": "WHOIS command not found on system",
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }
    except Exception as e:
        logging.error(f"WHOIS lookup failed: {e}")
        return {
            "whois_lookup": {
                "target": target,
                "error": str(e),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }


def run_banner_grab(target: str, args) -> dict:
    """
    Run banner grabbing module
    
    Args:
        target: Target domain or IP
        args: Parsed command line arguments
        
    Returns:
        Banner grabbing results dictionary
    """
    logging.info(f"Starting banner grabbing: {target}")
    
    try:
        # Use ports from port scan if available, otherwise use default banner ports
        ports = None
        if args.ports:
            ports = parse_ports(args.ports)
            if isinstance(ports, tuple):
                # Convert range to list
                ports = list(range(ports[0], ports[1] + 1))
        
        results = banner.run(
            target,
            ports=ports,
            timeout=args.timeout,
            max_workers=min(args.workers, 20)  # Limit workers for banner grabbing
        )
        
        return results
    except Exception as e:
        logging.error(f"Banner grabbing failed: {e}")
        return {
            "banner_grab": {
                "target": target,
                "error": str(e),
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        }


def main():
    """
    Main execution function
    Orchestrates multiple reconnaissance modules
    """
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Determine which modules to run
    run_all = args.all
    modules_to_run = []
    
    if run_all or args.portscan:
        modules_to_run.append("portscan")
    if run_all or args.subdomains:
        modules_to_run.append("subdomains")
    if run_all or args.dns:
        modules_to_run.append("dns")
    if run_all or args.whois:
        modules_to_run.append("whois")
    if run_all or args.banner:
        modules_to_run.append("banner")
    
    # If no modules specified, default to port scan (backward compatibility)
    if not modules_to_run:
        modules_to_run.append("portscan")
    
    logging.info(f"Target: {args.target}")
    logging.info(f"Modules to run: {', '.join(modules_to_run)}")
    
    # Run modules and collect results
    all_results = {}
    validation_result = run_validation(args)
    all_results["validation"] = validation_result

    if not validation_result.get("valid", False):
        logging.error("Target validation failed. Exiting.")
        print_results(validation_result, args.format)
        sys.exit(1)

    has_error = False
    
    try:
        for module_name in modules_to_run:
            try:
                if module_name == "portscan":
                    results = run_portscan(args.target, args)
                    all_results.update(results)
                    
                elif module_name == "subdomains":
                    results = run_subdomain_enum(args.target)
                    all_results.update(results)
                    
                elif module_name == "dns":
                    results = run_dns_enum(args.target, args)
                    all_results.update(results)
                    
                elif module_name == "whois":
                    results = run_whois_lookup(args.target)
                    all_results.update(results)
                    
                elif module_name == "banner":
                    results = run_banner_grab(args.target, args)
                    all_results.update(results)
                
                # Check for errors in this module
                for key in results:
                    if "error" in results[key]:
                        has_error = True
                        
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logging.error(f"Error running {module_name}: {e}")
                has_error = True
        
        # Save all results to file
        if all_results:
            # Generate appropriate prefix for filename
            prefix = "recon"
            if len(modules_to_run) == 1:
                prefix = modules_to_run[0]
            
            if args.output:
                saved_path = save_results(all_results, args.output)
            else:
                custom_name = generate_filename(prefix=prefix)
                saved_path = save_results(all_results, custom_name)
            
            # Print results for each module
            for module_name in modules_to_run:
                module_key_map = {
                    "portscan": "port_scan",
                    "subdomains": "subdomain_enum",
                    "dns": "dns_enum",
                    "whois": "whois_lookup",
                    "banner": "banner_grab"
                }
                
                module_key = module_key_map.get(module_name)
                if module_key and module_key in all_results:
                    module_results = {module_key: all_results[module_key]}
                    print_results(module_results, args.format)
            
            if saved_path and args.format == "text":
                print(f"[+] All results saved to: {saved_path}\n")
        
        # Exit with appropriate code
        if has_error:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":

    main()


