"""
Main entry point for Port Scanner Module
Handles CLI arguments, logging, and file saving
Module itself remains silent and reusable
"""

import sys
import os
import logging
import argparse
import json
from datetime import datetime
from modules import portscan_module


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


def generate_filename(prefix: str = "portscan", extension: str = "json"):
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
    
    # Text format - clean and simple
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


def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Port Scanner Module - Silent worker for reconnaissance framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py 192.168.1.1 -p 1-1000
  python main.py example.com -p 80,443,8080
  python main.py example.com -t 2 -w 100
  python main.py example.com -f json -o custom_name
  python main.py example.com -v
        """
    )
    
    parser.add_argument(
        "target",
        help="Target domain name or IP address"
    )
    
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan: '80,443,8080' or '1-1000' (default: common ports)",
        default=None
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        help="Connection timeout in seconds (default: 1.5)",
        default=1.5
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        help="Maximum concurrent threads (default: 50)",
        default=50
    )
    
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


def main():
    """
    Main execution function
    Simple wrapper around the silent module
    """
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Build configuration
    config = {
        "timeout": args.timeout,
        "max_workers": args.workers
    }
    
    # Parse ports if provided
    if args.ports:
        config["ports"] = parse_ports(args.ports)
    
    # Run port scan (module is silent)
    try:
        logging.info(f"Starting port scan: {args.target}")
        results = portscan_module.run(args.target, config)
        
        # Add target to results for display
        results["port_scan"]["target"] = args.target
        
        # Save results automatically
        saved_path = save_results(results, args.output)
        
        # Print results
        print_results(results, args.format)
        
        if saved_path and args.format == "text":
            print(f"[+] Results saved to: {saved_path}\n")
        
        # Exit with appropriate code
        scan_data = results.get("port_scan", {})
        if "error" in scan_data:
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()