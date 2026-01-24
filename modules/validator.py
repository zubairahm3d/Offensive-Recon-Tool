"""
validator.py
Centralized input validation for Offensive Recon Tool
Ensures safe, correct, and consistent inputs before modules execute
"""

import re
import socket
import os
from typing import List, Optional, Tuple, Dict, Union
from urllib.parse import urlparse


# =========================
# Regex Patterns
# =========================

DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)

IP_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

SAFE_FILENAME_REGEX = re.compile(r"[^a-zA-Z0-9._-]")


# =========================
# Basic Validators
# =========================

def is_valid_ip(ip: str) -> bool:
    if not IP_REGEX.match(ip):
        return False
    return all(0 <= int(p) <= 255 for p in ip.split("."))


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))


def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


# =========================
# Target Validation
# =========================

def validate_target(
    target: str,
    domain_only: bool = False
) -> Dict:
    if not target:
        return {"valid": False, "error": "Target cannot be empty"}

    target = target.strip().lower()

    if is_url(target):
        return {"valid": False, "error": "URLs are not allowed as targets"}

    if is_valid_ip(target):
        if domain_only:
            return {"valid": False, "error": "This module requires a domain, not an IP"}
        return {"valid": True, "target": target, "type": "ip"}

    if is_valid_domain(target):
        resolved = resolve_target(target)
        if not resolved:
            return {"valid": False, "error": "Domain could not be resolved"}
        return {
            "valid": True,
            "target": target,
            "type": "domain",
            "resolved_ip": resolved
        }

    return {"valid": False, "error": "Invalid domain or IP format"}


# =========================
# Port Validation
# =========================

def validate_ports(
    ports: Optional[Union[List[int], Tuple[int, int]]]
) -> Dict:
    if ports is None:
        return {"valid": True, "ports": None}

    if isinstance(ports, tuple):
        start, end = ports
        if start < 1 or end > 65535 or start > end:
            return {"valid": False, "error": "Invalid port range"}
        return {"valid": True, "ports": list(range(start, end + 1))}

    if isinstance(ports, list):
        clean = []
        for p in ports:
            if not isinstance(p, int) or p < 1 or p > 65535:
                return {"valid": False, "error": f"Invalid port value: {p}"}
            clean.append(p)
        return {"valid": True, "ports": clean}

    return {"valid": False, "error": "Ports must be a list or range"}


# =========================
# Runtime Options
# =========================

def validate_timeout(timeout: float) -> Dict:
    if not isinstance(timeout, (int, float)):
        return {"valid": False, "error": "Timeout must be numeric"}
    if timeout < 0.5 or timeout > 30:
        return {"valid": False, "error": "Timeout must be between 0.5 and 30 seconds"}
    return {"valid": True, "timeout": float(timeout)}


def validate_workers(workers: int) -> Dict:
    if not isinstance(workers, int):
        return {"valid": False, "error": "Workers must be an integer"}
    if workers < 1 or workers > 200:
        return {"valid": False, "error": "Workers must be between 1 and 200"}
    return {"valid": True, "workers": workers}


# =========================
# DNS Validation
# =========================

ALLOWED_DNS_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"}

def validate_dns_types(types: Optional[List[str]]) -> Dict:
    if not types:
        return {"valid": True, "types": None}

    cleaned = []
    for t in types:
        t = t.upper().strip()
        if t not in ALLOWED_DNS_TYPES:
            return {"valid": False, "error": f"Invalid DNS record type: {t}"}
        cleaned.append(t)

    return {"valid": True, "types": cleaned}


def validate_nameserver(ns: Optional[str]) -> Dict:
    if not ns:
        return {"valid": True, "nameserver": None}

    if not is_valid_ip(ns):
        return {"valid": False, "error": "Nameserver must be a valid IP address"}

    return {"valid": True, "nameserver": ns}


# =========================
# WHOIS Validation
# =========================

def validate_whois_domain(domain: str) -> Dict:
    check = validate_target(domain, domain_only=True)
    if not check["valid"]:
        return check

    if not re.fullmatch(r"[a-zA-Z0-9.-]+", domain):
        return {"valid": False, "error": "Invalid characters in domain"}

    return {"valid": True, "domain": domain}


# =========================
# URL Validation
# =========================
def validate_url_target(target: str) -> Dict:
    """
    Validate and normalize URL for crawler module
    """
    if not target:
        return {"valid": False, "error": "Target URL cannot be empty"}

    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)

    if not parsed.scheme or not parsed.netloc:
        return {"valid": False, "error": "Invalid URL format"}

    return {"valid": True, "url": target, "domain": parsed.netloc}

# =========================
# Crawler Validation
# =========================
def validate_crawler_depth(depth: int) -> Dict:
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        return {"valid": False, "error": "Crawler depth must be an integer"}

    if depth < 1 or depth > 5:
        return {"valid": False, "error": "Crawler depth must be between 1 and 5"}

    return {"valid": True, "depth": depth}

# =========================
# katana Validation
# =========================
def validate_katana(use_katana: bool) -> Dict:
    if not use_katana:
        return {"valid": True}

    try:
        from modules.crawler import check_katana
    except ImportError:
        return {"valid": False, "error": "Crawler module not found"}

    if not check_katana():
        return {
            "valid": False,
            "error": "Katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        }

    return {"valid": True}

# =========================
#Tech_detect Validation
# =========================
def validate_tech_target(domain: str) -> Dict:
    """
    Technology detection only supports DOMAIN (no URL, no IP)
    """
    if is_url(domain):
        return {"valid": False, "error": "Technology detection requires a domain, not a URL"}

    if is_valid_ip(domain):
        return {"valid": False, "error": "Technology detection does not support IP addresses"}

    if not is_valid_domain(domain):
        return {"valid": False, "error": "Invalid domain format for technology detection"}

    resolved = resolve_target(domain)
    if not resolved:
        return {"valid": False, "error": "Domain could not be resolved"}

    return {"valid": True, "domain": domain, "resolved_ip": resolved}


# =========================
# Report Validation
# =========================

def sanitize_filename(value: str) -> str:
    value = SAFE_FILENAME_REGEX.sub("_", value)
    return value.strip("_")


def validate_report_format(fmt: str) -> Dict:
    if fmt not in ("txt", "html", "text", "json"):
        return {"valid": False, "error": "Invalid report format"}
    return {"valid": True, "format": fmt}


# =========================
# Master Validator (Main.py)
# =========================

def validate_main_inputs(args) -> Dict:
    """
    Validate all inputs coming from main.py before execution
    """

    # =========================
    # Module conflict check
    # =========================
    if args.crawler and (args.dns or args.subdomains or args.whois or args.tech_detect):
        return {
            "valid": False,
            "error": "Crawler cannot be combined with DNS, subdomains, WHOIS, or tech-detect"
        }

    # =========================
    # Extractor dependency
    # =========================
    if args.extractor and not args.crawler and not args.all:
        return {
            "valid": False,
            "error": "Extractor requires crawler module"
        }

    # =========================
    # Target Validation (mode-based)
    # =========================
    if args.crawler:
        url_check = validate_url_target(args.target)
        if not url_check["valid"]:
            return url_check

        depth_check = validate_crawler_depth(args.depth)
        if not depth_check["valid"]:
            return depth_check

        katana_check = validate_katana(not args.python_crawler)
        if not katana_check["valid"]:
            return katana_check

    elif args.tech_detect:
        tech_check = validate_tech_target(args.target)
        if not tech_check["valid"]:
            return tech_check

    else:
        needs_domain = args.subdomains or args.dns or args.whois
        target_check = validate_target(args.target, domain_only=needs_domain)
        if not target_check["valid"]:
            return target_check

    # =========================
    # Port scan options
    # =========================
    ports_check = validate_ports(args.ports)
    if not ports_check["valid"]:
        return ports_check

    timeout_check = validate_timeout(args.timeout)
    if not timeout_check["valid"]:
        return timeout_check

    workers_check = validate_workers(args.workers)
    if not workers_check["valid"]:
        return workers_check

    # =========================
    # DNS options
    # =========================
    dns_types_check = validate_dns_types(
        args.dns_types.split(",") if args.dns_types else None
    )
    if not dns_types_check["valid"]:
        return dns_types_check

    ns_check = validate_nameserver(args.nameserver)
    if not ns_check["valid"]:
        return ns_check

    # =========================
    # Output filename
    # =========================
    if args.output:
        args.output = sanitize_filename(args.output)

    return {"valid": True}
