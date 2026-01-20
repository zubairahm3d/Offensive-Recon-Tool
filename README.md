# Offensive Recon Tool

A simple reconnaissance tool for gathering information about target domains and IP addresses.

## Requirements

- Python 3.7+
- `whois` command (pre-installed on most Linux systems)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Command Structure

```bash
python main.py <target> [module flags] [options]
```

### Available Modules

| Module | Flag | Description |
|--------|------|-------------|
| Port Scan | `--portscan` | Scan for open ports |
| Subdomain Enum | `--subdomains` | Find subdomains |
| DNS Lookup | `--dns` | Query DNS records |
| WHOIS Lookup | `--whois` | Get domain registration info |
| Banner Grabbing | `--banner` | Grab service banners |
| All Modules | `--all` | Run everything |

## Quick Examples

### Port Scanning

```bash
# Scan common ports
python main.py example.com --portscan

# Scan specific ports
python main.py example.com --portscan -p 80,443,8080

# Scan port range
python main.py example.com --portscan -p 1-1000
```

### Subdomain Enumeration

```bash
python main.py example.com --subdomains
```

### DNS Enumeration

```bash
# All DNS records
python main.py example.com --dns

# Specific record types
python main.py example.com --dns --dns-types A,MX,NS
```

### WHOIS Lookup

```bash
python main.py example.com --whois
```

### Banner Grabbing

```bash
# Grab banners from default ports
python main.py example.com --banner

# Grab banners from specific ports
python main.py example.com --banner -p 80,443,8080

# Combine with port scan
python main.py example.com --portscan --banner -p 1-1000
```

### Run Multiple Modules

```bash
# DNS + Port Scan
python main.py example.com --dns --portscan -p 80,443

# Port Scan + Banner Grabbing
python main.py example.com --portscan --banner -p 80,443,8080

# Everything
python main.py example.com --all
```

## Common Options

| Option | Description |
|--------|-------------|
| `-p, --ports` | Ports to scan (e.g., `80,443` or `1-1000`) |
| `-t, --timeout` | Connection timeout in seconds (default: 1.5) |
| `-w, --workers` | Max threads for port scan (default: 50) |
| `-f, --format` | Output format: `text` , `json` or 'html' (default: text) |
| `-o, --output` | Custom filename for results |
| `-v, --verbose` | Enable verbose logging |

## Output

Results are automatically saved to the `Results/` directory with timestamps and if save in html it will also be saved in 'reports'/ directory.

```bash
Results/
├── portscan_2026-01-19_13-24-28.json
├── dns_2026-01-19_13-25-20.json
└── recon_2026-01-19_13-24-50.json
reports/
└── google.com_2026_10_20_13_45.html
```

## Examples

```bash
# Quick web server check
python main.py target.com --portscan -p 80,443,8080,8443

# Web server fingerprinting
python main.py target.com --portscan --banner -p 80,443,8080

# Full reconnaissance
python main.py target.com --all -o full_scan

# JSON output for automation
python main.py target.com --dns -f json

# Verbose mode for debugging
python main.py target.com --portscan -v
```

## Default Behavior

If no module flags are specified, port scan runs by default:

```bash
# These are equivalent
python main.py example.com -p 80,443
python main.py example.com --portscan -p 80,443
```

