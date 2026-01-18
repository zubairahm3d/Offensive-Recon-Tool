# Port Scanner Module

A modular TCP port scanning tool designed to be used as part of a reconnaissance or security assessment framework.
The scanner is built with clean separation between core logic and user interaction, making it easy to reuse, extend, and integrate into larger tools.

This project was developed with a focus on clarity, reliability, and professional software structure rather than raw exploitation features.

---

## Overview

This port scanner follows a **module-first design**.
The scanning engine runs silently and only returns structured data. All user interaction, logging, and file handling is managed by a separate CLI wrapper.

This approach allows the scanner to be:

* Used as a standalone CLI tool
* Imported into other reconnaissance modules
* Extended later with features like banner grabbing or service enumeration

---

## Project Structure

```
port-scanner/
│
├── main.py
│   CLI wrapper responsible for:
│   - Argument parsing
│   - Logging
│   - Output formatting
│   - Saving results
│
├── modules/
│   ├── __init__.py
│   └── portscan_module.py
│       Core scanning logic (silent worker)
│
├── Results/
│   Automatically created directory for scan outputs
│
└── README.md
```

---

## Design Principles

* **Separation of concerns**
  Scanning logic is fully independent from input/output handling.

* **Silent module behavior**
  The core module never prints, prompts, or writes files.

* **Framework-ready**
  Designed to plug into a larger reconnaissance workflow.

* **Readable and maintainable code**
  Clear structure, consistent naming, and defensive error handling.

---

## Features

### Core Capabilities

* TCP connect port scanning
* Domain name resolution to IP
* Multi-threaded scanning using thread pools
* Configurable timeout and concurrency
* Common service identification by port number
* Graceful handling of network errors and invalid targets

### Output and Reporting

* Automatic saving of results to a `Results/` directory
* Timestamped JSON result files
* Human-readable terminal output
* JSON output option for automation and integration

---

## Requirements

* Python 3.7 or newer
* No third-party libraries required
* Works on Windows, Linux, and macOS

---

## Installation

### Windows (PowerShell)

```powershell
cd path\to\port-scanner
python -m venv venv
venv\Scripts\Activate.ps1
pip install --upgrade pip
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Linux / macOS

```bash
cd path/to/port-scanner
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

---

## Usage

### Basic Scan

```bash
python main.py example.com
```

Scans a default set of common ports.

### Scan Specific Ports

```bash
python main.py example.com -p 80,443,8080
```

### Scan a Port Range

```bash
python main.py example.com -p 1-1000
```

### Full TCP Port Scan

```bash
python main.py example.com -p 1-65535
```

Note: Full scans are slow and may trigger security monitoring systems.

---

## Command Line Options

| Option        | Description                  | Default        |
| ------------- | ---------------------------- | -------------- |
| target        | Domain or IP address         | Required       |
| -p, --ports   | Port list or range           | Common ports   |
| -t, --timeout | Connection timeout (seconds) | 1.5            |
| -w, --workers | Concurrent threads           | 50             |
| -f, --format  | Output format (text/json)    | text           |
| -o, --output  | Custom output filename       | Auto-generated |
| -v, --verbose | Enable debug logging         | Disabled       |

---

## Example Output

### Terminal Output

```
[+] Port Scan Results

Target        : example.com
Resolved IP   : 93.184.216.34
Scan Type     : tcp_connect
Scan Time     : 2026-01-18 18:30:45

Open Ports (3):
------------------------------
PORT       SERVICE
------------------------------
22         ssh
80         http
443        https
```

### JSON Output

```json
{
  "port_scan": {
    "target": "example.com",
    "resolved_ip": "93.184.216.34",
    "scan_type": "tcp_connect",
    "open_ports": [
      {"port": 22, "service": "ssh"},
      {"port": 80, "service": "http"},
      {"port": 443, "service": "https"}
    ],
    "scan_time": "2026-01-18 18:30:45"
  }
}
```

---

## Using the Module Programmatically

```python
from modules import portscan_module

results = portscan_module.run("example.com", {
    "ports": (1, 1000),
    "timeout": 2,
    "max_workers": 100
})

open_ports = results["port_scan"]["open_ports"]
```

The module returns structured data and does not print or save anything on its own.

---

## Testing Targets

Safe domains commonly used for testing:

```bash
python main.py scanme.nmap.org
python main.py example.com -p 80,443
python main.py localhost -p 1-1024
```

---

## Performance Notes

* Larger port ranges increase scan time significantly
* Increasing threads improves speed but increases network noise
* Shorter timeouts reduce scan time but may miss filtered ports

Recommended starting point:

```bash
python main.py target.com -p 1-1000 -t 1.5 -w 50
```

---

## Limitations

* TCP scans only (no UDP scanning)
* Service detection is port-based, not banner-based
* Not designed to bypass firewalls or IDS systems

These limitations are intentional for reliability and safe reconnaissance use.

---

## Legal and Ethical Use

Only scan systems that you own or have explicit permission to test.

Unauthorized port scanning may violate:

* Local laws
* Organizational policies
* Terms of service

Use responsibly and ethically.

---

## Author Notes

This project was developed as part of a professional internship to demonstrate:

* Modular software design
* Secure coding practices
* Reconnaissance tooling fundamentals
* Clean documentation and maintainability

---

Version: 1.0.0
Last Updated: January 2026
Python Version: 3.7+
