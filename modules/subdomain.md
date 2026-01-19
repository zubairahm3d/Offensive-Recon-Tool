# Subdomain Enumeration Module

**Status:** Ready for Merge  
**Module Path:** `subdomain_module/subdomains.py`

## Overview
This branch adds the `subdomains` module. It performs passive reconnaissance using public APIs (HackerTarget & crt.sh) to find subdomains without alerting the target.

## Setup for the Team
1. **Merge this branch** into main.
2. The file `subdomains.py` will automatically be placed inside the `subdomain_module` folder.
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
## Integration guide
Add this to main.py
```python
from subdomain_module.subdomains import get_subdomains
```
Add this where you handle the --subdomains argument:
```python
if args.subdomains:
        target = args.subdomains
        print(f"[*] Enumerating subdomains for: {target}")
        
        # call module
        found_list = get_subdomains(target)
        
        if found_list:
            print(f"[+] Found {len(found_list)} unique subdomains.")
            # Pass 'found_list' to the next tool (e.g., Live Check or Port Scanner)
        else:
            print("[-] No subdomains found.")
```
How to test manually:

```python
#run frm project root
python subdomain_module/subdomains.py tesla.com  #example domain
```

