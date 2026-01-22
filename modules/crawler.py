import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import shutil
import subprocess
import json

import os

def check_katana():
    """Check if katana is installed and available in PATH or default Go bin. Returns path or None."""
    if shutil.which("katana") is not None:
        return "katana"
        
    # Check default Go bin path on Windows
    home = os.path.expanduser("~")
    go_bin = os.path.join(home, "go", "bin", "katana.exe")
    if os.path.exists(go_bin):
        return go_bin
        
    return None

def crawl(target_url, max_depth=2):
    """
    Crawl the target URL to find internal links.
    
    Args:
        target_url (str): The starting URL.
        max_depth (int): Maximum recursion depth.
    
    Returns:
        list: A list of unique internal URLs discovered.
    """
    logging.info(f"Starting crawler on {target_url} with depth {max_depth}")
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"https://{target_url}"
    
    visited = set()
    to_visit = [(target_url, 0)]
    internal_urls = set()
    
    domain = urlparse(target_url).netloc
    
    while to_visit:
        current_url, depth = to_visit.pop(0)
        
        if current_url in visited or depth > max_depth:
            continue
        
        visited.add(current_url)
        
        try:
            # Use tuple timeout (connect, read) and disable SSL verify
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            try:
                response = requests.get(current_url, timeout=(3.05, 10), headers=headers, verify=False)
            except requests.exceptions.Timeout:
                logging.warning(f"Timeout crawling {current_url}")
                continue
            except requests.exceptions.SSLError:
                logging.warning(f"SSL Error crawling {current_url}")
                continue
            except requests.exceptions.RequestException as e:
                logging.debug(f"Request error {current_url}: {e}")
                continue

            if response.status_code != 200:
                continue
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                parsed_url = urlparse(full_url)
                
                # Filter for same domain (allow www variation)
                if (parsed_url.netloc == domain or parsed_url.netloc.endswith(f".{domain}")) and parsed_url.scheme in ['http', 'https']:
                    internal_urls.add(full_url)
                    
                    if full_url not in visited and depth + 1 <= max_depth:
                        to_visit.append((full_url, depth + 1))
                        
        except Exception as e:
            logging.debug(f"Error crawling {current_url}: {e}")
            
    logging.info(f"Crawler finished. Found {len(internal_urls)} internal URLs.")
    return list(internal_urls)

def crawl_with_katana(target_url, max_depth=2):
    """
    Crawl using Katana (headless mode).
    
    Args:
        target_url (str): Starting URL.
        max_depth (int): Recursion depth (mapped to -d).
        
    Returns:
        list: Discovered URLs.
    """
    katana_path = check_katana()
    if not katana_path:
        logging.error("Katana not found. Please install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        raise FileNotFoundError("Katana not found in PATH")
        
    logging.info(f"Starting Katana crawler on {target_url} with depth {max_depth}")
    
    cmd = [
        katana_path,
        "-u", target_url,
        "-d", str(max_depth),
        "-jc",          # Javascript crawling (headless)
        "-kf",          # Keep fragments/params
        "-silent",      # JSON output only if compatible, else plain text
        # "-json"       # JSON output is better for parsing, let's stick to text line parsing for simplicity first or use -json
    ]
    
    internal_urls = set()
    domain = urlparse(target_url if target_url.startswith('http') else f"https://{target_url}").netloc
    
    try:
        # Run katana and capture output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            logging.error(f"Katana failed: {stderr}")
            return []
            
        # Parse output (line by line)
        for line in stdout.splitlines():
            url = line.strip()
            if not url:
                continue
                
            # Filter logic similar to python crawler (same domain)
            parsed_url = urlparse(url)
            if (parsed_url.netloc == domain or parsed_url.netloc.endswith(f".{domain}")) and parsed_url.scheme in ['http', 'https']:
                internal_urls.add(url)
                
    except Exception as e:
        logging.error(f"Error running Katana: {e}")
        
    logging.info(f"Katana finished. Found {len(internal_urls)} URLs.")
    return list(internal_urls)
