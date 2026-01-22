from urllib.parse import urlparse, parse_qs
import logging

def extract(urls):
    """
    Extract interesting data from a list of URLs.
    
    Args:
        urls (list): List of URLs to analyze.
        
    Returns:
        dict: Dictionary containing 'js_files' and 'parameters'.
    """
    logging.info(f"Starting extraction on {len(urls)} URLs")
    
    js_files = set()
    parameterized_urls = set()
    
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path
        
        # Identify JS files
        if path.endswith('.js'):
            js_files.add(url)
            
        # Identify URLs with parameters
        if parsed.query:
            parameterized_urls.add(url)
            
    logging.info(f"Extraction finished. Found {len(js_files)} JS files and {len(parameterized_urls)} parameterized URLs.")
    
    return {
        'js_files': list(js_files),
        'parameters': list(parameterized_urls)
    }
