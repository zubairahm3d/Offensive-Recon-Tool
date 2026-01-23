#!/usr/bin/env python3
"""
Technology Detection Module
Advanced web technology fingerprinting using multiple methods
Author: Sibghat Ullah
Date: January 2025
"""

import requests
import re
import json
from typing import Dict, List, Set
from urllib.parse import urlparse

# Try to import Wappalyzer
try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    print("[!] Wappalyzer not available. Install with: pip install python-Wappalyzer")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("[!] BeautifulSoup not available. Install with: pip install beautifulsoup4")


class TechnologyDetector:
    """
    Advanced technology detection using multiple methods:
    1. Wappalyzer (comprehensive database)
    2. HTTP Headers analysis
    3. HTML content parsing
    4. JavaScript library detection
    5. Meta tags analysis
    6. Cookie analysis
    """
    
    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self.technologies = {
            'web_server': [],
            'programming_languages': [],
            'frameworks': [],
            'cms': [],
            'javascript_libraries': [],
            'analytics': [],
            'cdn': [],
            'databases': [],
            'security': [],
            'all_detected': set()
        }
        
    def detect_all(self) -> Dict:
        """Run all detection methods"""
        print(f"\n[*] Starting technology detection for {self.target}")
        
        # Try to fetch the webpage
        url, response = self._fetch_webpage()
        if not response:
            return {'error': 'Failed to fetch webpage'}
        
        print(f"[+] Successfully fetched {url}")
        
        # Method 1: Wappalyzer (most comprehensive)
        if WAPPALYZER_AVAILABLE:
            wappalyzer_results = self._detect_with_wappalyzer(url, response)
            print(f"[+] Wappalyzer detected: {len(wappalyzer_results)} technologies")
        
        # Method 2: HTTP Headers
        header_results = self._analyze_headers(response)
        print(f"[+] Header analysis found: {len(header_results)} indicators")
        
        # Method 3: HTML Content
        html_results = self._analyze_html_content(response.text)
        print(f"[+] HTML analysis found: {len(html_results)} technologies")
        
        # Method 4: JavaScript Libraries
        js_results = self._detect_javascript_libraries(response.text)
        print(f"[+] JavaScript detection found: {len(js_results)} libraries")
        
        # Method 5: Meta Tags
        meta_results = self._analyze_meta_tags(response.text)
        print(f"[+] Meta tag analysis found: {len(meta_results)} indicators")
        
        # Method 6: Cookies
        cookie_results = self._analyze_cookies(response.cookies)
        print(f"[+] Cookie analysis found: {len(cookie_results)} indicators")
        
        # Compile results
        self._compile_results()
        
        return self.technologies
    
    def _fetch_webpage(self) -> tuple:
        """Fetch webpage with proper headers"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{self.target}"
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=15, 
                    allow_redirects=True,
                    verify=False  # For sites with SSL issues
                )
                
                if response.status_code == 200:
                    return url, response
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"[-] Failed with {protocol}: {str(e)}")
                continue
        
        return None, None
    
    def _detect_with_wappalyzer(self, url: str, response) -> Set[str]:
        """Detect technologies using Wappalyzer"""
        if not WAPPALYZER_AVAILABLE:
            return set()
        
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage(url, response.text, response.headers)
            detected = wappalyzer.analyze(webpage)
            
            # Add to all_detected
            self.technologies['all_detected'].update(detected)
            
            return detected
        except Exception as e:
            if self.verbose:
                print(f"[-] Wappalyzer detection failed: {str(e)}")
            return set()
    
    def _analyze_headers(self, response) -> List[str]:
        """Analyze HTTP headers for technology indicators"""
        results = []
        headers = response.headers
        
        # Server header
        if 'Server' in headers:
            server = headers['Server']
            results.append(f"Server: {server}")
            self.technologies['web_server'].append(server)
            self.technologies['all_detected'].add(server.split('/')[0])
        
        # X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            results.append(f"Powered-By: {powered_by}")
            self.technologies['programming_languages'].append(powered_by)
            self.technologies['all_detected'].add(powered_by.split('/')[0])
        
        # X-AspNet-Version
        if 'X-AspNet-Version' in headers:
            aspnet = headers['X-AspNet-Version']
            results.append(f"ASP.NET: {aspnet}")
            self.technologies['frameworks'].append(f"ASP.NET {aspnet}")
            self.technologies['all_detected'].add('ASP.NET')
        
        # X-Generator
        if 'X-Generator' in headers:
            generator = headers['X-Generator']
            results.append(f"Generator: {generator}")
            self.technologies['cms'].append(generator)
            self.technologies['all_detected'].add(generator)
        
        # CDN Detection from headers
        cdn_headers = {
            'CF-RAY': 'Cloudflare',
            'X-Amz-Cf-Id': 'Amazon CloudFront',
            'X-Cache': 'Varnish/CDN',
            'X-CDN': 'CDN'
        }
        
        for header, cdn_name in cdn_headers.items():
            if header in headers:
                results.append(f"CDN: {cdn_name}")
                self.technologies['cdn'].append(cdn_name)
                self.technologies['all_detected'].add(cdn_name)
        
        return results
    
    def _analyze_html_content(self, html: str) -> List[str]:
        """Analyze HTML content for technology signatures"""
        results = []
        html_lower = html.lower()
        
        # CMS Detection
        cms_patterns = {
            'WordPress': [
                '/wp-content/',
                '/wp-includes/',
                'wp-json',
                'wordpress'
            ],
            'Joomla': [
                '/components/com_',
                'joomla',
                '/media/jui/'
            ],
            'Drupal': [
                'drupal',
                '/sites/default/',
                'drupal.js'
            ],
            'Magento': [
                'magento',
                '/skin/frontend/',
                'mage/cookies'
            ],
            'Shopify': [
                'shopify',
                'cdn.shopify.com',
                'shopify-buy'
            ],
            'Wix': [
                'wix.com',
                'wixstatic.com',
                'parastorage.com'
            ],
            'Squarespace': [
                'squarespace',
                'static1.squarespace.com'
            ],
            'Ghost': [
                'ghost.io',
                'content/themes/'
            ]
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in html_lower for pattern in patterns):
                results.append(f"CMS: {cms}")
                self.technologies['cms'].append(cms)
                self.technologies['all_detected'].add(cms)
        
        # Framework Detection
        framework_patterns = {
            'Django': ['csrftoken', '__admin_media_prefix__'],
            'Ruby on Rails': ['csrf-param', 'rails', 'action="/rails/'],
            'Laravel': ['laravel', 'laravel_session', 'csrf-token'],
            'Flask': ['werkzeug'],
            'Express.js': ['x-powered-by: express'],
            'Spring': ['jsessionid', 'spring'],
            'ASP.NET': ['__viewstate', '__eventvalidation'],
            'Phoenix': ['phoenix', '_csrf_token'],
            'Symfony': ['symfony', 'sf-toolbar'],
            'CodeIgniter': ['codeigniter', 'ci_session']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in html_lower for pattern in patterns):
                results.append(f"Framework: {framework}")
                self.technologies['frameworks'].append(framework)
                self.technologies['all_detected'].add(framework)
        
        return results
    
    def _detect_javascript_libraries(self, html: str) -> List[str]:
        """Detect JavaScript libraries and frameworks"""
        results = []
        html_lower = html.lower()
        
        js_libraries = {
            # Frontend Frameworks
            'React': ['react.js', 'react.min.js', 'react-dom', '_react'],
            'Vue.js': ['vue.js', 'vue.min.js', 'vuejs', '__vue__'],
            'Angular': ['angular.js', 'angular.min.js', 'ng-', '@angular'],
            'Svelte': ['svelte', '_svelte'],
            'Ember.js': ['ember.js', 'ember.min.js'],
            
            # JavaScript Libraries
            'jQuery': ['jquery.min.js', 'jquery.js', 'jquery-'],
            'Lodash': ['lodash.js', 'lodash.min.js'],
            'Underscore.js': ['underscore.js', 'underscore.min.js'],
            'Moment.js': ['moment.js', 'moment.min.js'],
            'Axios': ['axios.js', 'axios.min.js'],
            
            # CSS Frameworks
            'Bootstrap': ['bootstrap.js', 'bootstrap.min.js', 'bootstrap.css'],
            'Tailwind CSS': ['tailwind.css', 'tailwindcss'],
            'Foundation': ['foundation.js', 'foundation.css'],
            'Bulma': ['bulma.css', 'bulma.min.css'],
            'Materialize': ['materialize.js', 'materialize.css'],
            
            # Charting Libraries
            'Chart.js': ['chart.js', 'chart.min.js'],
            'D3.js': ['d3.js', 'd3.min.js'],
            'Highcharts': ['highcharts.js'],
            'Plotly': ['plotly.js'],
            
            # Other Popular Libraries
            'Three.js': ['three.js', 'three.min.js'],
            'GSAP': ['gsap.js', 'gsap.min.js'],
            'Anime.js': ['anime.js', 'anime.min.js'],
            'AOS': ['aos.js', 'aos.css'],
            'Swiper': ['swiper.js', 'swiper.css'],
            'Slick': ['slick.js', 'slick.css']
        }
        
        for library, patterns in js_libraries.items():
            if any(pattern in html_lower for pattern in patterns):
                results.append(library)
                self.technologies['javascript_libraries'].append(library)
                self.technologies['all_detected'].add(library)
        
        return results
    
    def _analyze_meta_tags(self, html: str) -> List[str]:
        """Analyze meta tags for technology indicators"""
        results = []
        
        if not BS4_AVAILABLE:
            return results
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                gen_content = generator.get('content')
                results.append(f"Generator: {gen_content}")
                self.technologies['cms'].append(gen_content)
                self.technologies['all_detected'].add(gen_content.split()[0])
            
            # Analytics detection from meta tags
            analytics_patterns = {
                'Google Analytics': ['google-analytics', 'ga.js', 'gtag.js'],
                'Google Tag Manager': ['googletagmanager.com/gtm.js'],
                'Facebook Pixel': ['facebook.com/tr', 'fbq('],
                'Hotjar': ['hotjar.com/c/hotjar-']
            }
            
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '').lower()
                for analytics, patterns in analytics_patterns.items():
                    if any(pattern in src for pattern in patterns):
                        results.append(f"Analytics: {analytics}")
                        self.technologies['analytics'].append(analytics)
                        self.technologies['all_detected'].add(analytics)
        
        except Exception as e:
            if self.verbose:
                print(f"[-] Meta tag analysis failed: {str(e)}")
        
        return results
    
    def _analyze_cookies(self, cookies) -> List[str]:
        """Analyze cookies for technology indicators"""
        results = []
        
        cookie_patterns = {
            'PHP': ['phpsessid'],
            'ASP.NET': ['asp.net_sessionid', 'aspxauth'],
            'Java/JSP': ['jsessionid'],
            'Laravel': ['laravel_session'],
            'Django': ['sessionid', 'csrftoken'],
            'Express.js': ['connect.sid'],
            'ColdFusion': ['cfid', 'cftoken']
        }
        
        cookie_names = [cookie.name.lower() for cookie in cookies]
        
        for tech, patterns in cookie_patterns.items():
            if any(pattern in ' '.join(cookie_names) for pattern in patterns):
                results.append(f"Cookie indicator: {tech}")
                self.technologies['programming_languages'].append(tech)
                self.technologies['all_detected'].add(tech)
        
        return results
    
    def _compile_results(self):
        """Compile and clean up results"""
        # Remove duplicates
        for key in self.technologies:
            if isinstance(self.technologies[key], list):
                self.technologies[key] = list(set(self.technologies[key]))
        
        # Convert set to sorted list
        self.technologies['all_detected'] = sorted(list(self.technologies['all_detected']))
    
    def print_results(self):
        """Print formatted results"""
        print("\n" + "="*60)
        print("TECHNOLOGY DETECTION RESULTS")
        print("="*60)
        
        categories = {
            'web_server': '🖥️  Web Servers',
            'programming_languages': '💻 Programming Languages',
            'frameworks': '🔧 Frameworks',
            'cms': '📝 Content Management Systems',
            'javascript_libraries': '📚 JavaScript Libraries',
            'analytics': '📊 Analytics',
            'cdn': '🌐 CDN/Caching',
            'databases': '💾 Databases',
            'security': '🔒 Security'
        }
        
        for key, title in categories.items():
            if self.technologies[key]:
                print(f"\n{title}:")
                for tech in self.technologies[key]:
                    print(f"  • {tech}")
        
        if self.technologies['all_detected']:
            print(f"\n🎯 All Detected Technologies ({len(self.technologies['all_detected'])}):")
            for i, tech in enumerate(self.technologies['all_detected'], 1):
                print(f"  {i}. {tech}")
        
        print("\n" + "="*60)
    
    def to_json(self) -> str:
        """Export results as JSON"""
        # Convert set to list for JSON serialization
        export_data = self.technologies.copy()
        export_data['all_detected'] = sorted(list(export_data['all_detected']))
        return json.dumps(export_data, indent=2)
    
    def to_dict(self) -> Dict:
        """Return results as dictionary"""
        result = self.technologies.copy()
        result['all_detected'] = sorted(list(result['all_detected']))
        return result


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python tech_detector.py <target_domain>")
        print("Example: python tech_detector.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Create detector instance
    detector = TechnologyDetector(target, verbose=True)
    
    # Run detection
    results = detector.detect_all()
    
    # Print results
    detector.print_results()
    
    # Save to file
    with open(f'tech_detection_{target}.json', 'w') as f:
        f.write(detector.to_json())
    
    print(f"\n[+] Results saved to: tech_detection_{target}.json")
