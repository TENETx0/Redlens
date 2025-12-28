#!/usr/bin/env python3
"""
Technology Fingerprinting Module
Performs comprehensive technology stack detection including web servers, frameworks,
CMS, JavaScript libraries, analytics, CDNs, and third-party integrations.
"""

import requests
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, Back
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import hashlib

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class LoadingBar:
    """Animated loading bar for visual feedback"""
    def __init__(self, description="Processing"):
        self.description = description
        self.running = False
        self.thread = None
    
    def animate(self):
        """Animate the loading bar"""
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while self.running:
            sys.stdout.write(f"\r{Fore.CYAN}[{chars[idx % len(chars)]}] {self.description}...{Style.RESET_ALL}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
    
    def start(self):
        """Start the loading animation"""
        self.running = True
        self.thread = Thread(target=self.animate)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, success=True):
        """Stop the loading animation"""
        self.running = False
        if self.thread:
            self.thread.join()
        symbol = f"{Fore.GREEN}✓{Style.RESET_ALL}" if success else f"{Fore.RED}✗{Style.RESET_ALL}"
        sys.stdout.write(f"\r{symbol} {self.description} - {'Complete' if success else 'Failed'}                    \n")
        sys.stdout.flush()

class ProgressBar:
    """Progress bar for scan stages"""
    def __init__(self, total_stages):
        self.total = total_stages
        self.current = 0
    
    def update(self, stage_name):
        """Update progress bar"""
        self.current += 1
        percentage = (self.current / self.total) * 100
        filled = int(percentage / 2)
        bar = "█" * filled + "░" * (50 - filled)
        
        print(f"\n{Fore.YELLOW}{stage_name.center(70)}{Style.RESET_ALL}")
        print(f"[{Fore.GREEN}{bar}{Style.RESET_ALL}] {percentage:.1f}% ({self.current}/{self.total})\n")

class TechnologyFingerprinter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'technologies': {
                'web_servers': [],
                'frontend_frameworks': [],
                'backend_frameworks': [],
                'programming_languages': [],
                'cms': [],
                'javascript_libraries': [],
                'analytics': [],
                'cdn': [],
                'waf': [],
                'databases': [],
                'caching': [],
                'authentication': [],
                'payment': [],
                'devops': [],
                'cloud': [],
                'containers': [],
                'plugins': [],
                'other': []
            },
            'versions': {},
            'confidence_scores': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Get wordlists directory
        self.wordlists_dir = self.get_wordlists_directory()
        
        # Load all wordlists
        self.load_wordlists()
        
        # HTML patterns for technology detection
        self.html_patterns = {
            # Meta tags
            'generator': r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            'og_site_name': r'<meta\s+property=["\']og:site_name["\']\s+content=["\']([^"\']+)["\']',
            'application_name': r'<meta\s+name=["\']application-name["\']\s+content=["\']([^"\']+)["\']',
            
            # Framework signatures
            'ng_version': r'ng-version=["\']([^"\']+)["\']',
            'react_version': r'react@([0-9.]+)',
            'vue_version': r'vue@([0-9.]+)',
            
            # Common libraries in HTML
            'jquery': r'jquery[.-]([0-9.]+)(?:\.min)?\.js',
            'bootstrap': r'bootstrap[.-]([0-9.]+)(?:\.min)?\.(?:js|css)',
            'font_awesome': r'font-awesome[.-]([0-9.]+)',
            
            # CMS specific
            'wordpress': r'wp-(?:content|includes)',
            'drupal': r'sites/(?:default|all)/(?:themes|modules)',
            'joomla': r'/components/com_',
            'magento': r'(?:Mage\.Cookies|Magento)',
            
            # Comments
            'html_comments': r'<!--\s*(.+?)\s*-->',
        }
        
        # JavaScript global variables that indicate technologies
        self.js_globals = [
            'jQuery', 'angular', 'React', 'Vue', 'Ember', 'Backbone',
            'Meteor', 'Polymer', 'Aurelia', 'Svelte', 'Alpine',
            'Next', 'Nuxt', 'Gatsby', 'Remix',
            'WP', 'Drupal', 'Joomla',
            'ga', 'gtag', '_gaq', '_gat', 'analytics',
            'Shopify', 'Wix', 'Squarespace'
        ]
        
        # Cookie patterns
        self.cookie_patterns = {
            'PHP': ['PHPSESSID', 'phpsessid'],
            'ASP.NET': ['ASP.NET_SessionId', 'ASPSESSIONID'],
            'Java': ['JSESSIONID', 'jsessionid'],
            'Django': ['sessionid', 'csrftoken', 'django'],
            'Rails': ['_session_id', '_csrf_token'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'Express': ['connect.sid'],
            'Flask': ['session'],
            'ColdFusion': ['CFID', 'CFTOKEN'],
            'Kentico': ['CMSPreferredCulture'],
            'Shopify': ['_shopify_s', '_shopify_y'],
            'WordPress': ['wordpress_', 'wp-settings'],
            'Magento': ['frontend', 'X-Magento-Vary'],
            'Drupal': ['SSESS', 'SESS'],
        }
        
        # Header-based technology detection
        self.header_technologies = {
            'X-Powered-By': {
                'PHP': r'PHP/?([0-9.]+)?',
                'ASP.NET': r'ASP\.NET',
                'Express': r'Express',
                'Next.js': r'Next\.js',
            },
            'Server': {
                'nginx': r'nginx/?([0-9.]+)?',
                'Apache': r'Apache/?([0-9.]+)?',
                'IIS': r'Microsoft-IIS/?([0-9.]+)?',
                'LiteSpeed': r'LiteSpeed/?([0-9.]+)?',
                'Caddy': r'Caddy/?([0-9.]+)?',
                'Kestrel': r'Kestrel',
            }
        }
        
        # Technology-specific paths to probe
        self.probe_paths = {
            'WordPress': [
                '/wp-admin/', '/wp-login.php', '/wp-content/',
                '/wp-includes/', '/xmlrpc.php', '/wp-json/'
            ],
            'Drupal': [
                '/user/login', '/core/', '/sites/default/',
                '/modules/', '/themes/'
            ],
            'Joomla': [
                '/administrator/', '/components/', '/modules/',
                '/plugins/', '/templates/'
            ],
            'Magento': [
                '/admin/', '/downloader/', '/app/etc/',
                '/skin/', '/js/mage/'
            ],
            'Laravel': [
                '/public/', '/storage/', '/vendor/'
            ],
            'Django': [
                '/admin/', '/static/', '/media/'
            ],
            'Ruby on Rails': [
                '/assets/', '/rails/info/properties'
            ],
            'Next.js': [
                '/_next/', '/_next/static/'
            ],
            'Nuxt.js': [
                '/_nuxt/', '/.nuxt/'
            ],
            'React': [
                '/static/js/main', '/static/css/main'
            ],
            'Angular': [
                '/main.js', '/polyfills.js', '/runtime.js'
            ],
            'Vue.js': [
                '/js/app.js', '/js/chunk-vendors'
            ],
        }
    
    def get_wordlists_directory(self):
        """Get the wordlists directory path"""
        # Get the script directory (modules/)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up one level to main directory
        main_dir = os.path.dirname(script_dir)
        # Wordlists directory
        wordlists_dir = os.path.join(main_dir, 'wordlists')
        
        return wordlists_dir
    
    def load_wordlist(self, filename):
        """Load a wordlist file"""
        filepath = os.path.join(self.wordlists_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"{Fore.YELLOW}[!] Wordlist not found: {filename}{Style.RESET_ALL}")
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Skip empty lines and comments
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading {filename}: {str(e)}{Style.RESET_ALL}")
            return []
    
    def load_wordlists(self):
        """Load all technology wordlists"""
        self.wordlists = {
            'web_servers': self.load_wordlist('tech_webservers.txt'),
            'frontend': self.load_wordlist('tech_frontend.txt'),
            'backend': self.load_wordlist('tech_backend.txt'),
            'cms': self.load_wordlist('tech_cms.txt'),
            'javascript': self.load_wordlist('tech_javascript.txt'),
            'analytics': self.load_wordlist('tech_analytics.txt'),
            'cdn': self.load_wordlist('tech_cdn.txt'),
            'databases': self.load_wordlist('tech_databases.txt'),
            'programming': self.load_wordlist('tech_programming.txt'),
            'devops': self.load_wordlist('tech_devops.txt'),
            'cloud': self.load_wordlist('tech_cloud.txt'),
            'plugins': self.load_wordlist('tech_plugins.txt'),
            'ecommerce': self.load_wordlist('tech_ecommerce.txt'),
            'security': self.load_wordlist('tech_security.txt'),
        }
        
        # Count loaded technologies
        total_loaded = sum(len(wl) for wl in self.wordlists.values())
        print(f"{Fore.GREEN}[✓] Loaded {total_loaded} technology signatures from wordlists{Style.RESET_ALL}")
    
    def print_section(self, title):
        """Print section header"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}{Style.RESET_ALL}\n")
    
    def print_check(self, check_name, status, details=""):
        """Print check result"""
        status_color = Fore.GREEN if status == "PASS" else Fore.RED if status == "FAIL" else Fore.YELLOW
        status_symbol = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
        
        print(f"{status_color}[{status_symbol}]{Style.RESET_ALL} {check_name}")
        if details:
            print(f"    {Fore.WHITE}{details}{Style.RESET_ALL}")
    
    def fetch_page_content(self):
        """Fetch the main page content"""
        self.print_section("Fetching Page Content")
        
        loader = LoadingBar("Retrieving HTML, CSS, and JavaScript")
        loader.start()
        
        page_data = {
            'html': '',
            'headers': {},
            'cookies': {},
            'scripts': [],
            'stylesheets': [],
            'status_code': None
        }
        
        try:
            response = self.session.get(self.target_url, timeout=15, verify=False, allow_redirects=True)
            
            page_data['html'] = response.text
            page_data['headers'] = dict(response.headers)
            page_data['status_code'] = response.status_code
            
            # Extract cookies
            for cookie in response.cookies:
                page_data['cookies'][cookie.name] = cookie.value
            
            # Extract script sources
            script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
            page_data['scripts'] = re.findall(script_pattern, page_data['html'])
            
            # Extract stylesheet sources
            css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
            page_data['stylesheets'] = re.findall(css_pattern, page_data['html'])
            
            loader.stop(True)
            
            self.print_check("Page Retrieved", "PASS", 
                           f"Status: {response.status_code}, Size: {len(page_data['html'])} bytes")
            self.print_check("Scripts Found", "PASS", f"{len(page_data['scripts'])} script files")
            self.print_check("Stylesheets Found", "PASS", f"{len(page_data['stylesheets'])} CSS files")
            
        except Exception as e:
            loader.stop(False)
            self.print_check("Page Retrieval", "FAIL", str(e))
        
        return page_data
    
    def analyze_headers(self, headers):
        """Analyze HTTP headers for technology fingerprints"""
        self.print_section("HTTP Header Analysis")
        
        detected = []
        
        for header, value in headers.items():
            header_lower = header.lower()
            
            # Check against header technology patterns
            for tech_header, patterns in self.header_technologies.items():
                if header.lower() == tech_header.lower():
                    for tech_name, pattern in patterns.items():
                        match = re.search(pattern, value, re.IGNORECASE)
                        if match:
                            version = match.group(1) if match.groups() else None
                            detected.append({
                                'name': tech_name,
                                'version': version,
                                'category': 'web_servers' if tech_header == 'Server' else 'backend_frameworks',
                                'confidence': 'high',
                                'source': f'Header: {header}'
                            })
            
            # Check wordlist technologies in headers
            for category, wordlist in self.wordlists.items():
                for tech in wordlist:
                    if tech.lower() in value.lower():
                        detected.append({
                            'name': tech,
                            'version': None,
                            'category': category,
                            'confidence': 'medium',
                            'source': f'Header: {header}'
                        })
        
        # Display detected technologies
        if detected:
            for tech in detected[:20]:  # Show first 20
                version_str = f" v{tech['version']}" if tech['version'] else ""
                self.print_check(
                    f"{tech['name']}{version_str}",
                    "PASS",
                    f"Source: {tech['source']} | Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("Header Analysis", "WARN", "No technologies detected in headers")
        
        return detected
    
    def analyze_cookies(self, cookies):
        """Analyze cookies for technology fingerprints"""
        self.print_section("Cookie Analysis")
        
        detected = []
        
        if not cookies:
            self.print_check("Cookies", "WARN", "No cookies found")
            return detected
        
        for cookie_name, cookie_value in cookies.items():
            # Check against cookie patterns
            for tech_name, patterns in self.cookie_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in cookie_name.lower():
                        detected.append({
                            'name': tech_name,
                            'version': None,
                            'category': 'backend_frameworks' if tech_name in ['PHP', 'ASP.NET', 'Java'] else 'cms',
                            'confidence': 'high',
                            'source': f'Cookie: {cookie_name}'
                        })
        
        # Display results
        if detected:
            for tech in detected:
                self.print_check(
                    tech['name'],
                    "PASS",
                    f"Source: {tech['source']} | Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("Cookie Analysis", "WARN", "No technology signatures in cookies")
        
        return detected
    
    def analyze_html_content(self, html):
        """Analyze HTML content for technology signatures"""
        self.print_section("HTML Content Analysis")
        
        loader = LoadingBar("Scanning HTML for technology signatures")
        loader.start()
        
        detected = []
        
        # Check HTML patterns
        for pattern_name, pattern in self.html_patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches[:10]:  # Limit matches
                if pattern_name == 'generator':
                    # Parse generator tag
                    detected.append({
                        'name': match,
                        'version': None,
                        'category': 'cms',
                        'confidence': 'high',
                        'source': 'HTML meta generator'
                    })
                elif 'version' in pattern_name:
                    tech_name = pattern_name.split('_')[0]
                    detected.append({
                        'name': tech_name.capitalize(),
                        'version': match,
                        'category': 'frontend_frameworks',
                        'confidence': 'high',
                        'source': 'HTML attribute'
                    })
        
        # Check for wordlist technologies in HTML
        html_lower = html.lower()
        for category, wordlist in self.wordlists.items():
            for tech in wordlist:
                # Case-insensitive search
                if tech.lower() in html_lower:
                    # Try to extract version
                    version_pattern = re.escape(tech) + r'[/-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
                    version_match = re.search(version_pattern, html, re.IGNORECASE)
                    version = version_match.group(1) if version_match else None
                    
                    detected.append({
                        'name': tech,
                        'version': version,
                        'category': category,
                        'confidence': 'medium',
                        'source': 'HTML content'
                    })
        
        loader.stop(True)
        
        # Display results (top 30)
        if detected:
            unique_detected = []
            seen = set()
            for tech in detected:
                key = (tech['name'].lower(), tech['category'])
                if key not in seen:
                    seen.add(key)
                    unique_detected.append(tech)
            
            for tech in unique_detected[:30]:
                version_str = f" v{tech['version']}" if tech['version'] else ""
                self.print_check(
                    f"{tech['name']}{version_str}",
                    "PASS",
                    f"Category: {tech['category']} | Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("HTML Analysis", "WARN", "No technologies detected in HTML")
        
        return detected
    
    def analyze_javascript(self, scripts, html):
        """Analyze JavaScript files and inline scripts"""
        self.print_section("JavaScript Library Analysis")
        
        loader = LoadingBar(f"Analyzing {len(scripts)} JavaScript files")
        loader.start()
        
        detected = []
        
        # Check script sources against wordlist
        for script_src in scripts:
            script_lower = script_src.lower()
            
            # Check against JavaScript wordlist
            for js_lib in self.wordlists.get('javascript', []):
                if js_lib.lower() in script_lower:
                    # Try to extract version
                    version_pattern = re.escape(js_lib) + r'[/-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
                    version_match = re.search(version_pattern, script_src, re.IGNORECASE)
                    version = version_match.group(1) if version_match else None
                    
                    detected.append({
                        'name': js_lib,
                        'version': version,
                        'category': 'javascript_libraries',
                        'confidence': 'high',
                        'source': f'Script: {script_src[:50]}...'
                    })
        
        # Check inline scripts for global variables
        inline_script_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(inline_script_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for js_global in self.js_globals:
            for inline_script in inline_scripts[:10]:  # Check first 10 inline scripts
                if js_global in inline_script:
                    detected.append({
                        'name': js_global,
                        'version': None,
                        'category': 'javascript_libraries',
                        'confidence': 'medium',
                        'source': 'Inline script'
                    })
        
        loader.stop(True)
        
        # Display results
        if detected:
            unique_detected = []
            seen = set()
            for tech in detected:
                key = tech['name'].lower()
                if key not in seen:
                    seen.add(key)
                    unique_detected.append(tech)
            
            for tech in unique_detected[:25]:
                version_str = f" v{tech['version']}" if tech['version'] else ""
                self.print_check(
                    f"{tech['name']}{version_str}",
                    "PASS",
                    f"Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("JavaScript Analysis", "WARN", "No JavaScript libraries identified")
        
        return detected
    
    def detect_analytics_and_trackers(self, html, scripts):
        """Detect analytics and tracking technologies"""
        self.print_section("Analytics & Tracking Detection")
        
        detected = []
        
        # Common analytics patterns
        analytics_patterns = {
            'Google Analytics': [r'google-analytics\.com', r'gtag\(', r'ga\(', r'_gaq', r'UA-\d+-\d+'],
            'Google Tag Manager': [r'googletagmanager\.com/gtm\.js'],
            'Facebook Pixel': [r'connect\.facebook\.net', r'fbq\('],
            'Hotjar': [r'static\.hotjar\.com'],
            'Mixpanel': [r'mixpanel\.com/libs'],
            'Segment': [r'cdn\.segment\.com'],
            'Adobe Analytics': [r'omniture\.com', r's\.t\(\)'],
            'Matomo': [r'matomo\.', r'piwik\.'],
            'Yandex Metrica': [r'mc\.yandex\.ru'],
            'Clicky': [r'static\.getclicky\.com'],
            'StatCounter': [r'statcounter\.com'],
            'Crazy Egg': [r'crazyegg\.com'],
            'Heap Analytics': [r'heap\.io'],
            'Amplitude': [r'amplitude\.com'],
            'FullStory': [r'fullstory\.com'],
        }
        
        combined_content = html + ' '.join(scripts)
        
        for tech_name, patterns in analytics_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_content, re.IGNORECASE):
                    detected.append({
                        'name': tech_name,
                        'version': None,
                        'category': 'analytics',
                        'confidence': 'high',
                        'source': 'Analytics signature'
                    })
                    break
        
        # Check wordlist analytics
        for analytics_tech in self.wordlists.get('analytics', []):
            if analytics_tech.lower() in combined_content.lower():
                if not any(d['name'] == analytics_tech for d in detected):
                    detected.append({
                        'name': analytics_tech,
                        'version': None,
                        'category': 'analytics',
                        'confidence': 'medium',
                        'source': 'Pattern match'
                    })
        
        # Display results
        if detected:
            for tech in detected:
                self.print_check(
                    tech['name'],
                    "PASS",
                    f"Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("Analytics Detection", "PASS", "No analytics/tracking detected")
        
        return detected
    
    def probe_technology_paths(self):
        """Probe specific paths to confirm technologies"""
        self.print_section("Technology Path Probing")
        
        loader = LoadingBar("Probing technology-specific paths")
        loader.start()
        
        detected = []
        
        def probe_path(tech_name, path):
            """Probe a single path"""
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return tech_name, path, response.status_code
            except:
                pass
            return None
        
        # Parallel probing
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for tech_name, paths in self.probe_paths.items():
                for path in paths[:3]:  # Probe first 3 paths for each tech
                    futures.append(executor.submit(probe_path, tech_name, path))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    tech_name, path, status = result
                    detected.append({
                        'name': tech_name,
                        'version': None,
                        'category': 'cms' if tech_name in ['WordPress', 'Drupal', 'Joomla', 'Magento'] else 'frontend_frameworks',
                        'confidence': 'high',
                        'source': f'Path probe: {path} ({status})'
                    })
        
        loader.stop(True)
        
        # Display results
        if detected:
            unique_detected = {}
            for tech in detected:
                if tech['name'] not in unique_detected:
                    unique_detected[tech['name']] = tech
            
            for tech_name, tech in unique_detected.items():
                self.print_check(
                    tech_name,
                    "PASS",
                    f"Confirmed via: {tech['source']}"
                )
        else:
            self.print_check("Path Probing", "WARN", "No technologies confirmed via path probing")
        
        return detected
    
    def detect_cdn_and_waf(self, headers):
        """Detect CDN and WAF technologies"""
        self.print_section("CDN & WAF Detection")
        
        detected = []
        
        # CDN indicators
        cdn_indicators = {
            'Cloudflare': ['CF-RAY', 'cf-cache-status', '__cfduid'],
            'Fastly': ['X-Fastly-Request-ID', 'Fastly-SSL'],
            'Akamai': ['X-Akamai-Transformed', 'X-Akamai-Session-Info'],
            'Amazon CloudFront': ['X-Amz-Cf-Id', 'X-Amz-Cf-Pop'],
            'Azure CDN': ['X-Azure-Ref', 'X-EC-Custom-Error'],
            'KeyCDN': ['x-keycdn-cache'],
            'StackPath': ['x-stackpath-edge'],
            'Sucuri': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
            'Incapsula': ['X-CDN', 'visid_incap'],
        }
        
        # WAF indicators
        waf_indicators = {
            'ModSecurity': ['X-Mod-Security'],
            'AWS WAF': ['X-Amzn-Waf'],
            'Cloudflare WAF': ['CF-RAY'],
            'Imperva': ['X-Iinfo'],
            'F5 BIG-IP': ['X-WA-Info', 'BigIP'],
            'Barracuda': ['barra_counter_session'],
            'Citrix NetScaler': ['ns_af', 'NSC_'],
            'FortiWeb': ['FORTIWAFSID'],
            'Akamai': ['AkamaiGHost'],
        }
        
        headers_str = ' '.join([f"{k}:{v}" for k, v in headers.items()]).lower()
        
        # Check CDN
        for cdn_name, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    detected.append({
                        'name': cdn_name,
                        'version': None,
                        'category': 'cdn',
                        'confidence': 'high',
                        'source': f'Header: {indicator}'
                    })
                    break
        
        # Check WAF
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator.lower() in headers_str:
                    detected.append({
                        'name': waf_name,
                        'version': None,
                        'category': 'waf',
                        'confidence': 'high',
                        'source': f'Header: {indicator}'
                    })
                    break
        
        # Check wordlist
        for cdn_tech in self.wordlists.get('cdn', []):
            if cdn_tech.lower() in headers_str:
                if not any(d['name'] == cdn_tech for d in detected):
                    detected.append({
                        'name': cdn_tech,
                        'version': None,
                        'category': 'cdn',
                        'confidence': 'medium',
                        'source': 'Header pattern'
                    })
        
        # Display results
        if detected:
            for tech in detected:
                self.print_check(
                    f"{tech['name']} ({tech['category'].upper()})",
                    "PASS",
                    f"Confidence: {tech['confidence']}"
                )
        else:
            self.print_check("CDN/WAF Detection", "WARN", "No CDN or WAF detected")
        
        return detected
    
    def aggregate_results(self, all_detections):
        """Aggregate and deduplicate all detections"""
        self.print_section("Aggregating Technology Stack")
        
        # Deduplicate and organize by category
        tech_map = {}
        
        for detection in all_detections:
            name = detection['name']
            category = detection['category']
            
            key = (name.lower(), category)
            
            if key not in tech_map:
                tech_map[key] = {
                    'name': name,
                    'version': detection.get('version'),
                    'category': category,
                    'confidence': detection.get('confidence', 'low'),
                    'sources': []
                }
            
            # Update version if found
            if detection.get('version') and not tech_map[key]['version']:
                tech_map[key]['version'] = detection['version']
            
            # Add source
            if detection.get('source'):
                tech_map[key]['sources'].append(detection['source'])
            
            # Upgrade confidence if higher
            confidence_order = {'low': 0, 'medium': 1, 'high': 2}
            current_conf = confidence_order.get(tech_map[key]['confidence'], 0)
            new_conf = confidence_order.get(detection.get('confidence', 'low'), 0)
            if new_conf > current_conf:
                tech_map[key]['confidence'] = detection['confidence']
        
        # Organize by category
        for tech_data in tech_map.values():
            category = tech_data['category']
            
            if category in self.results['technologies']:
                self.results['technologies'][category].append({
                    'name': tech_data['name'],
                    'version': tech_data['version'],
                    'confidence': tech_data['confidence']
                })
            
            if tech_data['version']:
                self.results['versions'][tech_data['name']] = tech_data['version']
            
            self.results['confidence_scores'][tech_data['name']] = tech_data['confidence']
        
        # Display aggregated results
        print(f"{Fore.GREEN}Technology Stack Summary:{Style.RESET_ALL}\n")
        
        category_names = {
            'web_servers': 'Web Servers',
            'frontend_frameworks': 'Frontend Frameworks',
            'backend_frameworks': 'Backend Frameworks',
            'programming_languages': 'Programming Languages',
            'cms': 'Content Management Systems',
            'javascript_libraries': 'JavaScript Libraries',
            'analytics': 'Analytics & Tracking',
            'cdn': 'CDN Services',
            'waf': 'Web Application Firewalls',
            'databases': 'Databases',
            'caching': 'Caching Systems',
            'devops': 'DevOps Tools',
            'cloud': 'Cloud Platforms',
            'plugins': 'Plugins & Extensions'
        }
        
        for category, display_name in category_names.items():
            techs = self.results['technologies'].get(category, [])
            if techs:
                print(f"{Fore.CYAN}  {display_name}:{Style.RESET_ALL}")
                for tech in techs[:10]:  # Show top 10 per category
                    version_str = f" v{tech['version']}" if tech.get('version') else ""
                    confidence_color = Fore.GREEN if tech['confidence'] == 'high' else Fore.YELLOW if tech['confidence'] == 'medium' else Fore.WHITE
                    print(f"    {confidence_color}• {tech['name']}{version_str}{Style.RESET_ALL}")
        
        # Count total technologies
        total_techs = sum(len(techs) for techs in self.results['technologies'].values())
        print(f"\n{Fore.GREEN}[✓] Total Technologies Detected: {total_techs}{Style.RESET_ALL}")
        
        return tech_map
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"TechFingerprint_{hostname}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("TECHNOLOGY FINGERPRINTING REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # Technology stack summary
        report.append("\n" + "=" * 80)
        report.append("TECHNOLOGY STACK SUMMARY")
        report.append("=" * 80)
        
        category_names = {
            'web_servers': 'Web Servers',
            'frontend_frameworks': 'Frontend Frameworks',
            'backend_frameworks': 'Backend Frameworks',
            'programming_languages': 'Programming Languages',
            'cms': 'Content Management Systems',
            'javascript_libraries': 'JavaScript Libraries',
            'analytics': 'Analytics & Tracking',
            'cdn': 'CDN Services',
            'waf': 'Web Application Firewalls',
            'databases': 'Databases',
            'caching': 'Caching Systems',
            'authentication': 'Authentication',
            'payment': 'Payment Systems',
            'devops': 'DevOps Tools',
            'cloud': 'Cloud Platforms',
            'containers': 'Containers/Orchestration',
            'plugins': 'Plugins & Extensions',
            'other': 'Other Technologies'
        }
        
        for category, display_name in category_names.items():
            techs = self.results['technologies'].get(category, [])
            if techs:
                report.append(f"\n{display_name}:")
                report.append("-" * 40)
                for tech in techs:
                    version_str = f" v{tech['version']}" if tech.get('version') else ""
                    confidence_str = f" [{tech['confidence']} confidence]"
                    report.append(f"  • {tech['name']}{version_str}{confidence_str}")
        
        # Versions detected
        if self.results['versions']:
            report.append("\n" + "=" * 80)
            report.append("VERSION INFORMATION")
            report.append("=" * 80)
            for tech, version in self.results['versions'].items():
                report.append(f"  {tech}: {version}")
        
        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        
        total_techs = sum(len(techs) for techs in self.results['technologies'].values())
        high_confidence = sum(1 for score in self.results['confidence_scores'].values() if score == 'high')
        
        report.append(f"\nTotal Technologies Detected: {total_techs}")
        report.append(f"High Confidence Detections: {high_confidence}")
        report.append(f"Versions Identified: {len(self.results['versions'])}")
        
        for category, display_name in category_names.items():
            count = len(self.results['technologies'].get(category, []))
            if count > 0:
                report.append(f"  {display_name}: {count}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting Technology Fingerprinting{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    fingerprinter = TechnologyFingerprinter(target_url)
    
    # Define scan stages
    stages = [
        ("Fetch Page Content", fingerprinter.fetch_page_content),
        ("HTTP Header Analysis", None),
        ("Cookie Analysis", None),
        ("HTML Content Analysis", None),
        ("JavaScript Analysis", None),
        ("Analytics & Trackers", None),
        ("Technology Path Probing", None),
        ("CDN & WAF Detection", None),
        ("Aggregate Results", None),
    ]
    
    progress = ProgressBar(len(stages))
    all_detections = []
    
    try:
        # Stage 1: Fetch page content
        progress.update(stages[0][0])
        page_data = stages[0][1]()
        
        if not page_data['html']:
            print(f"\n{Fore.RED}[!] Failed to retrieve page content. Cannot continue.{Style.RESET_ALL}")
            return
        
        # Stage 2: Analyze headers
        progress.update(stages[1][0])
        header_detections = fingerprinter.analyze_headers(page_data['headers'])
        all_detections.extend(header_detections)
        
        # Stage 3: Analyze cookies
        progress.update(stages[2][0])
        cookie_detections = fingerprinter.analyze_cookies(page_data['cookies'])
        all_detections.extend(cookie_detections)
        
        # Stage 4: Analyze HTML
        progress.update(stages[3][0])
        html_detections = fingerprinter.analyze_html_content(page_data['html'])
        all_detections.extend(html_detections)
        
        # Stage 5: Analyze JavaScript
        progress.update(stages[4][0])
        js_detections = fingerprinter.analyze_javascript(page_data['scripts'], page_data['html'])
        all_detections.extend(js_detections)
        
        # Stage 6: Detect analytics
        progress.update(stages[5][0])
        analytics_detections = fingerprinter.detect_analytics_and_trackers(page_data['html'], page_data['scripts'])
        all_detections.extend(analytics_detections)
        
        # Stage 7: Probe paths
        progress.update(stages[6][0])
        probe_detections = fingerprinter.probe_technology_paths()
        all_detections.extend(probe_detections)
        
        # Stage 8: CDN/WAF detection
        progress.update(stages[7][0])
        cdn_waf_detections = fingerprinter.detect_cdn_and_waf(page_data['headers'])
        all_detections.extend(cdn_waf_detections)
        
        # Stage 9: Aggregate results
        progress.update(stages[8][0])
        fingerprinter.aggregate_results(all_detections)
        
        # Generate report
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  Finalizing Report")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        loader = LoadingBar("Generating comprehensive report")
        loader.start()
        time.sleep(1)
        report_path = fingerprinter.generate_report()
        loader.stop(True)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        total_techs = sum(len(techs) for techs in fingerprinter.results['technologies'].values())
        high_confidence = sum(1 for score in fingerprinter.results['confidence_scores'].values() if score == 'high')
        
        print(f"{Fore.YELLOW}[✓] Technologies Detected: {total_techs}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] High Confidence: {high_confidence}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Versions Identified: {len(fingerprinter.results['versions'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Scan Duration: {(time.time() - fingerprinter.results.get('start_time', time.time())):.2f}s{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # For testing
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python tech.py <target_url>")
