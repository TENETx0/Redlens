#!/usr/bin/env python3
"""
Application Surface Mapping Module
Performs comprehensive web application surface mapping including crawling, endpoint discovery,
HTTP method enumeration, parameter discovery, form mapping, and authentication flow detection.
"""

import requests
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
from urllib.robotparser import RobotFileParser
from bs4 import BeautifulSoup
from colorama import Fore, Style, Back
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
import warnings
import hashlib
from xml.etree import ElementTree as ET

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

class ApplicationSurfaceMapper:
    def __init__(self, target_url, max_depth=3, max_urls=500):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.max_depth = max_depth
        self.max_urls = max_urls
        
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'urls': {
                'discovered': [],
                'crawled': [],
                'skipped': [],
                'errors': []
            },
            'endpoints': {
                'get': [],
                'post': [],
                'put': [],
                'delete': [],
                'patch': [],
                'options': [],
                'head': []
            },
            'forms': [],
            'parameters': {
                'query': set(),
                'body': set(),
                'headers': set()
            },
            'authentication': {
                'login_endpoints': [],
                'logout_endpoints': [],
                'password_reset': [],
                'registration': [],
                'oauth': []
            },
            'upload_endpoints': [],
            'api_endpoints': [],
            'static_resources': {
                'js': [],
                'css': [],
                'images': [],
                'fonts': [],
                'other': []
            },
            'external_links': [],
            'subdomains': set(),
            'technologies': set(),
            'sitemap_urls': [],
            'robots_directives': {}
        }
        
        self.visited_urls = set()
        self.to_visit = deque()
        self.url_lock = Lock()
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'
        })
        
        # Authentication/Security patterns
        self.auth_patterns = {
            'login': [
                r'/login', r'/signin', r'/sign-in', r'/auth', r'/authenticate',
                r'/session/new', r'/account/login', r'/user/login',
                r'/admin/login', r'/portal/login', r'/connect'
            ],
            'logout': [
                r'/logout', r'/signout', r'/sign-out', r'/session/destroy',
                r'/account/logout', r'/disconnect', r'/exit'
            ],
            'reset': [
                r'/reset', r'/forgot', r'/password/reset', r'/password/forgot',
                r'/recover', r'/account/recover', r'/password-reset'
            ],
            'register': [
                r'/register', r'/signup', r'/sign-up', r'/join',
                r'/account/create', r'/user/register', r'/registration'
            ],
            'oauth': [
                r'/oauth', r'/auth/google', r'/auth/facebook', r'/auth/github',
                r'/connect/google', r'/social', r'/sso'
            ]
        }
        
        # Form field patterns
        self.sensitive_fields = {
            'password': ['password', 'passwd', 'pwd', 'pass', 'secret'],
            'username': ['username', 'user', 'login', 'email', 'userid'],
            'email': ['email', 'e-mail', 'mail'],
            'credit_card': ['card', 'cardnumber', 'cc', 'creditcard', 'cvv', 'cvc'],
            'phone': ['phone', 'telephone', 'mobile', 'cell'],
            'ssn': ['ssn', 'social', 'socialsecurity'],
            'token': ['token', 'csrf', 'xsrf', '_token', 'authenticity_token'],
            'api_key': ['api_key', 'apikey', 'key', 'secret_key']
        }
        
        # File upload patterns
        self.upload_patterns = [
            r'upload', r'file', r'attach', r'import', r'avatar',
            r'photo', r'image', r'document', r'media', r'asset'
        ]
        
        # API endpoint patterns
        self.api_patterns = [
            r'/api/', r'/v1/', r'/v2/', r'/v3/', r'/rest/',
            r'/graphql', r'/json', r'/ajax', r'/service/',
            r'.json', r'.xml', r'/endpoint/'
        ]
        
        # Static resource extensions
        self.static_extensions = {
            'js': ['.js', '.jsx', '.ts', '.tsx', '.mjs'],
            'css': ['.css', '.scss', '.sass', '.less'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico', '.bmp'],
            'fonts': ['.woff', '.woff2', '.ttf', '.eot', '.otf'],
            'other': ['.pdf', '.zip', '.tar', '.gz', '.xml', '.txt', '.csv']
        }
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # Common parameter names
        self.common_params = [
            'id', 'page', 'limit', 'offset', 'sort', 'order', 'search', 'q',
            'filter', 'category', 'tag', 'type', 'status', 'from', 'to',
            'start', 'end', 'lang', 'locale', 'format', 'callback', 'redirect',
            'next', 'return', 'url', 'ref', 'source', 'utm_source', 'token'
        ]
        
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
    
    def is_valid_url(self, url):
        """Check if URL is valid and within scope"""
        try:
            parsed = urlparse(url)
            
            # Must be HTTP/HTTPS
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Must be same domain
            if parsed.netloc != self.base_domain:
                return False
            
            # Skip common non-HTML extensions
            skip_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
                '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3',
                '.avi', '.mov', '.wmv', '.flv', '.webm'
            ]
            
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            # Skip common logout/delete actions
            skip_patterns = [r'logout', r'signout', r'delete', r'remove']
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in skip_patterns):
                return False
            
            return True
        
        except:
            return False
    
    def normalize_url(self, url):
        """Normalize URL for comparison"""
        parsed = urlparse(url)
        
        # Remove fragment
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            ''  # No fragment
        ))
        
        # Remove trailing slash from path
        if normalized.endswith('/') and normalized.count('/') > 3:
            normalized = normalized[:-1]
        
        return normalized
    
    def parse_robots_txt(self):
        """Parse robots.txt for directives"""
        self.print_section("Robots.txt Analysis")
        
        robots_url = urljoin(self.target_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                self.print_check("robots.txt Found", "PASS", robots_url)
                
                # Parse robots.txt
                rp = RobotFileParser()
                rp.parse(response.text.split('\n'))
                
                # Extract directives
                lines = response.text.split('\n')
                disallowed = []
                allowed = []
                sitemaps = []
                
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            disallowed.append(path)
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            allowed.append(path)
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        sitemaps.append(sitemap)
                
                self.results['robots_directives'] = {
                    'disallowed': disallowed,
                    'allowed': allowed,
                    'sitemaps': sitemaps
                }
                
                if disallowed:
                    print(f"\n{Fore.YELLOW}  Disallowed Paths:{Style.RESET_ALL}")
                    for path in disallowed[:10]:
                        print(f"    {Fore.RED}×{Style.RESET_ALL} {path}")
                
                if sitemaps:
                    print(f"\n{Fore.GREEN}  Sitemaps Found:{Style.RESET_ALL}")
                    for sitemap in sitemaps:
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {sitemap}")
                
            else:
                self.print_check("robots.txt", "WARN", "Not found")
        
        except Exception as e:
            self.print_check("robots.txt", "FAIL", str(e))
    
    def parse_sitemap(self, sitemap_url=None):
        """Parse sitemap.xml for URLs"""
        self.print_section("Sitemap.xml Parsing")
        
        if sitemap_url is None:
            sitemap_url = urljoin(self.target_url, '/sitemap.xml')
        
        try:
            response = self.session.get(sitemap_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                self.print_check("Sitemap Found", "PASS", sitemap_url)
                
                # Parse XML
                try:
                    root = ET.fromstring(response.content)
                    
                    # Handle different sitemap formats
                    namespaces = {
                        'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9',
                        'xhtml': 'http://www.w3.org/1999/xhtml'
                    }
                    
                    urls = []
                    
                    # Check if it's a sitemap index
                    sitemaps = root.findall('.//sm:sitemap/sm:loc', namespaces)
                    if sitemaps:
                        # It's a sitemap index, parse each sitemap
                        for sitemap in sitemaps[:5]:  # Limit to 5 sitemaps
                            self.parse_sitemap(sitemap.text)
                    else:
                        # Regular sitemap
                        for url_elem in root.findall('.//sm:url/sm:loc', namespaces):
                            url = url_elem.text
                            if url:
                                urls.append(url)
                                self.results['sitemap_urls'].append(url)
                                
                                # Add to crawl queue if valid
                                if self.is_valid_url(url):
                                    normalized = self.normalize_url(url)
                                    if normalized not in self.visited_urls:
                                        self.to_visit.append((normalized, 0))
                    
                    if urls:
                        self.print_check("URLs Extracted", "PASS", f"{len(urls)} URLs found")
                
                except ET.ParseError as e:
                    self.print_check("XML Parsing", "FAIL", "Invalid XML format")
            
            else:
                self.print_check("Sitemap", "WARN", "Not found")
        
        except Exception as e:
            self.print_check("Sitemap Parsing", "FAIL", str(e)[:100])
    
    def extract_links(self, html, base_url):
        """Extract all links from HTML"""
        links = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all anchor tags
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                absolute_url = urljoin(base_url, href)
                links.append(absolute_url)
            
            # Find links in JavaScript (basic patterns)
            js_url_patterns = [
                r'["\']https?://[^"\']+["\']',
                r'["\']\/[^"\']+["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for script in soup.find_all('script'):
                if script.string:
                    for pattern in js_url_patterns:
                        matches = re.findall(pattern, script.string)
                        for match in matches:
                            # Clean up the match
                            url = match.strip('"\'')
                            if url.startswith(('http://', 'https://', '/')):
                                absolute_url = urljoin(base_url, url)
                                links.append(absolute_url)
        
        except Exception as e:
            pass
        
        return list(set(links))
    
    def extract_forms(self, html, page_url):
        """Extract and analyze all forms"""
        forms = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(page_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'fields': [],
                    'has_file_upload': False,
                    'sensitive_fields': [],
                    'purpose': 'unknown'
                }
                
                # Extract all form fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    field = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'id': input_tag.get('id', ''),
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required'),
                        'placeholder': input_tag.get('placeholder', '')
                    }
                    
                    if field['name']:
                        form_data['fields'].append(field)
                        
                        # Check for file upload
                        if field['type'] == 'file':
                            form_data['has_file_upload'] = True
                        
                        # Check for sensitive fields
                        field_name_lower = field['name'].lower()
                        for category, patterns in self.sensitive_fields.items():
                            if any(pattern in field_name_lower for pattern in patterns):
                                form_data['sensitive_fields'].append({
                                    'name': field['name'],
                                    'category': category
                                })
                
                # Determine form purpose
                action_lower = form_data['action'].lower()
                field_names = ' '.join([f['name'].lower() for f in form_data['fields']])
                
                if any(pattern in action_lower or pattern in field_names for pattern in ['login', 'signin', 'auth']):
                    form_data['purpose'] = 'login'
                elif any(pattern in action_lower or pattern in field_names for pattern in ['register', 'signup', 'join']):
                    form_data['purpose'] = 'registration'
                elif any(pattern in action_lower or pattern in field_names for pattern in ['search', 'query']):
                    form_data['purpose'] = 'search'
                elif any(pattern in action_lower or pattern in field_names for pattern in ['contact', 'message', 'feedback']):
                    form_data['purpose'] = 'contact'
                elif any(pattern in action_lower or pattern in field_names for pattern in ['reset', 'forgot', 'recover']):
                    form_data['purpose'] = 'password_reset'
                elif form_data['has_file_upload']:
                    form_data['purpose'] = 'upload'
                
                forms.append(form_data)
        
        except Exception as e:
            pass
        
        return forms
    
    def extract_parameters(self, url):
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                self.results['parameters']['query'].add(param)
        
        except:
            pass
    
    def categorize_url(self, url):
        """Categorize URL type"""
        url_lower = url.lower()
        
        # Check authentication patterns
        for auth_type, patterns in self.auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return f'auth_{auth_type}'
        
        # Check for file upload
        if any(re.search(pattern, url_lower) for pattern in self.upload_patterns):
            return 'upload'
        
        # Check for API
        if any(re.search(pattern, url_lower) for pattern in self.api_patterns):
            return 'api'
        
        # Check static resources
        for resource_type, extensions in self.static_extensions.items():
            if any(url_lower.endswith(ext) for ext in extensions):
                return f'static_{resource_type}'
        
        return 'page'
    
    def test_http_methods(self, url):
        """Test which HTTP methods are allowed on endpoint"""
        allowed_methods = []
        
        try:
            # First try OPTIONS to get allowed methods
            response = self.session.options(url, timeout=5, verify=False)
            allow_header = response.headers.get('Allow', '')
            
            if allow_header:
                allowed_methods = [m.strip() for m in allow_header.split(',')]
                return allowed_methods
        
        except:
            pass
        
        # Test each method individually
        for method in self.http_methods:
            try:
                response = self.session.request(
                    method, 
                    url, 
                    timeout=5, 
                    verify=False,
                    allow_redirects=False
                )
                
                # Method is allowed if status is not 405 (Method Not Allowed)
                if response.status_code != 405:
                    allowed_methods.append(method)
            
            except:
                pass
        
        return allowed_methods
    
    def crawl_url(self, url, depth):
        """Crawl a single URL"""
        try:
            # Mark as visited
            with self.url_lock:
                self.visited_urls.add(url)
                self.results['urls']['crawled'].append(url)
            
            # Make request
            response = self.session.get(url, timeout=15, verify=False, allow_redirects=True)
            
            # Categorize URL
            category = self.categorize_url(url)
            
            # Store by category
            if category.startswith('auth_'):
                auth_type = category.replace('auth_', '')
                if url not in self.results['authentication'].get(auth_type + '_endpoints', []):
                    if auth_type in ['login', 'logout', 'reset', 'register', 'oauth']:
                        self.results['authentication'][auth_type + '_endpoints'].append(url)
            
            elif category == 'upload':
                if url not in self.results['upload_endpoints']:
                    self.results['upload_endpoints'].append(url)
            
            elif category == 'api':
                if url not in self.results['api_endpoints']:
                    self.results['api_endpoints'].append(url)
            
            elif category.startswith('static_'):
                resource_type = category.replace('static_', '')
                if url not in self.results['static_resources'][resource_type]:
                    self.results['static_resources'][resource_type].append(url)
            
            # Extract parameters from URL
            self.extract_parameters(url)
            
            # Only process HTML responses
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type.lower():
                return
            
            html = response.text
            
            # Extract forms
            forms = self.extract_forms(html, url)
            for form in forms:
                self.results['forms'].append(form)
                
                # Categorize forms for authentication endpoints
                if form['purpose'] == 'login':
                    if form['action'] not in self.results['authentication']['login_endpoints']:
                        self.results['authentication']['login_endpoints'].append(form['action'])
                
                elif form['purpose'] == 'registration':
                    if form['action'] not in self.results['authentication']['registration']:
                        self.results['authentication']['registration'].append(form['action'])
                
                elif form['purpose'] == 'password_reset':
                    if form['action'] not in self.results['authentication']['password_reset']:
                        self.results['authentication']['password_reset'].append(form['action'])
                
                elif form['purpose'] == 'upload':
                    if form['action'] not in self.results['upload_endpoints']:
                        self.results['upload_endpoints'].append(form['action'])
            
            # Extract links
            if depth < self.max_depth:
                links = self.extract_links(html, url)
                
                for link in links:
                    if self.is_valid_url(link):
                        normalized = self.normalize_url(link)
                        
                        with self.url_lock:
                            if normalized not in self.visited_urls and normalized not in [u[0] for u in self.to_visit]:
                                self.to_visit.append((normalized, depth + 1))
                                self.results['urls']['discovered'].append(normalized)
                    else:
                        # Check if it's external
                        parsed = urlparse(link)
                        if parsed.netloc and parsed.netloc != self.base_domain:
                            if link not in self.results['external_links']:
                                self.results['external_links'].append(link)
                            
                            # Check for subdomains
                            if self.hostname in parsed.netloc:
                                self.results['subdomains'].add(parsed.netloc)
        
        except Exception as e:
            with self.url_lock:
                self.results['urls']['errors'].append({'url': url, 'error': str(e)[:100]})
    
    def start_crawling(self):
        """Start the crawling process"""
        self.print_section("Website Crawling")
        
        # Add initial URL to queue
        self.to_visit.append((self.target_url, 0))
        
        loader = LoadingBar(f"Crawling (max depth: {self.max_depth}, max URLs: {self.max_urls})")
        loader.start()
        
        crawled_count = 0
        
        try:
            while self.to_visit and crawled_count < self.max_urls:
                # Get next URL
                with self.url_lock:
                    if not self.to_visit:
                        break
                    url, depth = self.to_visit.popleft()
                    
                    if url in self.visited_urls:
                        continue
                
                # Crawl URL
                self.crawl_url(url, depth)
                crawled_count += 1
                
                # Update progress
                if crawled_count % 10 == 0:
                    loader.description = f"Crawling ({crawled_count}/{self.max_urls} URLs, {len(self.to_visit)} in queue)"
            
            loader.stop(True)
            
            self.print_check("URLs Crawled", "PASS", f"{crawled_count} pages")
            self.print_check("URLs Discovered", "PASS", f"{len(self.results['urls']['discovered'])} total")
            self.print_check("Forms Found", "PASS", f"{len(self.results['forms'])} forms")
            
        except Exception as e:
            loader.stop(False)
            self.print_check("Crawling", "FAIL", str(e))
    
    def endpoint_enumeration(self):
        """Enumerate endpoints and test HTTP methods"""
        self.print_section("Endpoint & HTTP Method Discovery")
        
        loader = LoadingBar("Testing HTTP methods on discovered endpoints")
        loader.start()
        
        # Get unique endpoints (excluding static resources)
        endpoints = []
        for url in self.results['urls']['crawled']:
            category = self.categorize_url(url)
            if not category.startswith('static_'):
                endpoints.append(url)
        
        # Test methods on a sample of endpoints (to avoid too many requests)
        sample_size = min(50, len(endpoints))
        sample_endpoints = endpoints[:sample_size]
        
        method_results = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.test_http_methods, url): url for url in sample_endpoints}
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    methods = future.result()
                    method_results[url] = methods
                    
                    # Store by method
                    for method in methods:
                        method_lower = method.lower()
                        if method_lower in self.results['endpoints']:
                            if url not in self.results['endpoints'][method_lower]:
                                self.results['endpoints'][method_lower].append(url)
                
                except:
                    pass
        
        loader.stop(True)
        
        # Display results
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            count = len(self.results['endpoints'][method.lower()])
            if count > 0:
                self.print_check(f"{method} Endpoints", "PASS", f"{count} endpoints")
    
    def analyze_authentication_flows(self):
        """Analyze authentication and session management"""
        self.print_section("Authentication Flow Analysis")
        
        # Check what we found
        auth_found = False
        
        if self.results['authentication']['login_endpoints']:
            self.print_check("Login Endpoints", "PASS", 
                           f"{len(self.results['authentication']['login_endpoints'])} found")
            for endpoint in self.results['authentication']['login_endpoints'][:5]:
                print(f"    {Fore.GREEN}•{Style.RESET_ALL} {endpoint}")
            auth_found = True
        
        if self.results['authentication']['logout_endpoints']:
            self.print_check("Logout Endpoints", "PASS", 
                           f"{len(self.results['authentication']['logout_endpoints'])} found")
            auth_found = True
        
        if self.results['authentication']['password_reset']:
            self.print_check("Password Reset", "PASS", 
                           f"{len(self.results['authentication']['password_reset'])} found")
            auth_found = True
        
        if self.results['authentication']['registration']:
            self.print_check("Registration", "PASS", 
                           f"{len(self.results['authentication']['registration'])} found")
            auth_found = True
        
        if self.results['authentication']['oauth']:
            self.print_check("OAuth Endpoints", "PASS", 
                           f"{len(self.results['authentication']['oauth'])} found")
            auth_found = True
        
        if not auth_found:
            self.print_check("Authentication", "WARN", "No authentication endpoints detected")
    
    def analyze_forms(self):
        """Analyze discovered forms"""
        self.print_section("Form Analysis")
        
        if not self.results['forms']:
            self.print_check("Forms", "WARN", "No forms found")
            return
        
        # Categorize forms
        form_types = defaultdict(int)
        sensitive_forms = []
        upload_forms = []
        
        for form in self.results['forms']:
            form_types[form['purpose']] += 1
            
            if form['sensitive_fields']:
                sensitive_forms.append(form)
            
            if form['has_file_upload']:
                upload_forms.append(form)
        
        # Display statistics
        self.print_check("Total Forms", "PASS", f"{len(self.results['forms'])} forms discovered")
        
        print(f"\n{Fore.CYAN}  Form Types:{Style.RESET_ALL}")
        for form_type, count in form_types.items():
            print(f"    {Fore.YELLOW}•{Style.RESET_ALL} {form_type}: {count}")
        
        if sensitive_forms:
            print(f"\n{Fore.RED}  Forms with Sensitive Fields: {len(sensitive_forms)}{Style.RESET_ALL}")
            for form in sensitive_forms[:5]:
                print(f"    {Fore.RED}⚠{Style.RESET_ALL} {form['action']}")
                for field in form['sensitive_fields']:
                    print(f"      - {field['name']} ({field['category']})")
        
        if upload_forms:
            print(f"\n{Fore.YELLOW}  File Upload Forms: {len(upload_forms)}{Style.RESET_ALL}")
            for form in upload_forms[:5]:
                print(f"    {Fore.YELLOW}↑{Style.RESET_ALL} {form['action']}")
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"SurfaceMap_{hostname}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        # Convert sets to lists for JSON serialization
        report_data = self.results.copy()
        report_data['parameters']['query'] = list(report_data['parameters']['query'])
        report_data['parameters']['body'] = list(report_data['parameters']['body'])
        report_data['parameters']['headers'] = list(report_data['parameters']['headers'])
        report_data['subdomains'] = list(report_data['subdomains'])
        report_data['technologies'] = list(report_data['technologies'])
        
        report = []
        report.append("=" * 80)
        report.append("APPLICATION SURFACE MAPPING REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}")
        report.append(f"Max Depth: {self.max_depth}")
        report.append(f"Max URLs: {self.max_urls}\n")
        report.append("=" * 80)
        
        # URL Discovery Summary
        report.append("\n" + "=" * 80)
        report.append("URL DISCOVERY SUMMARY")
        report.append("=" * 80)
        report.append(f"\nURLs Discovered: {len(self.results['urls']['discovered'])}")
        report.append(f"URLs Crawled: {len(self.results['urls']['crawled'])}")
        report.append(f"URLs with Errors: {len(self.results['urls']['errors'])}")
        report.append(f"External Links: {len(self.results['external_links'])}")
        report.append(f"Subdomains Found: {len(self.results['subdomains'])}")
        
        # HTTP Methods
        report.append("\n" + "=" * 80)
        report.append("HTTP METHODS DISCOVERED")
        report.append("=" * 80)
        for method in ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']:
            count = len(self.results['endpoints'][method])
            if count > 0:
                report.append(f"\n{method.upper()}: {count} endpoints")
                for endpoint in self.results['endpoints'][method][:20]:
                    report.append(f"  • {endpoint}")
        
        # Forms
        report.append("\n" + "=" * 80)
        report.append("FORMS DISCOVERED")
        report.append("=" * 80)
        report.append(f"\nTotal Forms: {len(self.results['forms'])}")
        
        for i, form in enumerate(self.results['forms'][:50], 1):
            report.append(f"\nForm #{i}:")
            report.append(f"  Action: {form['action']}")
            report.append(f"  Method: {form['method']}")
            report.append(f"  Purpose: {form['purpose']}")
            report.append(f"  Fields: {len(form['fields'])}")
            
            if form['sensitive_fields']:
                report.append(f"  Sensitive Fields:")
                for field in form['sensitive_fields']:
                    report.append(f"    - {field['name']} ({field['category']})")
            
            if form['has_file_upload']:
                report.append(f"  Has File Upload: Yes")
        
        # Authentication
        report.append("\n" + "=" * 80)
        report.append("AUTHENTICATION ENDPOINTS")
        report.append("=" * 80)
        
        if self.results['authentication']['login_endpoints']:
            report.append(f"\nLogin Endpoints ({len(self.results['authentication']['login_endpoints'])}):")
            for endpoint in self.results['authentication']['login_endpoints']:
                report.append(f"  • {endpoint}")
        
        if self.results['authentication']['logout_endpoints']:
            report.append(f"\nLogout Endpoints ({len(self.results['authentication']['logout_endpoints'])}):")
            for endpoint in self.results['authentication']['logout_endpoints']:
                report.append(f"  • {endpoint}")
        
        if self.results['authentication']['password_reset']:
            report.append(f"\nPassword Reset ({len(self.results['authentication']['password_reset'])}):")
            for endpoint in self.results['authentication']['password_reset']:
                report.append(f"  • {endpoint}")
        
        if self.results['authentication']['registration']:
            report.append(f"\nRegistration ({len(self.results['authentication']['registration'])}):")
            for endpoint in self.results['authentication']['registration']:
                report.append(f"  • {endpoint}")
        
        # Parameters
        report.append("\n" + "=" * 80)
        report.append("PARAMETERS DISCOVERED")
        report.append("=" * 80)
        report.append(f"\nQuery Parameters: {len(report_data['parameters']['query'])}")
        if report_data['parameters']['query']:
            report.append("  " + ", ".join(sorted(list(report_data['parameters']['query']))[:50]))
        
        # Upload Endpoints
        if self.results['upload_endpoints']:
            report.append("\n" + "=" * 80)
            report.append("FILE UPLOAD ENDPOINTS")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['upload_endpoints'])}")
            for endpoint in self.results['upload_endpoints']:
                report.append(f"  • {endpoint}")
        
        # API Endpoints
        if self.results['api_endpoints']:
            report.append("\n" + "=" * 80)
            report.append("API ENDPOINTS")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['api_endpoints'])}")
            for endpoint in self.results['api_endpoints'][:50]:
                report.append(f"  • {endpoint}")
        
        # Sitemap URLs
        if self.results['sitemap_urls']:
            report.append("\n" + "=" * 80)
            report.append("SITEMAP URLS")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['sitemap_urls'])}")
            for url in self.results['sitemap_urls'][:100]:
                report.append(f"  • {url}")
        
        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        report.append(f"\nScan Duration: {(time.time() - self.results['start_time']):.2f}s")
        report.append(f"Pages Crawled: {len(self.results['urls']['crawled'])}")
        report.append(f"Total Endpoints: {sum(len(v) for v in self.results['endpoints'].values())}")
        report.append(f"Forms Found: {len(self.results['forms'])}")
        report.append(f"Upload Endpoints: {len(self.results['upload_endpoints'])}")
        report.append(f"API Endpoints: {len(self.results['api_endpoints'])}")
        report.append(f"Authentication Endpoints: {sum(len(v) for v in self.results['authentication'].values() if isinstance(v, list))}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        # Also save JSON version
        json_filepath = filepath.replace('.txt', '.json')
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting Application Surface Mapping{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    # Get user preferences
    try:
        max_depth = int(input(f"{Fore.YELLOW}[?] Maximum crawl depth (1-5, default 3): {Style.RESET_ALL}").strip() or "3")
        max_depth = max(1, min(5, max_depth))
    except:
        max_depth = 3
    
    try:
        max_urls = int(input(f"{Fore.YELLOW}[?] Maximum URLs to crawl (50-1000, default 500): {Style.RESET_ALL}").strip() or "500")
        max_urls = max(50, min(1000, max_urls))
    except:
        max_urls = 500
    
    mapper = ApplicationSurfaceMapper(target_url, max_depth=max_depth, max_urls=max_urls)
    
    # Define scan stages
    stages = [
        ("Robots.txt Analysis", mapper.parse_robots_txt),
        ("Sitemap.xml Parsing", lambda: mapper.parse_sitemap()),
        ("Website Crawling", mapper.start_crawling),
        ("HTTP Method Discovery", mapper.endpoint_enumeration),
        ("Authentication Analysis", mapper.analyze_authentication_flows),
        ("Form Analysis", mapper.analyze_forms),
    ]
    
    progress = ProgressBar(len(stages))
    
    try:
        # Run all stages
        for stage_name, stage_func in stages:
            progress.update(stage_name)
            stage_func()
            time.sleep(0.5)
        
        # Generate report
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  Finalizing Report")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        loader = LoadingBar("Generating comprehensive report")
        loader.start()
        time.sleep(1)
        report_path = mapper.generate_report()
        loader.stop(True)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[✓] Pages Crawled: {len(mapper.results['urls']['crawled'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Total Endpoints: {sum(len(v) for v in mapper.results['endpoints'].values())}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Forms Found: {len(mapper.results['forms'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Upload Endpoints: {len(mapper.results['upload_endpoints'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] API Endpoints: {len(mapper.results['api_endpoints'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Auth Endpoints: {sum(len(v) for v in mapper.results['authentication'].values() if isinstance(v, list))}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Scan Duration: {(time.time() - mapper.results.get('start_time', time.time())):.2f}s{Style.RESET_ALL}")
        
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
        print("Usage: python crawler.py <target_url>")
