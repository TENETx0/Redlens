#!/usr/bin/env python3
"""
API Reconnaissance Module
Performs comprehensive API discovery and security analysis including endpoint identification,
versioned API discovery, OpenAPI/Swagger detection, authentication enforcement, token analysis,
HTTP method abuse checks, rate limiting detection, error verbosity, and deprecated endpoints.
"""

import requests
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from colorama import Fore, Style, Back
from threading import Thread, Lock
from collections import defaultdict, Counter
import warnings
import base64
import jwt

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

class APIReconAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.hostname = self.parsed_url.netloc.split(':')[0]
        
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'api_endpoints': [],
            'versioned_apis': [],
            'documentation': [],
            'authentication': {},
            'tokens': [],
            'methods_analysis': {},
            'rate_limiting': {},
            'error_analysis': [],
            'deprecated_endpoints': [],
            'api_keys_found': [],
            'security_issues': []
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # API endpoint patterns (200+ patterns)
        self.api_patterns = [
            # REST API patterns
            '/api', '/api/', '/apis', '/apis/',
            '/rest', '/rest/', '/restful',
            '/v1', '/v2', '/v3', '/v4', '/v5',
            '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/v5',
            '/api/v1.0', '/api/v2.0', '/api/v3.0',
            
            # Common API paths
            '/api/users', '/api/user', '/api/accounts', '/api/account',
            '/api/products', '/api/items', '/api/data',
            '/api/auth', '/api/login', '/api/token',
            '/api/status', '/api/health', '/api/ping',
            '/api/search', '/api/query',
            '/api/upload', '/api/download',
            '/api/comments', '/api/posts',
            '/api/messages', '/api/notifications',
            
            # GraphQL
            '/graphql', '/graphql/', '/gql',
            '/api/graphql', '/graphiql',
            '/v1/graphql', '/v2/graphql',
            
            # gRPC
            '/grpc', '/grpc/',
            
            # SOAP
            '/soap', '/soap/', '/ws', '/webservice',
            '/services', '/service',
            
            # Documentation endpoints
            '/swagger', '/swagger/', '/swagger.json', '/swagger.yaml',
            '/swagger-ui', '/swagger-ui.html', '/swagger-ui/',
            '/openapi', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/docs', '/docs', '/documentation',
            '/redoc', '/rapidoc',
            '/api/swagger', '/api/openapi',
            '/api-explorer', '/explorer',
            
            # Admin APIs
            '/admin/api', '/api/admin',
            '/internal/api', '/api/internal',
            '/private/api', '/api/private',
            
            # Mobile APIs
            '/mobile/api', '/api/mobile',
            '/ios/api', '/api/ios',
            '/android/api', '/api/android',
            '/app/api', '/api/app',
            
            # Partner/External APIs
            '/partner/api', '/api/partner',
            '/external/api', '/api/external',
            '/public/api', '/api/public',
            
            # Webhook endpoints
            '/webhook', '/webhooks', '/api/webhook',
            '/callbacks', '/api/callback',
            
            # Health/Status
            '/health', '/healthcheck', '/status',
            '/api/health', '/api/status', '/api/ping',
            '/actuator', '/actuator/health',
            '/metrics', '/api/metrics',
            
            # Common resources
            '/api/customers', '/api/orders', '/api/payments',
            '/api/invoices', '/api/transactions',
            '/api/cart', '/api/checkout',
            '/api/profile', '/api/settings',
            '/api/dashboard', '/api/analytics',
            
            # File operations
            '/api/files', '/api/upload', '/api/download',
            '/api/media', '/api/images',
            '/api/documents', '/api/attachments',
            
            # Version patterns
            '/v1.0', '/v2.0', '/v3.0',
            '/1.0', '/2.0', '/3.0',
            '/version/1', '/version/2',
        ]
        
        # Common API resources
        self.api_resources = [
            'users', 'user', 'accounts', 'account',
            'products', 'product', 'items', 'item',
            'orders', 'order', 'customers', 'customer',
            'posts', 'post', 'comments', 'comment',
            'messages', 'message', 'notifications',
            'files', 'file', 'uploads', 'downloads',
            'settings', 'config', 'profile',
            'auth', 'login', 'logout', 'token',
            'search', 'query', 'results',
            'data', 'info', 'details',
        ]
        
        # HTTP methods to test
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # API key patterns in responses
        self.api_key_patterns = {
            'generic': [
                r'(?i)api[_-]?key[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})',
                r'(?i)apikey[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})',
            ],
            'aws': [
                r'(?i)AKIA[0-9A-Z]{16}',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9/+=]{40})',
            ],
            'google': [
                r'(?i)AIza[0-9A-Za-z\-_]{35}',
            ],
            'stripe': [
                r'(?i)sk_live_[0-9a-zA-Z]{24,}',
                r'(?i)pk_live_[0-9a-zA-Z]{24,}',
            ],
            'slack': [
                r'(?i)xox[baprs]-[0-9a-zA-Z]{10,72}',
            ],
            'github': [
                r'(?i)ghp_[0-9a-zA-Z]{36}',
                r'(?i)gho_[0-9a-zA-Z]{36}',
            ],
            'jwt': [
                r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            ]
        }
        
        # Rate limit headers
        self.rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'X-Rate-Limit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset',
            'Retry-After',
            'X-Retry-After',
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
            for line in details.split('\n'):
                if line.strip():
                    print(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")
    
    def identify_api_endpoints(self):
        """Identify API endpoints"""
        self.print_section("API Endpoint Identification")
        
        loader = LoadingBar(f"Scanning {len(self.api_patterns)} potential API paths")
        loader.start()
        
        discovered_endpoints = []
        
        for pattern in self.api_patterns:
            try:
                test_url = self.base_url + pattern
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Consider these status codes as "found"
                if response.status_code in [200, 201, 400, 401, 403, 404, 405, 500, 501, 502, 503]:
                    endpoint_info = {
                        'url': test_url,
                        'path': pattern,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'length': len(response.text),
                        'is_json': 'application/json' in response.headers.get('Content-Type', ''),
                        'is_xml': 'xml' in response.headers.get('Content-Type', ''),
                        'methods_allowed': self.extract_allowed_methods(response),
                        'requires_auth': response.status_code in [401, 403],
                    }
                    
                    # Extract API version if present
                    version = self.extract_version(pattern, response.text)
                    if version:
                        endpoint_info['version'] = version
                    
                    discovered_endpoints.append(endpoint_info)
            
            except:
                pass
        
        loader.stop(True)
        
        self.results['api_endpoints'] = discovered_endpoints
        
        if discovered_endpoints:
            self.print_check("API Endpoints Found", "PASS", f"{len(discovered_endpoints)} endpoint(s) discovered")
            
            # Categorize endpoints
            json_endpoints = [e for e in discovered_endpoints if e['is_json']]
            auth_required = [e for e in discovered_endpoints if e['requires_auth']]
            
            print(f"\n  {Fore.CYAN}Endpoint Breakdown:{Style.RESET_ALL}")
            print(f"    Total: {len(discovered_endpoints)}")
            print(f"    JSON APIs: {len(json_endpoints)}")
            print(f"    Auth Required: {len(auth_required)}")
            print()
            
            # Show top endpoints
            print(f"  {Fore.CYAN}Discovered Endpoints:{Style.RESET_ALL}")
            for endpoint in discovered_endpoints[:10]:
                status_color = self.get_status_color(endpoint['status'])
                auth_icon = "🔒" if endpoint['requires_auth'] else "🔓"
                print(f"    {auth_icon} {status_color}[{endpoint['status']}]{Style.RESET_ALL} {endpoint['path']}")
            
            if len(discovered_endpoints) > 10:
                print(f"    ... and {len(discovered_endpoints) - 10} more")
            print()
        else:
            self.print_check("API Endpoints", "WARN", "No API endpoints detected")
    
    def get_status_color(self, status_code):
        """Get color for status code"""
        if status_code < 300:
            return Fore.GREEN
        elif status_code < 400:
            return Fore.YELLOW
        elif status_code < 500:
            return Fore.MAGENTA
        else:
            return Fore.RED
    
    def extract_allowed_methods(self, response):
        """Extract allowed HTTP methods"""
        allow_header = response.headers.get('Allow', '')
        if allow_header:
            return [m.strip() for m in allow_header.split(',')]
        return []
    
    def extract_version(self, path, content):
        """Extract API version"""
        # From path
        version_match = re.search(r'/v(\d+(?:\.\d+)?)', path)
        if version_match:
            return version_match.group(1)
        
        # From content
        version_match = re.search(r'"version"\s*:\s*"([^"]+)"', content)
        if version_match:
            return version_match.group(1)
        
        return None
    
    def discover_versioned_apis(self):
        """Discover different API versions"""
        self.print_section("Versioned API Discovery")
        
        loader = LoadingBar("Testing API version patterns")
        loader.start()
        
        versioned_apis = {}
        
        # Test version patterns
        version_patterns = [
            '/api/v{}', '/v{}', '/api/v{}.0', '/v{}.0',
            '/api/{}.0', '/{}.0',
            '/api/version/{}', '/version/{}',
        ]
        
        for i in range(1, 6):  # Test v1 through v5
            for pattern in version_patterns:
                test_path = pattern.format(i)
                try:
                    test_url = self.base_url + test_path
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if response.status_code in [200, 400, 401, 403]:
                        version_info = {
                            'version': f'v{i}',
                            'path': test_path,
                            'url': test_url,
                            'status': response.status_code,
                            'active': response.status_code == 200,
                            'deprecated': 'deprecated' in response.text.lower(),
                            'content_type': response.headers.get('Content-Type', '')
                        }
                        
                        if f'v{i}' not in versioned_apis:
                            versioned_apis[f'v{i}'] = version_info
                            break
                
                except:
                    pass
        
        loader.stop(True)
        
        self.results['versioned_apis'] = list(versioned_apis.values())
        
        if versioned_apis:
            self.print_check("API Versions", "PASS", f"{len(versioned_apis)} version(s) found")
            
            for version, info in versioned_apis.items():
                status_icon = "✓" if info['active'] else "⚠"
                deprecated_label = " (DEPRECATED)" if info['deprecated'] else ""
                print(f"    {status_icon} {version}: {info['path']}{deprecated_label}")
            print()
        else:
            self.print_check("API Versions", "WARN", "No versioned APIs detected")
    
    def detect_api_documentation(self):
        """Detect OpenAPI/Swagger documentation"""
        self.print_section("OpenAPI / Swagger Detection")
        
        loader = LoadingBar("Scanning for API documentation")
        loader.start()
        
        doc_endpoints = [
            # Swagger/OpenAPI
            ('/swagger.json', 'Swagger JSON'),
            ('/swagger.yaml', 'Swagger YAML'),
            ('/swagger.yml', 'Swagger YAML'),
            ('/openapi.json', 'OpenAPI JSON'),
            ('/openapi.yaml', 'OpenAPI YAML'),
            ('/api/swagger.json', 'Swagger JSON'),
            ('/api/openapi.json', 'OpenAPI JSON'),
            ('/v1/swagger.json', 'Swagger v1'),
            ('/v2/swagger.json', 'Swagger v2'),
            ('/v3/swagger.json', 'Swagger v3'),
            
            # UI endpoints
            ('/swagger-ui', 'Swagger UI'),
            ('/swagger-ui.html', 'Swagger UI'),
            ('/swagger-ui/', 'Swagger UI'),
            ('/api-docs', 'API Docs'),
            ('/api/docs', 'API Docs'),
            ('/docs', 'Documentation'),
            ('/documentation', 'Documentation'),
            ('/redoc', 'ReDoc'),
            ('/rapidoc', 'RapiDoc'),
            ('/api-explorer', 'API Explorer'),
            
            # GraphQL
            ('/graphiql', 'GraphiQL'),
            ('/graphql/playground', 'GraphQL Playground'),
            ('/playground', 'GraphQL Playground'),
        ]
        
        documentation_found = []
        
        for path, doc_type in doc_endpoints:
            try:
                test_url = self.base_url + path
                response = self.session.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    doc_info = {
                        'type': doc_type,
                        'url': test_url,
                        'path': path,
                        'size': len(response.text),
                        'accessible': True
                    }
                    
                    # Parse OpenAPI/Swagger spec
                    if path.endswith('.json'):
                        try:
                            spec = response.json()
                            doc_info['spec_version'] = spec.get('swagger') or spec.get('openapi')
                            doc_info['api_title'] = spec.get('info', {}).get('title')
                            doc_info['api_version'] = spec.get('info', {}).get('version')
                            doc_info['endpoints_count'] = len(spec.get('paths', {}))
                        except:
                            pass
                    
                    documentation_found.append(doc_info)
            
            except:
                pass
        
        loader.stop(True)
        
        self.results['documentation'] = documentation_found
        
        if documentation_found:
            self.print_check("API Documentation", "FAIL", 
                           f"{len(documentation_found)} documentation endpoint(s) exposed")
            
            for doc in documentation_found:
                print(f"  📚 {doc['type']}: {doc['url']}")
                if 'api_title' in doc:
                    print(f"      Title: {doc['api_title']}")
                if 'api_version' in doc:
                    print(f"      Version: {doc['api_version']}")
                if 'endpoints_count' in doc:
                    print(f"      Endpoints: {doc['endpoints_count']}")
                print()
        else:
            self.print_check("API Documentation", "PASS", "No public documentation found")
    
    def check_authentication_enforcement(self):
        """Check authentication enforcement"""
        self.print_section("Authentication Enforcement Analysis")
        
        if not self.results['api_endpoints']:
            self.print_check("Authentication", "WARN", "No endpoints to test")
            return
        
        auth_analysis = {
            'no_auth_required': [],
            'auth_required': [],
            'inconsistent': []
        }
        
        # Test endpoints without authentication
        for endpoint in self.results['api_endpoints'][:20]:  # Test first 20
            try:
                # Test without auth
                response_no_auth = self.session.get(endpoint['url'], timeout=5, verify=False)
                
                # Test with invalid token
                headers = {'Authorization': 'Bearer INVALID_TOKEN_12345'}
                response_invalid = self.session.get(endpoint['url'], headers=headers, timeout=5, verify=False)
                
                auth_status = {
                    'endpoint': endpoint['path'],
                    'no_auth_status': response_no_auth.status_code,
                    'invalid_auth_status': response_invalid.status_code,
                }
                
                # Categorize
                if response_no_auth.status_code == 200:
                    auth_analysis['no_auth_required'].append(auth_status)
                elif response_no_auth.status_code in [401, 403]:
                    auth_analysis['auth_required'].append(auth_status)
                
                # Check for inconsistencies
                if response_no_auth.status_code == 200 and response_invalid.status_code == 200:
                    auth_analysis['inconsistent'].append(auth_status)
            
            except:
                pass
        
        self.results['authentication'] = auth_analysis
        
        # Print results
        if auth_analysis['no_auth_required']:
            self.print_check("Authentication Enforcement", "FAIL",
                           f"{len(auth_analysis['no_auth_required'])} endpoint(s) accessible without auth")
            
            for endpoint in auth_analysis['no_auth_required'][:5]:
                print(f"    🔓 {endpoint['endpoint']} [{endpoint['no_auth_status']}]")
            print()
        
        if auth_analysis['auth_required']:
            self.print_check("Protected Endpoints", "PASS",
                           f"{len(auth_analysis['auth_required'])} endpoint(s) require auth")
    
    def analyze_token_placement(self):
        """Analyze token placement and formats"""
        self.print_section("Token Placement & Format Analysis")
        
        tokens_found = []
        
        # Test common endpoints that might return tokens
        token_endpoints = ['/api/auth', '/api/login', '/api/token', '/auth', '/login']
        
        for path in token_endpoints:
            try:
                test_url = self.base_url + path
                
                # Try POST with dummy credentials
                data = {'username': 'test', 'password': 'test'}
                response = self.session.post(test_url, json=data, timeout=5, verify=False)
                
                # Look for tokens in response
                tokens = self.extract_tokens(response.text, response.headers)
                if tokens:
                    tokens_found.extend(tokens)
            
            except:
                pass
        
        # Also check current page for tokens
        try:
            response = self.session.get(self.target_url, timeout=5, verify=False)
            tokens = self.extract_tokens(response.text, response.headers)
            if tokens:
                tokens_found.extend(tokens)
        except:
            pass
        
        self.results['tokens'] = tokens_found
        
        if tokens_found:
            self.print_check("Tokens Found", "WARN", f"{len(tokens_found)} token(s) detected")
            
            for token in tokens_found:
                print(f"  🔑 {token['type']}: {token['location']}")
                print(f"      Format: {token['format']}")
                if 'decoded' in token:
                    print(f"      Decoded: {token['decoded']}")
                print()
        else:
            self.print_check("Token Detection", "PASS", "No exposed tokens found")
    
    def extract_tokens(self, content, headers):
        """Extract tokens from response"""
        tokens = []
        
        # Check for JWT tokens
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        jwt_matches = re.findall(jwt_pattern, content)
        
        for jwt_token in jwt_matches:
            token_info = {
                'type': 'JWT',
                'location': 'Response Body',
                'format': 'JSON Web Token',
                'value': jwt_token[:50] + '...' if len(jwt_token) > 50 else jwt_token
            }
            
            # Try to decode JWT
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                token_info['decoded'] = json.dumps(decoded, indent=2)[:200]
            except:
                pass
            
            tokens.append(token_info)
        
        # Check for Bearer tokens in headers
        auth_header = headers.get('Authorization', '')
        if 'Bearer' in auth_header:
            tokens.append({
                'type': 'Bearer Token',
                'location': 'Authorization Header',
                'format': 'Bearer',
                'value': auth_header[:50] + '...'
            })
        
        # Check for API keys
        for key_type, patterns in self.api_key_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    tokens.append({
                        'type': f'{key_type.upper()} API Key',
                        'location': 'Response Body',
                        'format': key_type,
                        'value': match[:30] + '...' if len(match) > 30 else match
                    })
        
        return tokens
    
    def check_http_method_abuse(self):
        """Check for HTTP method abuse"""
        self.print_section("HTTP Method Abuse Detection")
        
        if not self.results['api_endpoints']:
            self.print_check("Method Testing", "WARN", "No endpoints to test")
            return
        
        method_analysis = {}
        
        # Test first few endpoints with different methods
        test_endpoints = [e for e in self.results['api_endpoints'] if e['status'] == 200][:5]
        
        for endpoint in test_endpoints:
            endpoint_methods = {}
            
            for method in self.http_methods:
                try:
                    response = self.session.request(
                        method, endpoint['url'],
                        timeout=5, verify=False
                    )
                    
                    endpoint_methods[method] = {
                        'status': response.status_code,
                        'allowed': response.status_code != 405,
                        'content_length': len(response.text)
                    }
                
                except:
                    endpoint_methods[method] = {
                        'status': 0,
                        'allowed': False,
                        'content_length': 0
                    }
            
            method_analysis[endpoint['path']] = endpoint_methods
        
        self.results['methods_analysis'] = method_analysis
        
        # Analyze results
        dangerous_methods = []
        
        for path, methods in method_analysis.items():
            # Check for dangerous methods
            if methods.get('PUT', {}).get('allowed'):
                dangerous_methods.append(f"{path}: PUT allowed")
            if methods.get('DELETE', {}).get('allowed'):
                dangerous_methods.append(f"{path}: DELETE allowed")
        
        if dangerous_methods:
            self.print_check("HTTP Methods", "WARN",
                           f"{len(dangerous_methods)} endpoint(s) with risky methods")
            
            for finding in dangerous_methods[:5]:
                print(f"    ⚠ {finding}")
            print()
        else:
            self.print_check("HTTP Methods", "PASS", "No dangerous methods exposed")
    
    def detect_rate_limiting(self):
        """Detect rate limiting"""
        self.print_section("Rate Limit Header Detection")
        
        rate_limit_info = {}
        
        # Test an endpoint
        test_url = self.target_url
        if self.results['api_endpoints']:
            test_url = self.results['api_endpoints'][0]['url']
        
        try:
            # Make multiple requests
            for i in range(5):
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check for rate limit headers
                for header in self.rate_limit_headers:
                    if header in response.headers:
                        if header not in rate_limit_info:
                            rate_limit_info[header] = []
                        rate_limit_info[header].append(response.headers[header])
                
                time.sleep(0.5)
        
        except:
            pass
        
        self.results['rate_limiting'] = rate_limit_info
        
        if rate_limit_info:
            self.print_check("Rate Limiting", "PASS", "Rate limit headers detected")
            
            for header, values in rate_limit_info.items():
                print(f"    ✓ {header}: {values[0]}")
            print()
        else:
            self.print_check("Rate Limiting", "WARN", "No rate limit headers found")
    
    def analyze_api_errors(self):
        """Analyze API error verbosity"""
        self.print_section("API Error Verbosity Analysis")
        
        error_payloads = [
            ('Invalid ID', '/api/users/99999999'),
            ('SQL Injection', "/api/users/1' OR '1'='1"),
            ('Path Traversal', '/api/file?path=../../etc/passwd'),
            ('Invalid JSON', 'INVALID_JSON_DATA'),
        ]
        
        error_responses = []
        
        for error_type, payload in error_payloads:
            try:
                if error_type == 'Invalid JSON':
                    # POST with invalid JSON
                    test_url = self.results['api_endpoints'][0]['url'] if self.results['api_endpoints'] else self.target_url
                    response = self.session.post(
                        test_url,
                        data=payload,
                        headers={'Content-Type': 'application/json'},
                        timeout=5,
                        verify=False
                    )
                else:
                    # GET request
                    test_url = self.base_url + payload
                    response = self.session.get(test_url, timeout=5, verify=False)
                
                # Check for verbose errors
                verbose_indicators = [
                    'stack trace', 'exception', 'traceback',
                    'error:', 'warning:', 'fatal',
                    'line ', 'file ', 'function'
                ]
                
                is_verbose = any(indicator in response.text.lower() for indicator in verbose_indicators)
                
                if is_verbose or len(response.text) > 500:
                    error_responses.append({
                        'type': error_type,
                        'status': response.status_code,
                        'verbose': is_verbose,
                        'length': len(response.text),
                        'sample': response.text[:200]
                    })
            
            except:
                pass
        
        self.results['error_analysis'] = error_responses
        
        if error_responses:
            verbose_errors = [e for e in error_responses if e['verbose']]
            
            if verbose_errors:
                self.print_check("Error Verbosity", "FAIL",
                               f"{len(verbose_errors)} verbose error(s) detected")
                
                for error in verbose_errors:
                    print(f"    ⚠ {error['type']} [{error['status']}]")
                    print(f"       Length: {error['length']} bytes")
                    print(f"       Sample: {error['sample'][:100]}...")
                    print()
            else:
                self.print_check("Error Verbosity", "PASS", "Errors are not verbose")
        else:
            self.print_check("Error Testing", "WARN", "Could not test error responses")
    
    def detect_deprecated_endpoints(self):
        """Detect deprecated endpoints"""
        self.print_section("Deprecated Endpoint Detection")
        
        deprecated = []
        
        for endpoint in self.results['api_endpoints']:
            # Check for deprecation indicators
            try:
                response = self.session.get(endpoint['url'], timeout=5, verify=False)
                
                deprecation_indicators = [
                    'deprecated', 'sunset', 'obsolete',
                    'no longer supported', 'discontinued'
                ]
                
                # Check response
                is_deprecated = any(indicator in response.text.lower() for indicator in deprecation_indicators)
                
                # Check headers
                if 'Sunset' in response.headers or 'Deprecation' in response.headers:
                    is_deprecated = True
                
                if is_deprecated:
                    deprecated.append({
                        'path': endpoint['path'],
                        'url': endpoint['url'],
                        'reason': 'Deprecation indicator found'
                    })
            
            except:
                pass
        
        self.results['deprecated_endpoints'] = deprecated
        
        if deprecated:
            self.print_check("Deprecated Endpoints", "WARN",
                           f"{len(deprecated)} deprecated endpoint(s) found")
            
            for dep in deprecated:
                print(f"    ⚠ {dep['path']}")
            print()
        else:
            self.print_check("Deprecated Endpoints", "PASS", "No deprecated endpoints detected")
    
    def scan_for_api_keys(self):
        """Comprehensive API key scanning"""
        self.print_section("API Key & Secret Detection")
        
        loader = LoadingBar("Scanning for exposed API keys")
        loader.start()
        
        keys_found = []
        
        # Scan main page
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            keys = self.find_api_keys_in_content(response.text)
            if keys:
                keys_found.extend([{**k, 'location': 'Main Page'} for k in keys])
        except:
            pass
        
        # Scan JavaScript files
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
            
            for js_file in js_files[:10]:  # Limit to 10 files
                try:
                    js_url = urljoin(self.target_url, js_file)
                    js_response = self.session.get(js_url, timeout=5, verify=False)
                    keys = self.find_api_keys_in_content(js_response.text)
                    if keys:
                        keys_found.extend([{**k, 'location': js_file} for k in keys])
                except:
                    pass
        except:
            pass
        
        # Scan API endpoints
        for endpoint in self.results['api_endpoints'][:10]:
            try:
                response = self.session.get(endpoint['url'], timeout=5, verify=False)
                keys = self.find_api_keys_in_content(response.text)
                if keys:
                    keys_found.extend([{**k, 'location': endpoint['path']} for k in keys])
            except:
                pass
        
        loader.stop(True)
        
        self.results['api_keys_found'] = keys_found
        
        if keys_found:
            self.print_check("API Keys", "FAIL",
                           f"{len(keys_found)} potential API key(s) exposed")
            
            # Group by type
            by_type = {}
            for key in keys_found:
                key_type = key['type']
                if key_type not in by_type:
                    by_type[key_type] = []
                by_type[key_type].append(key)
            
            for key_type, keys in by_type.items():
                print(f"\n  🔑 {key_type}: {len(keys)} found")
                for key in keys[:3]:
                    print(f"      Location: {key['location']}")
                    print(f"      Value: {key['value'][:40]}...")
                if len(keys) > 3:
                    print(f"      ... and {len(keys) - 3} more")
            print()
        else:
            self.print_check("API Keys", "PASS", "No exposed API keys detected")
    
    def find_api_keys_in_content(self, content):
        """Find API keys in content"""
        keys = []
        
        for key_type, patterns in self.api_key_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    keys.append({
                        'type': key_type,
                        'value': match,
                        'pattern': pattern
                    })
        
        return keys
    
    def generate_security_summary(self):
        """Generate security issues summary"""
        self.print_section("Security Issues Summary")
        
        issues = []
        
        # Check for exposed documentation
        if self.results['documentation']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'API Documentation Exposed',
                'count': len(self.results['documentation']),
                'impact': 'Attackers can enumerate all API endpoints'
            })
        
        # Check for endpoints without auth
        no_auth = self.results.get('authentication', {}).get('no_auth_required', [])
        if no_auth:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Endpoints Without Authentication',
                'count': len(no_auth),
                'impact': 'Unauthorized access to API resources'
            })
        
        # Check for exposed API keys
        if self.results['api_keys_found']:
            issues.append({
                'severity': 'CRITICAL',
                'issue': 'Exposed API Keys',
                'count': len(self.results['api_keys_found']),
                'impact': 'Complete service compromise'
            })
        
        # Check for verbose errors
        verbose_errors = [e for e in self.results.get('error_analysis', []) if e.get('verbose')]
        if verbose_errors:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Verbose Error Messages',
                'count': len(verbose_errors),
                'impact': 'Information disclosure about backend'
            })
        
        # Check for missing rate limiting
        if not self.results['rate_limiting']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'No Rate Limiting Detected',
                'count': 1,
                'impact': 'Vulnerable to brute force and DoS'
            })
        
        self.results['security_issues'] = issues
        
        if issues:
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            issues.sort(key=lambda x: severity_order[x['severity']])
            
            for issue in issues:
                severity_color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN
                }.get(issue['severity'], Fore.WHITE)
                
                print(f"{severity_color}[{issue['severity']}]{Style.RESET_ALL} {issue['issue']}")
                print(f"    Count: {issue['count']}")
                print(f"    Impact: {issue['impact']}")
                print()
        else:
            print(f"{Fore.GREEN}✓ No major security issues detected{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"APIRecon_{hostname}_{timestamp}.txt"
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("API RECONNAISSANCE REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # API Endpoints
        report.append("\n" + "=" * 80)
        report.append("API ENDPOINTS DISCOVERED")
        report.append("=" * 80)
        report.append(f"\nTotal: {len(self.results['api_endpoints'])}")
        
        for endpoint in self.results['api_endpoints']:
            report.append(f"\nPath: {endpoint['path']}")
            report.append(f"  Status: {endpoint['status']}")
            report.append(f"  Content-Type: {endpoint['content_type']}")
            report.append(f"  Auth Required: {endpoint['requires_auth']}")
            if endpoint.get('methods_allowed'):
                report.append(f"  Methods: {', '.join(endpoint['methods_allowed'])}")
        
        # Documentation
        if self.results['documentation']:
            report.append("\n" + "=" * 80)
            report.append("API DOCUMENTATION")
            report.append("=" * 80)
            
            for doc in self.results['documentation']:
                report.append(f"\nType: {doc['type']}")
                report.append(f"  URL: {doc['url']}")
                if 'api_title' in doc:
                    report.append(f"  Title: {doc['api_title']}")
                if 'endpoints_count' in doc:
                    report.append(f"  Endpoints: {doc['endpoints_count']}")
        
        # Security Issues
        if self.results['security_issues']:
            report.append("\n" + "=" * 80)
            report.append("SECURITY ISSUES")
            report.append("=" * 80)
            
            for issue in self.results['security_issues']:
                report.append(f"\n[{issue['severity']}] {issue['issue']}")
                report.append(f"  Count: {issue['count']}")
                report.append(f"  Impact: {issue['impact']}")
        
        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        report.append(f"\nAPI Endpoints: {len(self.results['api_endpoints'])}")
        report.append(f"API Versions: {len(self.results['versioned_apis'])}")
        report.append(f"Documentation: {len(self.results['documentation'])}")
        report.append(f"Tokens Found: {len(self.results['tokens'])}")
        report.append(f"API Keys Found: {len(self.results['api_keys_found'])}")
        report.append(f"Security Issues: {len(self.results['security_issues'])}")
        report.append(f"Scan Duration: {(time.time() - self.results['start_time']):.2f}s")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        # Save JSON version
        json_filepath = filepath.replace('.txt', '.json')
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting API Reconnaissance{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = APIReconAnalyzer(target_url)
    
    # Define scan stages
    stages = [
        ("API Endpoint Identification", analyzer.identify_api_endpoints),
        ("Versioned API Discovery", analyzer.discover_versioned_apis),
        ("OpenAPI/Swagger Detection", analyzer.detect_api_documentation),
        ("Authentication Enforcement", analyzer.check_authentication_enforcement),
        ("Token Placement Analysis", analyzer.analyze_token_placement),
        ("HTTP Method Abuse Checks", analyzer.check_http_method_abuse),
        ("Rate Limit Detection", analyzer.detect_rate_limiting),
        ("API Error Verbosity", analyzer.analyze_api_errors),
        ("Deprecated Endpoints", analyzer.detect_deprecated_endpoints),
        ("API Key Detection", analyzer.scan_for_api_keys),
        ("Security Summary", analyzer.generate_security_summary),
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
        report_path = analyzer.generate_report()
        loader.stop(True)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[✓] API Endpoints: {len(analyzer.results['api_endpoints'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] API Versions: {len(analyzer.results['versioned_apis'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Documentation: {len(analyzer.results['documentation'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Security Issues: {len(analyzer.results['security_issues'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] API Keys Found: {len(analyzer.results['api_keys_found'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Scan Duration: {(time.time() - analyzer.results.get('start_time', time.time())):.2f}s{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python api.py <target_url>")
