#!/usr/bin/env python3
"""
Pre-flight Validation Module
Performs comprehensive pre-flight checks including URL normalization, DNS resolution,
protocol analysis, redirect chains, CDN/WAF detection, and advanced edge-case testing.
"""

import requests
import socket
import dns.resolver
import time
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, Back
from threading import Thread
import warnings
import ssl
import re
import itertools

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

class PreflightValidator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'checks': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Comprehensive CDN/WAF headers list
        self.cdn_headers = {
            'CF-RAY': 'Cloudflare',
            'CF-Cache-Status': 'Cloudflare',
            'CF-Request-ID': 'Cloudflare',
            'X-CDN': 'Generic CDN',
            'X-Cache': 'Cache Service',
            'X-Cache-Hits': 'Cache Service',
            'X-Served-By': 'Cache/CDN',
            'Via': 'Proxy/CDN',
            'X-Fastly-Request-ID': 'Fastly',
            'X-Akamai-Transformed': 'Akamai',
            'X-Akamai-Session-Info': 'Akamai',
            'Server-Timing': 'CDN Performance',
            'X-Edge-Location': 'CDN Edge',
            'X-Cache-Key': 'CDN Cache',
            'X-CDN-Pop': 'CDN Point of Presence',
            'X-CDN-Request-ID': 'CDN',
            'X-Azure-Ref': 'Azure CDN',
            'X-Amz-Cf-Id': 'Amazon CloudFront',
            'X-Amz-Cf-Pop': 'Amazon CloudFront',
            'X-CDN-Provider': 'CDN Provider',
            'X-Edge-IP': 'Edge Server',
            'X-Cache-Status': 'Cache Status',
            'Age': 'Cache Age',
            'X-Varnish': 'Varnish Cache',
            'X-Proxy-Cache': 'Proxy Cache',
            'X-GUploader-UploadID': 'Google Upload',
            'X-Goog-Generation': 'Google Cloud',
            'X-Goog-Metageneration': 'Google Cloud',
            'X-Goog-Stored-Content-Encoding': 'Google Cloud Storage',
            'X-Goog-Stored-Content-Length': 'Google Cloud Storage',
            'X-Sucuri-Cache': 'Sucuri',
            'X-Sucuri-ID': 'Sucuri',
            'X-StackPath-Edge': 'StackPath',
            'X-HW': 'Huawei Cloud',
        }
        
        # Comprehensive WAF headers list
        self.waf_headers = {
            'X-WAF': 'Generic WAF',
            'X-WAF-Event-ID': 'Generic WAF',
            'X-Sucuri-ID': 'Sucuri WAF',
            'X-Sucuri-Cache': 'Sucuri WAF',
            'X-Security': 'Security Service',
            'X-Security-Headers': 'Security Headers',
            'X-WebKnight-WAF': 'WebKnight WAF',
            'X-Denied-Reason': 'WAF Block',
            'X-Block-Reason': 'WAF Block',
            'X-XSS-Protection': 'XSS Filter',
            'X-Content-Security-Policy': 'CSP',
            'X-WebKit-CSP': 'CSP',
            'X-Mod-Security': 'ModSecurity',
            'X-NAXSI-SIG': 'NAXSI WAF',
            'X-DataDome': 'DataDome',
            'X-Distil-CS': 'Distil Networks',
            'X-Protected-By': 'Protection Service',
            'X-Fw-Hash': 'Firewall Hash',
            'X-BotDetect-ChallengeId': 'BotDetect',
            'X-Reblaze': 'Reblaze WAF',
            'X-SL-COMP': 'SafeLine WAF',
        }
        
        # Backend service indicators
        self.backend_indicators = {
            'tomcat': 'Apache Tomcat',
            'jboss': 'JBoss Application Server',
            'weblogic': 'Oracle WebLogic',
            'websphere': 'IBM WebSphere',
            'nginx': 'Nginx',
            'apache': 'Apache HTTP Server',
            'iis': 'Microsoft IIS',
            'lighttpd': 'Lighttpd',
            'jetty': 'Eclipse Jetty',
            'gunicorn': 'Gunicorn',
            'uwsgi': 'uWSGI',
            'passenger': 'Phusion Passenger',
            'puma': 'Puma',
            'unicorn': 'Unicorn',
            'thin': 'Thin',
            'mongrel': 'Mongrel',
            'cherrypy': 'CherryPy',
            'tornado': 'Tornado',
            'node.js': 'Node.js',
            'express': 'Express.js',
            'kestrel': 'Kestrel',
            'glassfish': 'GlassFish',
            'wildfly': 'WildFly',
            'payara': 'Payara',
            'resin': 'Resin',
            'undertow': 'Undertow',
            'netty': 'Netty',
            'vert.x': 'Vert.x',
            'akka': 'Akka HTTP',
            'spring': 'Spring Boot',
            'django': 'Django',
            'flask': 'Flask',
            'rails': 'Ruby on Rails',
            'laravel': 'Laravel',
            'symfony': 'Symfony',
            'asp.net': 'ASP.NET',
            'php': 'PHP',
            'perl': 'Perl',
            'python': 'Python',
            'ruby': 'Ruby',
            'java': 'Java',
            'golang': 'Go',
            'caddy': 'Caddy',
            'haproxy': 'HAProxy',
            'squid': 'Squid Proxy',
            'varnish': 'Varnish',
            'litespeed': 'LiteSpeed',
            'openlitespeed': 'OpenLiteSpeed',
        }
        
        # Debug and internal headers to check
        self.debug_headers = [
            'X-Debug', 'X-Debug-Token', 'X-Debug-Token-Link',
            'X-Internal', 'X-Internal-IP', 'X-Internal-Server',
            'X-Backend', 'X-Backend-Server', 'X-Backend-Host',
            'X-Server-Name', 'X-Server-IP', 'X-Server-ID',
            'X-Powered-By', 'X-Generator', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Drupal-Cache', 'X-Drupal-Dynamic-Cache',
            'X-Varnish', 'X-Varnish-Cache', 'X-Varnish-Host',
            'X-Application-Context', 'X-Runtime', 'X-Request-ID',
            'X-Correlation-ID', 'X-Trace-ID', 'X-B3-TraceId',
            'X-Amzn-Trace-Id', 'X-Cloud-Trace-Context',
            'X-Azure-RequestId', 'X-MS-RequestId',
            'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto',
            'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL',
            'X-Host', 'X-Original-Host', 'X-Forwarded-Server',
            'X-ProxyUser-Ip', 'X-Vercel-Id', 'X-Vercel-Cache',
            'X-Netlify-Id', 'X-NF-Request-ID', 'X-Heroku-Queue-Wait-Time',
            'X-Heroku-Dynos-In-Use', 'X-GitHub-Request-Id',
            'Server-Timing', 'Timing-Allow-Origin',
        ]
        
        # Comprehensive test paths (200+ paths)
        self.test_paths = [
            # Admin panels
            '/admin', '/admin/', '/administrator', '/administrator/',
            '/admin/login', '/admin/dashboard', '/admin/index',
            '/admin.php', '/admin.html', '/admin.asp', '/admin.aspx',
            '/wp-admin', '/wp-admin/', '/wp-login.php',
            '/cpanel', '/cPanel', '/webmail', '/whm',
            '/plesk', '/phpmyadmin', '/phpMyAdmin',
            '/adminer', '/adminer.php',
            '/manage', '/manager', '/management',
            '/control', '/controlpanel', '/control-panel',
            '/supervisor', '/moderator',
            
            # Login pages
            '/login', '/login/', '/signin', '/sign-in',
            '/login.php', '/login.html', '/login.asp', '/login.aspx',
            '/auth', '/auth/', '/authenticate',
            '/user/login', '/account/login', '/member/login',
            '/session/new', '/users/sign_in',
            
            # Config files
            '/config', '/config/', '/config.php', '/config.inc.php',
            '/configuration.php', '/config.json', '/config.yml',
            '/settings', '/settings.php', '/settings.json',
            '/.env', '/.env.local', '/.env.production',
            '/web.config', '/Web.config',
            '/app.config', '/application.yml', '/application.properties',
            '/config.xml', '/configuration.xml',
            
            # Database files
            '/database', '/db', '/mysql', '/mssql', '/oracle',
            '/database.sql', '/backup.sql', '/dump.sql',
            '/db.sqlite', '/database.sqlite', '/db.sqlite3',
            '/.db', '/data.db',
            
            # Backup files
            '/backup', '/backups', '/backup/',
            '/backup.zip', '/backup.tar.gz', '/backup.tar',
            '/site-backup.zip', '/db-backup.sql',
            '/old', '/old_site', '/site.old',
            '/backup_files', '/_backup',
            
            # API endpoints
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/', '/restful',
            '/graphql', '/graphiql',
            '/api/docs', '/api/swagger', '/swagger',
            '/api-docs', '/api/documentation',
            '/v1', '/v2', '/v3',
            
            # Development & Debug
            '/dev', '/develop', '/development',
            '/debug', '/debug/', '/debug.php',
            '/test', '/testing', '/test.php',
            '/staging', '/stage', '/qa',
            '/phpinfo.php', '/info.php', '/test.html',
            '/_profiler', '/profiler',
            
            # Common directories
            '/images', '/img', '/uploads', '/upload',
            '/files', '/file', '/download', '/downloads',
            '/assets', '/static', '/media',
            '/css', '/js', '/javascript',
            '/include', '/includes', '/inc',
            '/library', '/lib', '/libs',
            '/src', '/source', '/app',
            '/tmp', '/temp', '/cache',
            '/log', '/logs', '/log/',
            
            # Framework specific
            '/vendor', '/node_modules', '/bower_components',
            '/.git', '/.git/config', '/.git/HEAD',
            '/.svn', '/.svn/entries',
            '/.hg', '/.bzr',
            '/composer.json', '/composer.lock',
            '/package.json', '/package-lock.json',
            '/yarn.lock', '/Gemfile', '/Gemfile.lock',
            '/requirements.txt', '/setup.py',
            '/pom.xml', '/build.gradle',
            
            # Server files
            '/.htaccess', '/.htpasswd',
            '/robots.txt', '/sitemap.xml',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/humans.txt', '/security.txt',
            '/.well-known', '/.well-known/security.txt',
            
            # CMS specific
            '/wp-content', '/wp-includes',
            '/wp-config.php', '/wp-config.php.bak',
            '/sites/default/settings.php',
            '/typo3', '/typo3conf',
            '/administrator/manifests/files/joomla.xml',
            '/skin', '/var', '/media',
            '/downloader', '/pkginfo',
            
            # Error pages
            '/error', '/errors', '/error.html',
            '/404', '/404.html', '/404.php',
            '/500', '/500.html', '/500.php',
            '/403', '/403.html',
            
            # User endpoints
            '/user', '/users', '/profile', '/account',
            '/dashboard', '/panel', '/portal',
            '/member', '/members', '/membership',
            
            # Mobile & App
            '/mobile', '/app', '/apps',
            '/ios', '/android',
            '/m', '/m/',
            
            # Services
            '/services', '/service', '/webservice',
            '/api/health', '/healthcheck', '/health',
            '/status', '/server-status', '/nginx_status',
            '/metrics', '/actuator', '/actuator/health',
            
            # Documentation
            '/docs', '/doc', '/documentation',
            '/readme', '/README', '/README.md',
            '/changelog', '/CHANGELOG',
            '/license', '/LICENSE',
            
            # Monitoring & Stats
            '/stats', '/statistics', '/analytics',
            '/report', '/reports', '/reporting',
            '/monitor', '/monitoring',
            
            # E-commerce
            '/shop', '/store', '/cart', '/checkout',
            '/product', '/products', '/catalog',
            '/order', '/orders',
            
            # Search & Browse
            '/search', '/browse', '/find',
            '/query', '/results',
            
            # Common files
            '/index.php', '/index.html', '/index.asp',
            '/default.php', '/default.html', '/default.asp',
            '/home.php', '/home.html',
            '/main.php', '/main.html',
            
            # Path traversal tests
            '/../', '/..;/', '/..',
            '/../../../etc/passwd',
            '/..\\..\\..\\windows\\win.ini',
            
            # Special paths
            '/~admin', '/~root', '/~test',
            '/%2e%2e/', '/%252e%252e/',
            
            # Cloud metadata
            '/latest/meta-data', '/latest/user-data',
            '/computeMetadata/v1/',
            
            # Jenkins & CI/CD
            '/jenkins', '/hudson', '/ci',
            '/gitlab', '/github',
            '/job', '/view',
            
            # Version control
            '/.git/HEAD', '/.git/config', '/.git/index',
            '/.svn/entries', '/.svn/wc.db',
            '/.DS_Store',
            
            # Misc important paths
            '/console', '/shell', '/terminal',
            '/phpshell.php', '/c99.php', '/r57.php',
            '/server-info', '/server-status',
            '/.aws', '/.azure', '/.config',
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
    
    def url_normalization(self):
        """Validate and normalize URL"""
        self.print_section("URL Normalization & Validation")
        
        checks = {}
        
        # Scheme validation
        if self.parsed_url.scheme in ['http', 'https']:
            self.print_check("URL Scheme", "PASS", f"Scheme: {self.parsed_url.scheme}")
            checks['scheme'] = self.parsed_url.scheme
        else:
            self.print_check("URL Scheme", "FAIL", f"Invalid scheme: {self.parsed_url.scheme}")
            checks['scheme'] = None
        
        # Hostname validation
        if self.hostname:
            self.print_check("Hostname Extraction", "PASS", f"Hostname: {self.hostname}")
            checks['hostname'] = self.hostname
        else:
            self.print_check("Hostname Extraction", "FAIL", "No hostname found")
            checks['hostname'] = None
        
        # Port detection
        port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        self.print_check("Port Detection", "PASS", f"Port: {port}")
        checks['port'] = port
        
        # Path normalization
        path = self.parsed_url.path or '/'
        self.print_check("Path Normalization", "PASS", f"Path: {path}")
        checks['path'] = path
        
        self.results['checks']['url_normalization'] = checks
        return checks
    
    def dns_resolution(self):
        """Perform DNS resolution and analysis"""
        self.print_section("DNS Resolution & Analysis")
        
        loader = LoadingBar("Resolving DNS records")
        loader.start()
        
        dns_info = {}
        
        # A Record resolution
        try:
            a_records = socket.gethostbyname_ex(self.hostname)
            ip_addresses = a_records[2]
            dns_info['a_records'] = ip_addresses
        except socket.gaierror as e:
            dns_info['a_records'] = []
        
        # Additional DNS records
        record_types = ['AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        resolver = dns.resolver.Resolver()
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(self.hostname, record_type)
                records = [str(rdata) for rdata in answers]
                dns_info[f'{record_type.lower()}_records'] = records
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                dns_info[f'{record_type.lower()}_records'] = []
            except Exception:
                dns_info[f'{record_type.lower()}_records'] = []
        
        loader.stop(True)
        
        # Print results
        if dns_info.get('a_records'):
            self.print_check("A Record Resolution", "PASS", f"IPs: {', '.join(dns_info['a_records'])}")
        else:
            self.print_check("A Record Resolution", "FAIL", "No A records found")
        
        for record_type in record_types:
            records = dns_info.get(f'{record_type.lower()}_records', [])
            if records:
                self.print_check(f"{record_type} Records", "PASS", f"Found {len(records)} record(s)")
        
        self.results['checks']['dns_resolution'] = dns_info
        return dns_info
    
    def http_https_availability(self):
        """Check HTTP and HTTPS availability"""
        self.print_section("HTTP/HTTPS Availability Checks")
        
        availability = {}
        
        # Test both protocols
        protocols = ['http', 'https']
        for protocol in protocols:
            test_url = f"{protocol}://{self.hostname}"
            try:
                response = self.session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                self.print_check(f"{protocol.upper()} Availability", "PASS", 
                               f"Status: {response.status_code}, Server: {response.headers.get('Server', 'Unknown')}")
                availability[protocol] = {
                    'available': True,
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown')
                }
            except requests.exceptions.SSLError as e:
                self.print_check(f"{protocol.upper()} Availability", "WARN", f"SSL Error: {str(e)[:100]}")
                availability[protocol] = {'available': False, 'error': 'SSL Error'}
            except Exception as e:
                self.print_check(f"{protocol.upper()} Availability", "FAIL", str(e)[:100])
                availability[protocol] = {'available': False, 'error': str(e)[:100]}
        
        self.results['checks']['http_https_availability'] = availability
        return availability
    
    def redirect_chain_analysis(self):
        """Analyze redirect chains"""
        self.print_section("Redirect Chain Analysis")
        
        redirect_chain = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False, allow_redirects=True)
            
            if response.history:
                self.print_check("Redirect Detection", "PASS", f"Found {len(response.history)} redirect(s)")
                
                for i, resp in enumerate(response.history, 1):
                    redirect_info = {
                        'step': i,
                        'url': resp.url,
                        'status_code': resp.status_code,
                        'location': resp.headers.get('Location', '')
                    }
                    redirect_chain.append(redirect_info)
                    print(f"    {Fore.YELLOW}[{i}]{Style.RESET_ALL} {resp.url} → {resp.status_code} → {resp.headers.get('Location', 'N/A')}")
                
                print(f"    {Fore.GREEN}[Final]{Style.RESET_ALL} {response.url} ({response.status_code})")
            else:
                self.print_check("Redirect Detection", "PASS", "No redirects detected")
        except Exception as e:
            self.print_check("Redirect Chain Analysis", "FAIL", str(e))
        
        self.results['checks']['redirect_chain'] = redirect_chain
        return redirect_chain
    
    def cdn_waf_detection(self):
        """Detect CDN and WAF presence"""
        self.print_section("CDN / WAF Detection")
        
        loader = LoadingBar("Scanning for CDN/WAF indicators")
        loader.start()
        
        detection_results = {
            'cdn': [],
            'waf': [],
            'indicators': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Check for CDN headers
            for header, service in self.cdn_headers.items():
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    if service not in detection_results['cdn']:
                        detection_results['cdn'].append(service)
                    value = response.headers.get(header)
                    detection_results['indicators'].append(f"CDN: {service} ({header}: {value})")
            
            # Check for WAF headers
            for header, service in self.waf_headers.items():
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    if service not in detection_results['waf']:
                        detection_results['waf'].append(service)
                    value = response.headers.get(header)
                    detection_results['indicators'].append(f"WAF: {service} ({header}: {value})")
            
            # Server header analysis
            server = response.headers.get('Server', '').lower()
            x_powered = response.headers.get('X-Powered-By', '').lower()
            
            # Check server header for backend indicators
            for indicator, service in self.backend_indicators.items():
                if indicator in server or indicator in x_powered:
                    detection_results['indicators'].append(f"Backend: {service}")
            
            loader.stop(True)
            
            # Print results
            if detection_results['cdn']:
                for cdn in set(detection_results['cdn']):
                    self.print_check("CDN Detection", "PASS", f"{cdn} detected")
            else:
                self.print_check("CDN Detection", "WARN", "No CDN detected")
            
            if detection_results['waf']:
                for waf in set(detection_results['waf']):
                    self.print_check("WAF Detection", "PASS", f"{waf} detected")
            else:
                self.print_check("WAF Detection", "WARN", "No WAF detected")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("CDN/WAF Detection", "FAIL", str(e))
        
        self.results['checks']['cdn_waf_detection'] = detection_results
        return detection_results
    
    def protocol_downgrade_check(self):
        """Test protocol downgrade and port confusion"""
        self.print_section("Protocol Downgrade & Port Confusion Analysis")
        
        loader = LoadingBar("Testing protocol downgrade scenarios")
        loader.start()
        
        downgrade_results = {}
        
        # Test HTTP when HTTPS is expected
        if self.parsed_url.scheme == 'https':
            http_url = f"http://{self.hostname}"
            try:
                response = self.session.get(http_url, timeout=10, verify=False, allow_redirects=False)
                if response.status_code in [301, 302, 307, 308]:
                    downgrade_results['http_redirect'] = True
                else:
                    downgrade_results['http_redirect'] = False
            except Exception as e:
                downgrade_results['http_redirect'] = None
        
        # Test alternate ports
        alternate_ports = [8080, 8443, 8000, 8888, 3000, 5000, 9000]
        port_results = {}
        
        for port in alternate_ports:
            test_url = f"{self.parsed_url.scheme}://{self.hostname}:{port}"
            try:
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                port_results[port] = {'accessible': True, 'status': response.status_code}
            except:
                port_results[port] = {'accessible': False}
        
        downgrade_results['alternate_ports'] = port_results
        
        loader.stop(True)
        
        # Print results
        if self.parsed_url.scheme == 'https':
            if downgrade_results.get('http_redirect'):
                self.print_check("HTTP→HTTPS Redirect", "PASS", "Redirects to HTTPS")
            elif downgrade_results.get('http_redirect') is False:
                self.print_check("HTTP→HTTPS Redirect", "WARN", "HTTP accessible without redirect")
        
        accessible_ports = [p for p, data in port_results.items() if data.get('accessible')]
        if accessible_ports:
            for port in accessible_ports:
                self.print_check(f"Port {port} Access", "WARN", f"Accessible (Status: {port_results[port]['status']})")
        else:
            self.print_check("Alternate Ports", "PASS", "No alternate ports accessible")
        
        self.results['checks']['protocol_downgrade'] = downgrade_results
        return downgrade_results
    
    def host_header_analysis(self):
        """Analyze Host header trust and virtual host leakage"""
        self.print_section("Host Header Trust & Virtual Host Analysis")
        
        loader = LoadingBar("Testing Host header manipulation")
        loader.start()
        
        host_results = {}
        
        # Test with manipulated Host headers
        test_hosts = [
            ('invalid.example.com', 'Invalid Host'),
            ('localhost', 'Localhost'),
            (f'staging.{self.hostname}', 'Staging Subdomain'),
            (f'internal.{self.hostname}', 'Internal Subdomain'),
            (f'admin.{self.hostname}', 'Admin Subdomain'),
            (f'dev.{self.hostname}', 'Development Subdomain'),
        ]
        
        baseline_response = None
        try:
            baseline_response = self.session.get(self.target_url, timeout=10, verify=False)
            baseline_length = len(baseline_response.content)
        except:
            baseline_length = 0
        
        for test_host, description in test_hosts:
            try:
                headers = {'Host': test_host}
                response = self.session.get(self.target_url, headers=headers, timeout=10, verify=False)
                
                response_diff = abs(len(response.content) - baseline_length)
                if response_diff > 100:  # Significant difference
                    host_results[test_host] = {'different': True, 'delta': response_diff, 'status': response.status_code}
                else:
                    host_results[test_host] = {'different': False, 'delta': response_diff, 'status': response.status_code}
            except Exception as e:
                host_results[test_host] = {'error': str(e)[:100]}
        
        loader.stop(True)
        
        # Print results
        for test_host, description in test_hosts:
            if test_host in host_results:
                result = host_results[test_host]
                if result.get('different'):
                    self.print_check(f"{description} Host Header", "WARN", 
                                   f"Different response (Δ {result['delta']} bytes, Status: {result.get('status', 'N/A')})")
                elif 'error' not in result:
                    self.print_check(f"{description} Host Header", "PASS", "Same response as baseline")
        
        self.results['checks']['host_header_analysis'] = host_results
        return host_results
    
    def differential_response_profiling(self):
        """Baseline profiling for soft-404 and custom error detection"""
        self.print_section("Differential Response Baseline Profiling")
        
        loader = LoadingBar(f"Testing {len(self.test_paths)} paths")
        loader.start()
        
        profile_results = {
            'paths_tested': len(self.test_paths),
            'accessible_paths': [],
            'soft_404s': [],
            'redirects': [],
            'interesting_findings': []
        }
        
        interesting_status_codes = [200, 201, 301, 302, 307, 308, 401, 403, 500, 503]
        
        for idx, path in enumerate(self.test_paths):
            try:
                test_url = urljoin(self.target_url, path)
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)
                
                # Track interesting responses
                if response.status_code in interesting_status_codes:
                    finding = {
                        'path': path,
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    }
                    
                    if response.status_code == 200:
                        # Check for soft-404
                        is_soft_404 = (
                            'not found' in response.text.lower() or 
                            'error' in response.text.lower()[:500] or
                            '404' in response.text[:1000]
                        )
                        
                        if is_soft_404:
                            profile_results['soft_404s'].append(finding)
                        else:
                            profile_results['accessible_paths'].append(finding)
                            profile_results['interesting_findings'].append(finding)
                    
                    elif response.status_code in [301, 302, 307, 308]:
                        finding['location'] = response.headers.get('Location', '')
                        profile_results['redirects'].append(finding)
                    
                    elif response.status_code in [401, 403]:
                        profile_results['interesting_findings'].append(finding)
                
            except:
                pass
        
        loader.stop(True)
        
        # Print summary
        self.print_check("Total Paths Tested", "PASS", str(len(self.test_paths)))
        self.print_check("Accessible Paths (200)", "PASS" if profile_results['accessible_paths'] else "WARN", 
                        str(len(profile_results['accessible_paths'])))
        self.print_check("Soft-404 Detected", "WARN" if profile_results['soft_404s'] else "PASS", 
                        str(len(profile_results['soft_404s'])))
        self.print_check("Redirects Found", "PASS" if profile_results['redirects'] else "WARN", 
                        str(len(profile_results['redirects'])))
        self.print_check("Interesting Findings", "PASS" if profile_results['interesting_findings'] else "WARN", 
                        str(len(profile_results['interesting_findings'])))
        
        # Print some interesting findings
        if profile_results['accessible_paths']:
            print(f"\n{Fore.YELLOW}  Notable Accessible Paths:{Style.RESET_ALL}")
            for finding in profile_results['accessible_paths'][:10]:
                print(f"    {Fore.GREEN}[{finding['status_code']}]{Style.RESET_ALL} {finding['path']} ({finding['content_length']} bytes)")
        
        # Test unsupported methods
        print(f"\n{Fore.YELLOW}  HTTP Methods Analysis:{Style.RESET_ALL}")
        methods = ['TRACE', 'OPTIONS', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'CONNECT']
        for method in methods:
            try:
                response = self.session.request(method, self.target_url, timeout=5, verify=False)
                self.print_check(f"Method: {method}", "PASS", f"Status: {response.status_code}")
                profile_results[f'method_{method}'] = {'status_code': response.status_code}
            except:
                profile_results[f'method_{method}'] = {'blocked': True}
        
        self.results['checks']['differential_profiling'] = profile_results
        return profile_results
    
    def time_based_profiling(self):
        """Measure latency and timing patterns"""
        self.print_section("Time-Based Behavior Profiling")
        
        timing_results = {}
        
        # Baseline timing
        timings = []
        for i in range(5):
            start = time.time()
            try:
                self.session.get(self.target_url, timeout=10, verify=False)
                elapsed = time.time() - start
                timings.append(elapsed)
            except:
                pass
        
        if timings:
            avg_time = sum(timings) / len(timings)
            min_time = min(timings)
            max_time = max(timings)
            
            self.print_check("Baseline Latency", "PASS", 
                           f"Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")
            timing_results['baseline'] = {
                'average': avg_time,
                'min': min_time,
                'max': max_time,
                'samples': timings
            }
        
        # Cache bypass test
        try:
            start = time.time()
            headers = {'Cache-Control': 'no-cache', 'Pragma': 'no-cache'}
            self.session.get(self.target_url, headers=headers, timeout=10, verify=False)
            cache_bypass_time = time.time() - start
            
            if timings and cache_bypass_time > avg_time * 1.5:
                self.print_check("Cache Bypass Latency", "WARN", 
                               f"Significantly slower: {cache_bypass_time:.3f}s (potential caching)")
            else:
                self.print_check("Cache Bypass Latency", "PASS", f"Time: {cache_bypass_time:.3f}s")
            
            timing_results['cache_bypass'] = cache_bypass_time
        except:
            pass
        
        self.results['checks']['time_based_profiling'] = timing_results
        return timing_results
    
    def trust_boundary_detection(self):
        """Detect internal IP leaks and backend service exposure"""
        self.print_section("Trust Boundary Indicator Detection")
        
        loader = LoadingBar("Analyzing response headers and content")
        loader.start()
        
        boundary_results = {
            'internal_ips': [],
            'debug_headers': [],
            'backend_indicators': [],
            'sensitive_info': []
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Check for internal IPs in response body and headers
            ip_pattern = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
            
            # Check response body
            internal_ips_body = re.findall(ip_pattern, response.text[:10000])
            if internal_ips_body:
                boundary_results['internal_ips'].extend(list(set(internal_ips_body)))
            
            # Check all headers
            for header, value in response.headers.items():
                internal_ips_header = re.findall(ip_pattern, str(value))
                if internal_ips_header:
                    boundary_results['internal_ips'].extend(internal_ips_header)
            
            loader.stop(True)
            
            if boundary_results['internal_ips']:
                for ip in set(boundary_results['internal_ips']):
                    self.print_check("Internal IP Leakage", "WARN", f"Found: {ip}")
            else:
                self.print_check("Internal IP Leakage", "PASS", "No internal IPs found")
            
            # Check for debug/internal headers
            print(f"\n{Fore.YELLOW}  Debug & Internal Headers Analysis:{Style.RESET_ALL}")
            found_headers = []
            for header in self.debug_headers:
                header_value = None
                for resp_header, resp_value in response.headers.items():
                    if resp_header.lower() == header.lower():
                        header_value = resp_value
                        break
                
                if header_value:
                    self.print_check(f"Header: {header}", "WARN", f"Value: {header_value[:100]}")
                    found_headers.append({header: header_value})
                    boundary_results['debug_headers'].append({header: header_value})
            
            if not found_headers:
                self.print_check("Debug Headers", "PASS", "No debug headers found")
            
            # Check for backend service indicators
            print(f"\n{Fore.YELLOW}  Backend Service Indicators:{Style.RESET_ALL}")
            server_header = response.headers.get('Server', '').lower()
            x_powered = response.headers.get('X-Powered-By', '').lower()
            
            found_backends = []
            for indicator, service in self.backend_indicators.items():
                if indicator in server_header or indicator in x_powered:
                    if service not in found_backends:
                        self.print_check("Backend Service", "PASS", f"Detected: {service}")
                        found_backends.append(service)
                        boundary_results['backend_indicators'].append(service)
            
            if not found_backends:
                self.print_check("Backend Services", "WARN", "No specific backend detected")
            
            # Check for sensitive information patterns
            sensitive_patterns = {
                'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'api_key': r'(?i)(api[_-]?key|apikey|api[_-]?token)[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
                'aws_key': r'(?i)(AKIA[0-9A-Z]{16})',
                'private_key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            }
            
            for pattern_name, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response.text[:50000])
                if matches:
                    boundary_results['sensitive_info'].append({
                        'type': pattern_name,
                        'count': len(matches)
                    })
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Trust Boundary Detection", "FAIL", str(e))
        
        self.results['checks']['trust_boundary_detection'] = boundary_results
        return boundary_results
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"PreFlight_{hostname}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("PRE-FLIGHT VALIDATION REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # Add all check results
        for check_name, check_data in self.results['checks'].items():
            report.append(f"\n{check_name.upper().replace('_', ' ')}")
            report.append("-" * 80)
            report.append(json.dumps(check_data, indent=2))
            report.append("")
        
        # Add summary statistics
        report.append("\n" + "=" * 80)
        report.append("SUMMARY STATISTICS")
        report.append("=" * 80)
        
        # Calculate summary
        if 'differential_profiling' in self.results['checks']:
            prof = self.results['checks']['differential_profiling']
            report.append(f"\nPath Discovery:")
            report.append(f"  - Total Paths Tested: {prof.get('paths_tested', 0)}")
            report.append(f"  - Accessible Paths: {len(prof.get('accessible_paths', []))}")
            report.append(f"  - Soft-404s: {len(prof.get('soft_404s', []))}")
            report.append(f"  - Redirects: {len(prof.get('redirects', []))}")
            report.append(f"  - Interesting Findings: {len(prof.get('interesting_findings', []))}")
        
        if 'cdn_waf_detection' in self.results['checks']:
            cdn_waf = self.results['checks']['cdn_waf_detection']
            report.append(f"\nSecurity Services:")
            report.append(f"  - CDN Detected: {', '.join(cdn_waf.get('cdn', [])) if cdn_waf.get('cdn') else 'None'}")
            report.append(f"  - WAF Detected: {', '.join(cdn_waf.get('waf', [])) if cdn_waf.get('waf') else 'None'}")
        
        if 'trust_boundary_detection' in self.results['checks']:
            trust = self.results['checks']['trust_boundary_detection']
            report.append(f"\nTrust Boundary Issues:")
            report.append(f"  - Internal IPs Leaked: {len(set(trust.get('internal_ips', [])))}")
            report.append(f"  - Debug Headers Found: {len(trust.get('debug_headers', []))}")
            report.append(f"  - Backend Services: {len(trust.get('backend_indicators', []))}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting Pre-flight Validation{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    validator = PreflightValidator(target_url)
    
    # Define scan stages
    stages = [
        ("URL Normalization & Validation", validator.url_normalization),
        ("DNS Resolution & Analysis", validator.dns_resolution),
        ("HTTP/HTTPS Availability", validator.http_https_availability),
        ("Redirect Chain Analysis", validator.redirect_chain_analysis),
        ("CDN / WAF Detection", validator.cdn_waf_detection),
        ("Protocol Downgrade Check", validator.protocol_downgrade_check),
        ("Host Header Analysis", validator.host_header_analysis),
        ("Differential Response Profiling", validator.differential_response_profiling),
        ("Time-Based Profiling", validator.time_based_profiling),
        ("Trust Boundary Detection", validator.trust_boundary_detection),
    ]
    
    progress = ProgressBar(len(stages))
    
    try:
        # Run all checks
        for stage_name, stage_func in stages:
            progress.update(stage_name)
            stage_func()
            time.sleep(0.5)  # Brief pause for visual effect
        
        # Generate report
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  Finalizing Report")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        loader = LoadingBar("Generating comprehensive report")
        loader.start()
        time.sleep(1)
        report_path = validator.generate_report()
        loader.stop(True)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[✓] Total Checks Performed: {len(stages)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Scan Duration: {(time.time() - validator.results.get('start_time', time.time())):.2f}s{Style.RESET_ALL}")
        
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
        print("Usage: python preflight.py <target_url>")
