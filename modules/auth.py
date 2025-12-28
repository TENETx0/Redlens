#!/usr/bin/env python3
"""
Authentication & Session Analysis Module
Performs comprehensive authentication and session security analysis including
login mechanism identification, session cookie analysis, security flag validation,
token entropy testing, timeout behavior, and logout invalidation testing.
"""

import requests
import json
import os
import sys
import time
import re
import hashlib
import math
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style, Back
from threading import Thread, Lock
from collections import defaultdict, Counter
import warnings
import base64
import secrets

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

class AuthSessionAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.hostname = self.parsed_url.netloc.split(':')[0]
        
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'login_mechanisms': [],
            'authentication_flows': [],
            'session_cookies': [],
            'security_flags': {},
            'token_analysis': {},
            'session_behavior': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Login patterns
        self.login_patterns = {
            'endpoints': [
                '/login', '/signin', '/sign-in', '/auth', '/authenticate',
                '/session/new', '/account/login', '/user/login',
                '/admin/login', '/wp-login.php', '/administrator'
            ],
            'form_actions': [
                'login', 'signin', 'auth', 'authenticate', 'session',
                'log-in', 'sign-in'
            ],
            'input_names': {
                'username': ['username', 'user', 'login', 'email', 'userid', 'uname'],
                'password': ['password', 'passwd', 'pwd', 'pass']
            }
        }
        
        # Session cookie patterns
        self.session_cookie_patterns = [
            'session', 'sess', 'sessionid', 'sid', 'phpsessid',
            'jsessionid', 'asp.net_sessionid', 'aspsessionid',
            'connect.sid', '_session', 'auth', 'token', 'jwt',
            'access_token', 'refresh_token', 'remember',
            'laravel_session', 'symfony', 'django_session',
            'rails_session', 'express-session'
        ]
        
        # Security headers to check
        self.security_headers = [
            'Strict-Transport-Security', 'X-Frame-Options',
            'X-Content-Type-Options', 'Content-Security-Policy',
            'X-XSS-Protection', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Opener-Policy'
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
    
    def identify_login_mechanisms(self):
        """Identify login pages and mechanisms"""
        self.print_section("Login Mechanism Identification")
        
        loader = LoadingBar("Scanning for login endpoints")
        loader.start()
        
        login_endpoints = []
        
        # Test common login paths
        for path in self.login_patterns['endpoints']:
            try:
                url = self.base_url + path
                response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                
                if response.status_code == 200:
                    # Check if it's a login page
                    content = response.text.lower()
                    
                    # Look for login indicators
                    login_indicators = [
                        'password', 'username', 'login', 'sign in',
                        'authenticate', 'type="password"', 'name="password"'
                    ]
                    
                    indicator_count = sum(1 for indicator in login_indicators if indicator in content)
                    
                    if indicator_count >= 2:  # At least 2 indicators
                        login_info = {
                            'url': response.url,
                            'path': path,
                            'status': response.status_code,
                            'method': 'GET',
                            'indicators': indicator_count,
                            'forms': []
                        }
                        
                        # Extract forms
                        forms = self.extract_login_forms(response.text, response.url)
                        login_info['forms'] = forms
                        
                        login_endpoints.append(login_info)
            except:
                pass
        
        loader.stop(True)
        
        self.results['login_mechanisms'] = login_endpoints
        
        if login_endpoints:
            self.print_check("Login Endpoints Found", "PASS", f"{len(login_endpoints)} endpoint(s) discovered")
            for endpoint in login_endpoints:
                print(f"    {Fore.GREEN}→{Style.RESET_ALL} {endpoint['url']}")
                if endpoint['forms']:
                    print(f"      Forms: {len(endpoint['forms'])}")
        else:
            self.print_check("Login Endpoints", "WARN", "No login pages detected")
    
    def extract_login_forms(self, html, base_url):
        """Extract login forms from HTML"""
        from bs4 import BeautifulSoup
        
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'fields': [],
                    'has_password': False,
                    'has_username': False,
                    'csrf_token': None,
                    'remember_me': False
                }
                
                # Extract form fields
                for input_tag in form.find_all(['input', 'textarea']):
                    field = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'id': input_tag.get('id', ''),
                        'required': input_tag.has_attr('required')
                    }
                    
                    if field['name']:
                        form_data['fields'].append(field)
                        
                        # Check for password field
                        if field['type'] == 'password':
                            form_data['has_password'] = True
                        
                        # Check for username field
                        field_name_lower = field['name'].lower()
                        if any(un in field_name_lower for un in self.login_patterns['input_names']['username']):
                            form_data['has_username'] = True
                        
                        # Check for CSRF token
                        if 'csrf' in field_name_lower or 'token' in field_name_lower:
                            form_data['csrf_token'] = field['name']
                        
                        # Check for remember me
                        if 'remember' in field_name_lower:
                            form_data['remember_me'] = True
                
                # Only add if it looks like a login form
                if form_data['has_password']:
                    forms.append(form_data)
        
        except Exception as e:
            pass
        
        return forms
    
    def map_authentication_flow(self):
        """Map authentication flow"""
        self.print_section("Authentication Flow Mapping")
        
        if not self.results['login_mechanisms']:
            self.print_check("Authentication Flow", "WARN", "No login mechanisms found to analyze")
            return
        
        flows = []
        
        for login_mech in self.results['login_mechanisms']:
            for form in login_mech['forms']:
                flow = {
                    'login_url': login_mech['url'],
                    'action_url': form['action'],
                    'method': form['method'],
                    'fields': form['fields'],
                    'csrf_protection': form['csrf_token'] is not None,
                    'remember_me': form['remember_me'],
                    'security_features': []
                }
                
                # Check security features
                if form['csrf_token']:
                    flow['security_features'].append(f"CSRF Token: {form['csrf_token']}")
                
                if form['remember_me']:
                    flow['security_features'].append("Remember Me option")
                
                # Check if HTTPS
                if login_mech['url'].startswith('https://'):
                    flow['security_features'].append("HTTPS encrypted")
                else:
                    flow['security_features'].append("⚠ HTTP (not encrypted)")
                
                flows.append(flow)
                
                # Print flow details
                print(f"{Fore.CYAN}Flow: {login_mech['url']}{Style.RESET_ALL}")
                print(f"  Action: {form['action']}")
                print(f"  Method: {form['method']}")
                print(f"  Fields: {len(form['fields'])}")
                if flow['security_features']:
                    print(f"  Security:")
                    for feature in flow['security_features']:
                        if '⚠' in feature:
                            print(f"    {Fore.RED}{feature}{Style.RESET_ALL}")
                        else:
                            print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {feature}")
                print()
        
        self.results['authentication_flows'] = flows
        self.print_check("Authentication Flows Mapped", "PASS", f"{len(flows)} flow(s) analyzed")
    
    def analyze_session_cookies(self):
        """Analyze session cookies"""
        self.print_section("Session Cookie Discovery & Analysis")
        
        loader = LoadingBar("Collecting cookies from target")
        loader.start()
        
        # Make requests to collect cookies
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Also check login pages
            for login_mech in self.results['login_mechanisms']:
                try:
                    self.session.get(login_mech['url'], timeout=10, verify=False)
                except:
                    pass
        except:
            pass
        
        loader.stop(True)
        
        # Analyze collected cookies
        session_cookies = []
        
        for cookie in self.session.cookies:
            cookie_name_lower = cookie.name.lower()
            
            # Check if it's a session cookie
            is_session = any(pattern in cookie_name_lower for pattern in self.session_cookie_patterns)
            
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
                'samesite': self.get_samesite_attr(cookie),
                'expires': cookie.expires,
                'is_session_cookie': is_session,
                'length': len(cookie.value),
                'entropy': self.calculate_entropy(cookie.value),
                'security_score': 0
            }
            
            # Calculate security score
            score = 0
            if cookie_info['secure']:
                score += 30
            if cookie_info['httponly']:
                score += 30
            if cookie_info['samesite'] in ['Strict', 'Lax']:
                score += 20
            if cookie_info['entropy'] > 3.5:
                score += 20
            
            cookie_info['security_score'] = score
            
            session_cookies.append(cookie_info)
        
        self.results['session_cookies'] = session_cookies
        
        if session_cookies:
            self.print_check("Cookies Discovered", "PASS", f"{len(session_cookies)} cookie(s) found")
            
            print(f"\n{Fore.YELLOW}Cookie Details:{Style.RESET_ALL}\n")
            
            for cookie in session_cookies:
                # Determine if it's a session cookie
                cookie_type = "🔑 Session" if cookie['is_session_cookie'] else "🍪 Regular"
                
                print(f"{cookie_type} Cookie: {Fore.CYAN}{cookie['name']}{Style.RESET_ALL}")
                print(f"  Value Length: {cookie['length']} chars")
                print(f"  Entropy: {cookie['entropy']:.2f} bits")
                print(f"  Security Score: {self.get_score_color(cookie['security_score'])}{cookie['security_score']}/100{Style.RESET_ALL}")
                
                # Security flags
                print(f"  Flags:")
                print(f"    Secure: {self.get_flag_status(cookie['secure'])}")
                print(f"    HttpOnly: {self.get_flag_status(cookie['httponly'])}")
                print(f"    SameSite: {self.get_samesite_status(cookie['samesite'])}")
                
                print()
        else:
            self.print_check("Cookies", "WARN", "No cookies set by target")
    
    def get_samesite_attr(self, cookie):
        """Extract SameSite attribute from cookie"""
        # Try to get SameSite attribute
        samesite = None
        if hasattr(cookie, '_rest') and 'samesite' in cookie._rest:
            samesite = cookie._rest['samesite']
        elif hasattr(cookie, 'get_nonstandard_attr'):
            samesite = cookie.get_nonstandard_attr('SameSite')
        
        return samesite if samesite else 'None'
    
    def get_flag_status(self, enabled):
        """Get colored flag status"""
        if enabled:
            return f"{Fore.GREEN}✓ Enabled{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}✗ Disabled{Style.RESET_ALL}"
    
    def get_samesite_status(self, value):
        """Get colored SameSite status"""
        if value == 'Strict':
            return f"{Fore.GREEN}✓ Strict{Style.RESET_ALL}"
        elif value == 'Lax':
            return f"{Fore.YELLOW}⚠ Lax{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}✗ None{Style.RESET_ALL}"
    
    def get_score_color(self, score):
        """Get color based on security score"""
        if score >= 80:
            return Fore.GREEN
        elif score >= 50:
            return Fore.YELLOW
        else:
            return Fore.RED
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def validate_security_flags(self):
        """Validate cookie security flags"""
        self.print_section("Security Flag Validation")
        
        if not self.results['session_cookies']:
            self.print_check("Security Flags", "WARN", "No cookies to validate")
            return
        
        flag_analysis = {
            'secure_flag': {'enabled': 0, 'disabled': 0},
            'httponly_flag': {'enabled': 0, 'disabled': 0},
            'samesite_attr': {'strict': 0, 'lax': 0, 'none': 0}
        }
        
        vulnerabilities = []
        
        for cookie in self.results['session_cookies']:
            # Secure flag
            if cookie['secure']:
                flag_analysis['secure_flag']['enabled'] += 1
            else:
                flag_analysis['secure_flag']['disabled'] += 1
                if cookie['is_session_cookie']:
                    vulnerabilities.append({
                        'type': 'Missing Secure Flag',
                        'severity': 'HIGH',
                        'cookie': cookie['name'],
                        'description': 'Session cookie transmitted over unencrypted connections',
                        'impact': 'Cookie can be intercepted via man-in-the-middle attacks'
                    })
            
            # HttpOnly flag
            if cookie['httponly']:
                flag_analysis['httponly_flag']['enabled'] += 1
            else:
                flag_analysis['httponly_flag']['disabled'] += 1
                if cookie['is_session_cookie']:
                    vulnerabilities.append({
                        'type': 'Missing HttpOnly Flag',
                        'severity': 'MEDIUM',
                        'cookie': cookie['name'],
                        'description': 'Session cookie accessible via JavaScript',
                        'impact': 'Cookie vulnerable to XSS attacks'
                    })
            
            # SameSite attribute
            samesite = cookie['samesite']
            if samesite == 'Strict':
                flag_analysis['samesite_attr']['strict'] += 1
            elif samesite == 'Lax':
                flag_analysis['samesite_attr']['lax'] += 1
            else:
                flag_analysis['samesite_attr']['none'] += 1
                if cookie['is_session_cookie']:
                    vulnerabilities.append({
                        'type': 'Missing SameSite Attribute',
                        'severity': 'MEDIUM',
                        'cookie': cookie['name'],
                        'description': 'Cookie sent with cross-site requests',
                        'impact': 'Vulnerable to CSRF attacks'
                    })
        
        self.results['security_flags'] = flag_analysis
        self.results['vulnerabilities'].extend(vulnerabilities)
        
        # Print summary
        total_cookies = len(self.results['session_cookies'])
        
        print(f"{Fore.CYAN}Secure Flag Analysis:{Style.RESET_ALL}")
        self.print_check(
            f"Cookies with Secure flag",
            "PASS" if flag_analysis['secure_flag']['enabled'] == total_cookies else "FAIL",
            f"{flag_analysis['secure_flag']['enabled']}/{total_cookies} cookies"
        )
        
        print(f"\n{Fore.CYAN}HttpOnly Flag Analysis:{Style.RESET_ALL}")
        self.print_check(
            f"Cookies with HttpOnly flag",
            "PASS" if flag_analysis['httponly_flag']['enabled'] == total_cookies else "FAIL",
            f"{flag_analysis['httponly_flag']['enabled']}/{total_cookies} cookies"
        )
        
        print(f"\n{Fore.CYAN}SameSite Attribute Analysis:{Style.RESET_ALL}")
        print(f"  Strict: {flag_analysis['samesite_attr']['strict']}")
        print(f"  Lax: {flag_analysis['samesite_attr']['lax']}")
        print(f"  None: {flag_analysis['samesite_attr']['none']}")
    
    def analyze_token_strength(self):
        """Analyze token length and entropy"""
        self.print_section("Token Length & Entropy Analysis")
        
        if not self.results['session_cookies']:
            self.print_check("Token Analysis", "WARN", "No tokens to analyze")
            return
        
        token_analysis = []
        
        for cookie in self.results['session_cookies']:
            if cookie['is_session_cookie']:
                analysis = {
                    'name': cookie['name'],
                    'length': cookie['length'],
                    'entropy': cookie['entropy'],
                    'strength': 'UNKNOWN',
                    'issues': []
                }
                
                # Length analysis
                if cookie['length'] < 16:
                    analysis['strength'] = 'WEAK'
                    analysis['issues'].append('Token too short (< 16 chars)')
                elif cookie['length'] < 32:
                    analysis['strength'] = 'MEDIUM'
                    analysis['issues'].append('Token length could be improved')
                else:
                    analysis['strength'] = 'STRONG'
                
                # Entropy analysis
                if cookie['entropy'] < 2.5:
                    analysis['strength'] = 'WEAK'
                    analysis['issues'].append('Low entropy - predictable')
                elif cookie['entropy'] < 3.5:
                    if analysis['strength'] != 'WEAK':
                        analysis['strength'] = 'MEDIUM'
                    analysis['issues'].append('Moderate entropy')
                
                # Check for patterns
                if self.has_predictable_pattern(cookie['value']):
                    analysis['strength'] = 'WEAK'
                    analysis['issues'].append('Predictable pattern detected')
                
                # Check for sequential
                if self.is_sequential(cookie['value']):
                    analysis['strength'] = 'WEAK'
                    analysis['issues'].append('Sequential values detected')
                
                token_analysis.append(analysis)
                
                # Print analysis
                strength_color = {
                    'WEAK': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'STRONG': Fore.GREEN,
                    'UNKNOWN': Fore.WHITE
                }.get(analysis['strength'], Fore.WHITE)
                
                print(f"{Fore.CYAN}Token: {cookie['name']}{Style.RESET_ALL}")
                print(f"  Length: {cookie['length']} characters")
                print(f"  Entropy: {cookie['entropy']:.2f} bits")
                print(f"  Strength: {strength_color}{analysis['strength']}{Style.RESET_ALL}")
                
                if analysis['issues']:
                    print(f"  Issues:")
                    for issue in analysis['issues']:
                        print(f"    {Fore.RED}⚠{Style.RESET_ALL} {issue}")
                
                print()
        
        self.results['token_analysis'] = token_analysis
    
    def has_predictable_pattern(self, value):
        """Check for predictable patterns in token"""
        # Check for timestamp patterns
        if re.search(r'\d{10,13}', value):  # Unix timestamp
            return True
        
        # Check for simple incremental patterns
        if re.search(r'(123|abc|xyz)', value.lower()):
            return True
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', value):
            return True
        
        return False
    
    def is_sequential(self, value):
        """Check if value contains sequential characters"""
        if len(value) < 4:
            return False
        
        # Check for sequential numbers
        for i in range(len(value) - 3):
            substr = value[i:i+4]
            if substr.isdigit():
                nums = [int(c) for c in substr]
                if all(nums[j+1] - nums[j] == 1 for j in range(len(nums)-1)):
                    return True
        
        return False
    
    def test_session_timeout(self):
        """Test session timeout behavior"""
        self.print_section("Session Timeout Behavior Analysis")
        
        print(f"{Fore.YELLOW}Note: Full timeout testing requires waiting for session expiration.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Performing quick timeout estimation based on cookie attributes.{Style.RESET_ALL}\n")
        
        timeout_analysis = []
        
        for cookie in self.results['session_cookies']:
            if cookie['is_session_cookie']:
                analysis = {
                    'name': cookie['name'],
                    'has_expiry': cookie['expires'] is not None,
                    'timeout_type': 'UNKNOWN'
                }
                
                if cookie['expires']:
                    # Calculate timeout duration
                    expire_time = datetime.fromtimestamp(cookie['expires'])
                    current_time = datetime.now()
                    duration = expire_time - current_time
                    
                    analysis['timeout_type'] = 'ABSOLUTE'
                    analysis['expires_at'] = expire_time.strftime('%Y-%m-%d %H:%M:%S')
                    analysis['duration_seconds'] = int(duration.total_seconds())
                    analysis['duration_readable'] = self.format_duration(duration.total_seconds())
                    
                    # Evaluate timeout
                    if duration.total_seconds() < 900:  # 15 minutes
                        analysis['evaluation'] = 'GOOD - Short timeout'
                    elif duration.total_seconds() < 3600:  # 1 hour
                        analysis['evaluation'] = 'ACCEPTABLE'
                    elif duration.total_seconds() < 86400:  # 24 hours
                        analysis['evaluation'] = 'LONG - Consider shorter timeout'
                    else:
                        analysis['evaluation'] = 'TOO LONG - Security risk'
                else:
                    analysis['timeout_type'] = 'SESSION'
                    analysis['evaluation'] = 'Session cookie (expires on browser close)'
                
                timeout_analysis.append(analysis)
                
                # Print analysis
                print(f"{Fore.CYAN}Session: {cookie['name']}{Style.RESET_ALL}")
                print(f"  Type: {analysis['timeout_type']}")
                if analysis['has_expiry']:
                    print(f"  Expires: {analysis['expires_at']}")
                    print(f"  Duration: {analysis['duration_readable']}")
                print(f"  Evaluation: {analysis['evaluation']}")
                print()
        
        self.results['session_behavior']['timeout'] = timeout_analysis
    
    def format_duration(self, seconds):
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        else:
            return f"{int(seconds/86400)} days"
    
    def test_logout_invalidation(self):
        """Test logout behavior and session invalidation"""
        self.print_section("Logout Invalidation Testing")
        
        print(f"{Fore.YELLOW}Note: Full logout testing requires authenticated session.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Checking for logout endpoints and mechanism indicators.{Style.RESET_ALL}\n")
        
        # Look for logout endpoints
        logout_patterns = [
            '/logout', '/signout', '/sign-out', '/logoff',
            '/session/destroy', '/auth/logout', '/user/logout',
            '/exit', '/disconnect'
        ]
        
        logout_endpoints = []
        
        for pattern in logout_patterns:
            try:
                url = self.base_url + pattern
                response = self.session.head(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 303, 307, 308]:
                    logout_endpoints.append({
                        'url': url,
                        'status': response.status_code,
                        'redirects': response.status_code in [301, 302, 303, 307, 308]
                    })
            except:
                pass
        
        if logout_endpoints:
            self.print_check("Logout Endpoints Found", "PASS", f"{len(logout_endpoints)} endpoint(s)")
            for endpoint in logout_endpoints:
                redirect_info = " (redirects)" if endpoint['redirects'] else ""
                print(f"    {Fore.GREEN}→{Style.RESET_ALL} {endpoint['url']} [{endpoint['status']}]{redirect_info}")
        else:
            self.print_check("Logout Endpoints", "WARN", "No logout endpoints detected")
        
        self.results['session_behavior']['logout_endpoints'] = logout_endpoints
        
        # Recommendations
        print(f"\n{Fore.CYAN}Logout Best Practices:{Style.RESET_ALL}")
        recommendations = [
            "Session should be invalidated server-side on logout",
            "All session cookies should be cleared",
            "User should be redirected to login page",
            "Logout should work with GET and POST methods",
            "CSRF protection recommended for logout",
            "Consider implementing logout from all devices"
        ]
        
        for rec in recommendations:
            print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {rec}")
    
    def analyze_security_headers(self):
        """Analyze security-related HTTP headers"""
        self.print_section("Security Headers Analysis")
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            headers_found = []
            headers_missing = []
            
            for header in self.security_headers:
                if header in response.headers:
                    headers_found.append({
                        'name': header,
                        'value': response.headers[header]
                    })
                else:
                    headers_missing.append(header)
            
            # Print found headers
            if headers_found:
                print(f"{Fore.GREEN}Security Headers Present:{Style.RESET_ALL}\n")
                for header in headers_found:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {header['name']}")
                    print(f"    {Fore.WHITE}{header['value'][:100]}{Style.RESET_ALL}")
                print()
            
            # Print missing headers
            if headers_missing:
                print(f"{Fore.RED}Security Headers Missing:{Style.RESET_ALL}\n")
                for header in headers_missing:
                    print(f"  {Fore.RED}✗{Style.RESET_ALL} {header}")
                print()
            
            self.results['security_headers'] = {
                'found': headers_found,
                'missing': headers_missing
            }
        
        except Exception as e:
            self.print_check("Security Headers", "FAIL", str(e))
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        self.print_section("Security Recommendations")
        
        recommendations = []
        
        # Check vulnerabilities
        for vuln in self.results['vulnerabilities']:
            rec = f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}"
            recommendations.append(rec)
            
            severity_color = {
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.GREEN
            }.get(vuln['severity'], Fore.WHITE)
            
            print(f"{severity_color}[{vuln['severity']}]{Style.RESET_ALL} {vuln['type']}")
            print(f"  Cookie: {vuln['cookie']}")
            print(f"  Impact: {vuln['impact']}")
            print()
        
        # General recommendations
        general_recs = []
        
        # Check HTTPS
        if not self.target_url.startswith('https://'):
            general_recs.append("Implement HTTPS for all authentication pages")
        
        # Check security headers
        if 'security_headers' in self.results:
            if len(self.results['security_headers']['missing']) > 0:
                general_recs.append(f"Implement missing security headers: {', '.join(self.results['security_headers']['missing'][:3])}")
        
        # Check CSRF protection
        has_csrf = any(flow.get('csrf_protection', False) for flow in self.results.get('authentication_flows', []))
        if not has_csrf:
            general_recs.append("Implement CSRF protection for login forms")
        
        if general_recs:
            print(f"{Fore.CYAN}General Recommendations:{Style.RESET_ALL}\n")
            for rec in general_recs:
                print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {rec}")
                recommendations.append(rec)
        
        self.results['recommendations'] = recommendations
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"AuthSession_{hostname}_{timestamp}.txt"
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("AUTHENTICATION & SESSION ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # Login Mechanisms
        report.append("\n" + "=" * 80)
        report.append("LOGIN MECHANISMS")
        report.append("=" * 80)
        report.append(f"\nFound: {len(self.results['login_mechanisms'])}")
        
        for mech in self.results['login_mechanisms']:
            report.append(f"\nURL: {mech['url']}")
            report.append(f"Forms: {len(mech['forms'])}")
            for form in mech['forms']:
                report.append(f"  Action: {form['action']}")
                report.append(f"  Method: {form['method']}")
                report.append(f"  CSRF Protection: {'Yes' if form['csrf_token'] else 'No'}")
                report.append(f"  Fields: {len(form['fields'])}")
        
        # Session Cookies
        report.append("\n" + "=" * 80)
        report.append("SESSION COOKIES")
        report.append("=" * 80)
        report.append(f"\nTotal Cookies: {len(self.results['session_cookies'])}")
        
        for cookie in self.results['session_cookies']:
            report.append(f"\nCookie: {cookie['name']}")
            report.append(f"  Type: {'Session' if cookie['is_session_cookie'] else 'Regular'}")
            report.append(f"  Length: {cookie['length']}")
            report.append(f"  Entropy: {cookie['entropy']:.2f}")
            report.append(f"  Security Score: {cookie['security_score']}/100")
            report.append(f"  Flags:")
            report.append(f"    Secure: {cookie['secure']}")
            report.append(f"    HttpOnly: {cookie['httponly']}")
            report.append(f"    SameSite: {cookie['samesite']}")
        
        # Vulnerabilities
        if self.results['vulnerabilities']:
            report.append("\n" + "=" * 80)
            report.append("VULNERABILITIES DETECTED")
            report.append("=" * 80)
            
            for vuln in self.results['vulnerabilities']:
                report.append(f"\n[{vuln['severity']}] {vuln['type']}")
                report.append(f"  Cookie: {vuln['cookie']}")
                report.append(f"  Description: {vuln['description']}")
                report.append(f"  Impact: {vuln['impact']}")
        
        # Recommendations
        if self.results['recommendations']:
            report.append("\n" + "=" * 80)
            report.append("RECOMMENDATIONS")
            report.append("=" * 80)
            
            for i, rec in enumerate(self.results['recommendations'], 1):
                report.append(f"\n{i}. {rec}")
        
        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        report.append(f"\nLogin Endpoints: {len(self.results['login_mechanisms'])}")
        report.append(f"Session Cookies: {len([c for c in self.results['session_cookies'] if c['is_session_cookie']])}")
        report.append(f"Total Cookies: {len(self.results['session_cookies'])}")
        report.append(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
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
    print(f"\n{Fore.GREEN}[+] Starting Authentication & Session Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = AuthSessionAnalyzer(target_url)
    
    # Define scan stages
    stages = [
        ("Login Mechanism Identification", analyzer.identify_login_mechanisms),
        ("Authentication Flow Mapping", analyzer.map_authentication_flow),
        ("Session Cookie Analysis", analyzer.analyze_session_cookies),
        ("Security Flag Validation", analyzer.validate_security_flags),
        ("Token Strength Analysis", analyzer.analyze_token_strength),
        ("Session Timeout Behavior", analyzer.test_session_timeout),
        ("Logout Invalidation Testing", analyzer.test_logout_invalidation),
        ("Security Headers Analysis", analyzer.analyze_security_headers),
        ("Recommendations Generation", analyzer.generate_recommendations),
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
        
        print(f"{Fore.YELLOW}[✓] Login Endpoints: {len(analyzer.results['login_mechanisms'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Session Cookies: {len([c for c in analyzer.results['session_cookies'] if c['is_session_cookie']])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Total Cookies: {len(analyzer.results['session_cookies'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Vulnerabilities: {len(analyzer.results['vulnerabilities'])}{Style.RESET_ALL}")
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
        print("Usage: python auth.py <target_url>")
