#!/usr/bin/env python3
"""
Input Validation & Weak Signal Detection Module
Performs comprehensive input validation testing including reflected input detection,
error message analysis, stack trace exposure, SQL error patterns, template injection hints,
file path handling, parameter type inconsistency, response anomalies, and encoding behavior.
"""

import requests
import json
import os
import sys
import time
import re
import hashlib
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, Back
from threading import Thread, Lock
from collections import defaultdict, Counter
import warnings
from difflib import SequenceMatcher
import html
import base64

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

class InputValidationAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.hostname = self.parsed_url.netloc.split(':')[0]
        
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'reflected_inputs': [],
            'error_messages': [],
            'stack_traces': [],
            'sql_errors': [],
            'template_injection_hints': [],
            'file_path_behaviors': [],
            'parameter_inconsistencies': [],
            'response_anomalies': [],
            'encoding_behaviors': [],
            'vulnerabilities': [],
            'parameters_tested': 0
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Baseline response
        self.baseline_response = None
        self.baseline_length = 0
        
        # Test payloads
        self.reflection_payloads = [
            "REFLECT_TEST_12345",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "'\"<>",
            "UNIQUE_MARKER_98765"
        ]
        
        # SQL error patterns
        self.sql_error_patterns = {
            'mysql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'check the manual that corresponds to your MySQL',
                r'MySqlClient\.',
                r'com\.mysql\.jdbc'
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_.*',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PG::SyntaxError',
                r'org\.postgresql\.util\.PSQLException'
            ],
            'mssql': [
                r'Driver.* SQL[\-\_\ ]*Server',
                r'OLE DB.* SQL Server',
                r'(\W|\A)SQL Server.*Driver',
                r'Warning.*mssql_.*',
                r'Microsoft SQL Native Client error',
                r'SqlClient\.',
                r'com\.microsoft\.sqlserver\.jdbc'
            ],
            'oracle': [
                r'\bORA-[0-9][0-9][0-9][0-9]',
                r'Oracle error',
                r'Oracle.*Driver',
                r'Warning.*\Woci_.*',
                r'Warning.*\Wora_.*',
                r'oracle\.jdbc'
            ],
            'sqlite': [
                r'SQLite/JDBCDriver',
                r'SQLite\.Exception',
                r'System\.Data\.SQLite\.SQLiteException',
                r'Warning.*sqlite_.*',
                r'SQLite error',
                r'sqlite3\.OperationalError'
            ]
        }
        
        # Stack trace patterns
        self.stack_trace_patterns = [
            r'Traceback \(most recent call last\):',  # Python
            r'at [\w\.<>]+\([\w\s\.:]+:\d+\)',  # Java
            r'^\s+at .+ in .+:\d+',  # .NET
            r'Stack trace:',
            r'Fatal error:.*in .+ on line \d+',  # PHP
            r'Call Stack:',
            r'#\d+ .+ called at \[.+:\d+\]',  # PHP
            r'Exception in thread',
            r'Caused by:',
            r'\.printStackTrace\(\)',
        ]
        
        # Template injection patterns
        self.template_patterns = {
            'jinja2': [r'jinja2\.', r'TemplateNotFound', r'UndefinedError'],
            'erb': [r'ActionView::', r'erb:'],
            'freemarker': [r'freemarker\.', r'FreeMarker'],
            'velocity': [r'org\.apache\.velocity'],
            'thymeleaf': [r'thymeleaf\.', r'TemplateProcessingException'],
            'smarty': [r'Smarty error:', r'smarty\.'],
            'twig': [r'Twig_Error', r'Twig\\Error'],
        }
        
        # File path patterns
        self.file_path_patterns = [
            r'[a-zA-Z]:\\[\w\\]+',  # Windows paths
            r'/(?:etc|var|usr|home|root)/[\w/]+',  # Unix paths
            r'(?:include|require).*[\'"].*[\'"]',  # PHP includes
            r'open\(.*[\'"].*[\'"]',  # File open operations
            r'\.\./',  # Path traversal
            r'%2e%2e/',  # Encoded path traversal
        ]
        
        # Error message patterns
        self.generic_error_patterns = [
            r'fatal error',
            r'warning:',
            r'error:',
            r'exception',
            r'undefined',
            r'null pointer',
            r'internal server error',
            r'syntax error',
            r'parse error',
            r'runtime error',
            r'access denied',
            r'permission denied',
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
    
    def get_baseline(self):
        """Get baseline response for comparison"""
        self.print_section("Baseline Response Collection")
        
        loader = LoadingBar("Collecting baseline response")
        loader.start()
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            self.baseline_response = response.text
            self.baseline_length = len(response.text)
            self.baseline_status = response.status_code
            
            loader.stop(True)
            
            self.print_check("Baseline Collected", "PASS", 
                           f"Status: {self.baseline_status}, Length: {self.baseline_length} bytes")
        except Exception as e:
            loader.stop(False)
            self.print_check("Baseline Collection", "FAIL", str(e))
    
    def discover_parameters(self):
        """Discover parameters in URL"""
        query_params = parse_qs(self.parsed_url.query)
        
        if query_params:
            print(f"{Fore.CYAN}Parameters discovered in URL:{Style.RESET_ALL}")
            for param in query_params:
                print(f"  → {param}")
            print()
        
        return list(query_params.keys())
    
    def test_reflected_input(self):
        """Test for reflected input"""
        self.print_section("Reflected Input Detection")
        
        params = self.discover_parameters()
        
        if not params:
            self.print_check("Parameter Discovery", "WARN", "No parameters found in URL")
            # Try common parameter names
            params = ['id', 'q', 'search', 'query', 'page', 'name', 'user', 'file']
            print(f"{Fore.YELLOW}Testing common parameter names...{Style.RESET_ALL}\n")
        
        reflected_findings = []
        
        for param in params:
            for payload in self.reflection_payloads:
                try:
                    # Build test URL
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        # Check context
                        context = self.analyze_reflection_context(response.text, payload)
                        
                        finding = {
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'context': context,
                            'dangerous': context in ['html', 'script', 'attribute']
                        }
                        
                        reflected_findings.append(finding)
                        
                        # Print finding
                        danger_icon = "🔴" if finding['dangerous'] else "🟡"
                        print(f"{danger_icon} Reflection in {Fore.CYAN}{param}{Style.RESET_ALL}")
                        print(f"    Payload: {payload}")
                        print(f"    Context: {context}")
                        print()
                        
                        self.results['parameters_tested'] += 1
                        break  # Move to next parameter
                
                except Exception as e:
                    pass
            
            self.results['parameters_tested'] += 1
        
        self.results['reflected_inputs'] = reflected_findings
        
        if reflected_findings:
            self.print_check("Reflected Input", "FAIL", 
                           f"{len(reflected_findings)} parameter(s) reflect input")
        else:
            self.print_check("Reflected Input", "PASS", "No reflected input detected")
    
    def analyze_reflection_context(self, html_content, payload):
        """Analyze where the payload is reflected"""
        # Find payload in content
        index = html_content.find(payload)
        if index == -1:
            return "unknown"
        
        # Get surrounding context
        context_start = max(0, index - 100)
        context_end = min(len(html_content), index + len(payload) + 100)
        context = html_content[context_start:context_end]
        
        # Analyze context
        if '<script' in context[:100] and '</script>' in context[-100:]:
            return 'script'
        elif re.search(r'<\w+[^>]*' + re.escape(payload), context):
            return 'attribute'
        elif '<' in context[:50] and '>' in context[-50:]:
            return 'html'
        else:
            return 'text'
    
    def analyze_error_messages(self):
        """Analyze error messages and information disclosure"""
        self.print_section("Error Message Analysis")
        
        loader = LoadingBar("Testing error-inducing payloads")
        loader.start()
        
        error_payloads = [
            "'", '"', "\\", "/", "/*", "*", "%", "&", "|", "^",
            "1'1", "1\"1", "1/1", "1\\1",
            "{{", "}}", "${", "<%", "%>", "#{",
            "../", "..\\", "%2e%2e/",
            "1 AND 1=1", "1 OR 1=1", "'; DROP TABLE users--",
            "\x00", "\x0a", "\x0d",
            "999999999999999999999999",
            "-1", "0", "null", "undefined",
        ]
        
        error_findings = []
        
        params = self.discover_parameters()
        if not params:
            params = ['id', 'q', 'search']
        
        for param in params[:3]:  # Test first 3 params
            for payload in error_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for errors
                    for pattern in self.generic_error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            error_findings.append({
                                'parameter': param,
                                'payload': payload,
                                'pattern': pattern,
                                'status_code': response.status_code,
                                'sample': self.extract_error_sample(response.text, pattern)
                            })
                            break
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['error_messages'] = error_findings
        
        if error_findings:
            self.print_check("Error Messages", "FAIL", 
                           f"{len(error_findings)} error message(s) detected")
            
            # Show samples
            for finding in error_findings[:5]:
                print(f"  {Fore.RED}▸{Style.RESET_ALL} {finding['parameter']}: {finding['payload']}")
                print(f"    Pattern: {finding['pattern']}")
                if finding['sample']:
                    print(f"    Sample: {finding['sample'][:100]}...")
                print()
        else:
            self.print_check("Error Messages", "PASS", "No verbose error messages")
    
    def extract_error_sample(self, content, pattern):
        """Extract sample text around error pattern"""
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 150)
            return content[start:end].strip()
        return ""
    
    def detect_stack_traces(self):
        """Detect stack trace exposure"""
        self.print_section("Stack Trace Exposure Detection")
        
        loader = LoadingBar("Testing for stack trace disclosure")
        loader.start()
        
        stack_trace_payloads = [
            "1/0",  # Division by zero
            "throw_error",
            "undefined_function()",
            "null.method()",
            "array[-1]",
            "dict['nonexistent']",
        ]
        
        stack_traces = []
        
        params = self.discover_parameters()
        if not params:
            params = ['id', 'page', 'action']
        
        for param in params[:2]:
            for payload in stack_trace_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for stack traces
                    for pattern in self.stack_trace_patterns:
                        if re.search(pattern, response.text, re.MULTILINE):
                            stack_trace = self.extract_stack_trace(response.text)
                            
                            stack_traces.append({
                                'parameter': param,
                                'payload': payload,
                                'trace_sample': stack_trace[:500],
                                'language': self.detect_language_from_trace(stack_trace)
                            })
                            break
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['stack_traces'] = stack_traces
        
        if stack_traces:
            self.print_check("Stack Traces", "FAIL", 
                           f"{len(stack_traces)} stack trace(s) exposed")
            
            for trace in stack_traces:
                print(f"  {Fore.RED}▸{Style.RESET_ALL} {trace['parameter']}")
                print(f"    Language: {trace['language']}")
                print(f"    Sample: {trace['trace_sample'][:200]}...")
                print()
        else:
            self.print_check("Stack Traces", "PASS", "No stack traces exposed")
    
    def extract_stack_trace(self, content):
        """Extract stack trace from response"""
        for pattern in self.stack_trace_patterns:
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                start = match.start()
                # Extract multiple lines
                lines = content[start:].split('\n')[:15]
                return '\n'.join(lines)
        return ""
    
    def detect_language_from_trace(self, trace):
        """Detect programming language from stack trace"""
        if 'Traceback' in trace or '.py' in trace:
            return 'Python'
        elif '.java' in trace or 'Exception in thread' in trace:
            return 'Java'
        elif '.cs:' in trace or 'at System.' in trace:
            return '.NET/C#'
        elif '.php' in trace or 'Fatal error:' in trace:
            return 'PHP'
        elif '.rb:' in trace:
            return 'Ruby'
        elif '.js:' in trace or 'node_modules' in trace:
            return 'Node.js'
        else:
            return 'Unknown'
    
    def detect_sql_errors(self):
        """Detect SQL error patterns"""
        self.print_section("SQL Error Pattern Detection")
        
        loader = LoadingBar("Testing SQL error conditions")
        loader.start()
        
        sql_payloads = [
            "'",
            "''",
            "1'",
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='1",
            "1' UNION SELECT NULL--",
            "1'/**/OR/**/1=1--",
            "admin'--",
            "' WAITFOR DELAY '00:00:05'--",
        ]
        
        sql_errors = []
        
        params = self.discover_parameters()
        if not params:
            params = ['id', 'user', 'search']
        
        for param in params[:3]:
            for payload in sql_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for SQL errors
                    for db_type, patterns in self.sql_error_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                sql_errors.append({
                                    'parameter': param,
                                    'payload': payload,
                                    'database': db_type,
                                    'pattern': pattern,
                                    'sample': self.extract_error_sample(response.text, pattern)
                                })
                                break
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['sql_errors'] = sql_errors
        
        if sql_errors:
            self.print_check("SQL Errors", "FAIL", 
                           f"{len(sql_errors)} SQL error(s) detected")
            
            db_types = set(e['database'] for e in sql_errors)
            print(f"    Database types: {', '.join(db_types)}")
            print()
            
            for error in sql_errors[:3]:
                print(f"  {Fore.RED}▸{Style.RESET_ALL} {error['parameter']}: {error['payload']}")
                print(f"    Database: {error['database']}")
                print(f"    Sample: {error['sample'][:150]}...")
                print()
        else:
            self.print_check("SQL Errors", "PASS", "No SQL errors detected")
    
    def detect_template_injection(self):
        """Detect template injection hints"""
        self.print_section("Template Injection Error Hints")
        
        loader = LoadingBar("Testing template expression payloads")
        loader.start()
        
        template_payloads = [
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "{7*7}",
            "#{7*7}",
            "${{7*7}}",
            "{{config}}",
            "{{self}}",
            "${bean.class}",
            "<%= 7*7 %>",
        ]
        
        template_hints = []
        
        params = self.discover_parameters()
        if not params:
            params = ['name', 'template', 'view', 'page']
        
        for param in params[:3]:
            for payload in template_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for template errors
                    for engine, patterns in self.template_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                template_hints.append({
                                    'parameter': param,
                                    'payload': payload,
                                    'engine': engine,
                                    'pattern': pattern,
                                    'sample': self.extract_error_sample(response.text, pattern)
                                })
                                break
                    
                    # Check for evaluation
                    if '49' in response.text and payload in ['{{7*7}}', '${7*7}', '<%=7*7%>']:
                        template_hints.append({
                            'parameter': param,
                            'payload': payload,
                            'engine': 'Evaluated',
                            'pattern': 'Mathematical expression evaluated',
                            'sample': f'Payload {payload} resulted in 49'
                        })
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['template_injection_hints'] = template_hints
        
        if template_hints:
            self.print_check("Template Injection", "FAIL", 
                           f"{len(template_hints)} hint(s) detected")
            
            for hint in template_hints:
                print(f"  {Fore.RED}▸{Style.RESET_ALL} {hint['parameter']}: {hint['payload']}")
                print(f"    Engine: {hint['engine']}")
                print(f"    Pattern: {hint['pattern']}")
                print()
        else:
            self.print_check("Template Injection", "PASS", "No template errors detected")
    
    def test_file_path_handling(self):
        """Test file path handling behavior"""
        self.print_section("File Path Handling Behavior")
        
        loader = LoadingBar("Testing path traversal payloads")
        loader.start()
        
        path_payloads = [
            "../",
            "..\\",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e/",
            "%2e%2e%2f",
            "....//",
            "..;/",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "file:///etc/passwd",
        ]
        
        path_behaviors = []
        
        params = self.discover_parameters()
        if not params:
            params = ['file', 'path', 'page', 'include', 'template']
        
        for param in params[:3]:
            for payload in path_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for file path errors or exposure
                    for pattern in self.file_path_patterns:
                        if re.search(pattern, response.text):
                            path_behaviors.append({
                                'parameter': param,
                                'payload': payload,
                                'pattern': pattern,
                                'status_code': response.status_code,
                                'sample': self.extract_error_sample(response.text, pattern)
                            })
                            break
                    
                    # Check for known file contents
                    if 'root:' in response.text or '[extensions]' in response.text:
                        path_behaviors.append({
                            'parameter': param,
                            'payload': payload,
                            'pattern': 'File content exposed',
                            'status_code': response.status_code,
                            'sample': response.text[:200]
                        })
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['file_path_behaviors'] = path_behaviors
        
        if path_behaviors:
            self.print_check("File Path Handling", "FAIL", 
                           f"{len(path_behaviors)} behavior(s) detected")
            
            for behavior in path_behaviors[:3]:
                print(f"  {Fore.RED}▸{Style.RESET_ALL} {behavior['parameter']}: {behavior['payload']}")
                print(f"    Pattern: {behavior['pattern']}")
                print(f"    Status: {behavior['status_code']}")
                print()
        else:
            self.print_check("File Path Handling", "PASS", "No suspicious path behavior")
    
    def test_parameter_type_inconsistency(self):
        """Test parameter type inconsistency"""
        self.print_section("Parameter Type Inconsistency Analysis")
        
        loader = LoadingBar("Testing type confusion payloads")
        loader.start()
        
        type_payloads = {
            'string_to_int': ['123', 'abc', '12.34', '0x1A', '1e10'],
            'int_to_string': ['normal', '', '!@#$', 'null'],
            'array': ['[]', '["a","b"]', '{a:1}'],
            'boolean': ['true', 'false', '1', '0', 'yes', 'no'],
            'null': ['null', 'NULL', 'None', 'nil', 'undefined'],
            'special': ['\x00', '\n', '\r\n', '\t'],
        }
        
        inconsistencies = []
        
        params = self.discover_parameters()
        if not params:
            params = ['id', 'page', 'user_id', 'count']
        
        for param in params[:2]:
            baseline = None
            
            try:
                # Get baseline
                response = self.session.get(self.target_url, timeout=10, verify=False)
                baseline = {
                    'status': response.status_code,
                    'length': len(response.text)
                }
            except:
                continue
            
            for type_name, payloads in type_payloads.items():
                for payload in payloads:
                    try:
                        parsed = urlparse(self.target_url)
                        query = parse_qs(parsed.query)
                        query[param] = [payload]
                        
                        new_query = urlencode(query, doseq=True)
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                        
                        response = self.session.get(test_url, timeout=10, verify=False)
                        
                        # Check for inconsistencies
                        if response.status_code != baseline['status']:
                            inconsistencies.append({
                                'parameter': param,
                                'payload': payload,
                                'type': type_name,
                                'baseline_status': baseline['status'],
                                'test_status': response.status_code,
                                'difference': 'Status code changed'
                            })
                        
                        length_diff = abs(len(response.text) - baseline['length'])
                        if length_diff > baseline['length'] * 0.3:  # 30% difference
                            inconsistencies.append({
                                'parameter': param,
                                'payload': payload,
                                'type': type_name,
                                'baseline_length': baseline['length'],
                                'test_length': len(response.text),
                                'difference': f'Length changed by {length_diff} bytes'
                            })
                    
                    except Exception as e:
                        pass
        
        loader.stop(True)
        
        self.results['parameter_inconsistencies'] = inconsistencies
        
        if inconsistencies:
            self.print_check("Type Inconsistency", "WARN", 
                           f"{len(inconsistencies)} inconsistenc(ies) detected")
            
            for inconsistency in inconsistencies[:5]:
                print(f"  {Fore.YELLOW}▸{Style.RESET_ALL} {inconsistency['parameter']}: {inconsistency['payload']}")
                print(f"    Type: {inconsistency['type']}")
                print(f"    Difference: {inconsistency['difference']}")
                print()
        else:
            self.print_check("Type Inconsistency", "PASS", "Consistent parameter handling")
    
    def detect_response_anomalies(self):
        """Detect HTTP response anomalies"""
        self.print_section("HTTP Response Anomaly Detection")
        
        anomalies = []
        
        # Test various payloads and detect anomalies
        test_payloads = [
            ('normal', 'test'),
            ('special', '!@#$%^&*()'),
            ('long', 'A' * 1000),
            ('unicode', 'テスト中文'),
            ('encoded', '%20%21%22'),
        ]
        
        params = self.discover_parameters()
        if not params:
            params = ['q', 'search']
        
        responses = []
        
        for param in params[:1]:
            for name, payload in test_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start_time
                    
                    responses.append({
                        'payload_type': name,
                        'payload': payload[:50],
                        'status': response.status_code,
                        'length': len(response.text),
                        'time': elapsed,
                        'headers': dict(response.headers)
                    })
                
                except Exception as e:
                    pass
        
        # Analyze for anomalies
        if len(responses) > 1:
            # Check for status code variations
            statuses = [r['status'] for r in responses]
            if len(set(statuses)) > 1:
                anomalies.append({
                    'type': 'Status Code Variation',
                    'details': f"Codes: {set(statuses)}"
                })
            
            # Check for length variations
            lengths = [r['length'] for r in responses]
            avg_length = sum(lengths) / len(lengths)
            for resp in responses:
                if abs(resp['length'] - avg_length) > avg_length * 0.5:
                    anomalies.append({
                        'type': 'Response Length Anomaly',
                        'payload_type': resp['payload_type'],
                        'length': resp['length'],
                        'average': int(avg_length)
                    })
            
            # Check for time variations
            times = [r['time'] for r in responses]
            avg_time = sum(times) / len(times)
            for resp in responses:
                if resp['time'] > avg_time * 3:
                    anomalies.append({
                        'type': 'Response Time Anomaly',
                        'payload_type': resp['payload_type'],
                        'time': f"{resp['time']:.2f}s",
                        'average': f"{avg_time:.2f}s"
                    })
        
        self.results['response_anomalies'] = anomalies
        
        if anomalies:
            self.print_check("Response Anomalies", "WARN", 
                           f"{len(anomalies)} anomal(ies) detected")
            
            for anomaly in anomalies:
                print(f"  {Fore.YELLOW}▸{Style.RESET_ALL} {anomaly['type']}")
                for key, value in anomaly.items():
                    if key != 'type':
                        print(f"    {key}: {value}")
                print()
        else:
            self.print_check("Response Anomalies", "PASS", "No significant anomalies")
    
    def test_encoding_sanitization(self):
        """Test encoding and sanitization behavior"""
        self.print_section("Encoding & Sanitization Behavior")
        
        loader = LoadingBar("Testing encoding behaviors")
        loader.start()
        
        encoding_payloads = [
            ('<script>', 'HTML Tags'),
            ('&lt;script&gt;', 'HTML Entities'),
            ('%3Cscript%3E', 'URL Encoding'),
            ('%253Cscript%253E', 'Double URL Encoding'),
            ('\x3Cscript\x3E', 'Hex Encoding'),
            ('\\u003Cscript\\u003E', 'Unicode Escape'),
            (base64.b64encode(b'<script>').decode(), 'Base64'),
            ("'><script>", 'Quote Breaking'),
        ]
        
        behaviors = []
        
        params = self.discover_parameters()
        if not params:
            params = ['input', 'data', 'content']
        
        for param in params[:2]:
            for payload, encoding_type in encoding_payloads:
                try:
                    parsed = urlparse(self.target_url)
                    query = parse_qs(parsed.query)
                    query[param] = [payload]
                    
                    new_query = urlencode(query, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check how payload was handled
                    if payload in response.text:
                        behavior = 'Unsanitized'
                    elif html.escape(payload) in response.text:
                        behavior = 'HTML Escaped'
                    elif payload.replace('<', '').replace('>', '') in response.text:
                        behavior = 'Tags Stripped'
                    else:
                        behavior = 'Filtered/Removed'
                    
                    behaviors.append({
                        'parameter': param,
                        'encoding_type': encoding_type,
                        'payload': payload,
                        'behavior': behavior,
                        'safe': behavior != 'Unsanitized'
                    })
                
                except Exception as e:
                    pass
        
        loader.stop(True)
        
        self.results['encoding_behaviors'] = behaviors
        
        if behaviors:
            unsafe_count = len([b for b in behaviors if not b['safe']])
            
            if unsafe_count > 0:
                self.print_check("Encoding/Sanitization", "FAIL", 
                               f"{unsafe_count} unsanitized input(s)")
            else:
                self.print_check("Encoding/Sanitization", "PASS", 
                               "All inputs properly sanitized")
            
            # Show behavior breakdown
            behavior_types = Counter(b['behavior'] for b in behaviors)
            print(f"\n  {Fore.CYAN}Behavior Breakdown:{Style.RESET_ALL}")
            for behavior, count in behavior_types.items():
                color = Fore.GREEN if behavior != 'Unsanitized' else Fore.RED
                print(f"    {color}{behavior}: {count}{Style.RESET_ALL}")
            print()
        else:
            self.print_check("Encoding/Sanitization", "WARN", "No data to analyze")
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"InputValidation_{hostname}_{timestamp}.txt"
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("INPUT VALIDATION & WEAK SIGNAL DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}")
        report.append(f"Parameters Tested: {self.results['parameters_tested']}\n")
        report.append("=" * 80)
        
        # Reflected Inputs
        if self.results['reflected_inputs']:
            report.append("\n" + "=" * 80)
            report.append("REFLECTED INPUTS")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['reflected_inputs'])}")
            
            for ref in self.results['reflected_inputs']:
                report.append(f"\nParameter: {ref['parameter']}")
                report.append(f"  Payload: {ref['payload']}")
                report.append(f"  Context: {ref['context']}")
                report.append(f"  Dangerous: {ref['dangerous']}")
        
        # Error Messages
        if self.results['error_messages']:
            report.append("\n" + "=" * 80)
            report.append("ERROR MESSAGES")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['error_messages'])}")
            
            for error in self.results['error_messages']:
                report.append(f"\nParameter: {error['parameter']}")
                report.append(f"  Payload: {error['payload']}")
                report.append(f"  Pattern: {error['pattern']}")
                report.append(f"  Sample: {error['sample'][:200]}")
        
        # Stack Traces
        if self.results['stack_traces']:
            report.append("\n" + "=" * 80)
            report.append("STACK TRACES")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['stack_traces'])}")
            
            for trace in self.results['stack_traces']:
                report.append(f"\nParameter: {trace['parameter']}")
                report.append(f"  Language: {trace['language']}")
                report.append(f"  Sample:\n{trace['trace_sample']}")
        
        # SQL Errors
        if self.results['sql_errors']:
            report.append("\n" + "=" * 80)
            report.append("SQL ERRORS")
            report.append("=" * 80)
            report.append(f"\nTotal: {len(self.results['sql_errors'])}")
            
            db_types = set(e['database'] for e in self.results['sql_errors'])
            report.append(f"Database Types: {', '.join(db_types)}")
            
            for error in self.results['sql_errors']:
                report.append(f"\nParameter: {error['parameter']}")
                report.append(f"  Database: {error['database']}")
                report.append(f"  Payload: {error['payload']}")
                report.append(f"  Sample: {error['sample'][:200]}")
        
        # Statistics
        report.append("\n" + "=" * 80)
        report.append("STATISTICS")
        report.append("=" * 80)
        report.append(f"\nParameters Tested: {self.results['parameters_tested']}")
        report.append(f"Reflected Inputs: {len(self.results['reflected_inputs'])}")
        report.append(f"Error Messages: {len(self.results['error_messages'])}")
        report.append(f"Stack Traces: {len(self.results['stack_traces'])}")
        report.append(f"SQL Errors: {len(self.results['sql_errors'])}")
        report.append(f"Template Hints: {len(self.results['template_injection_hints'])}")
        report.append(f"File Path Issues: {len(self.results['file_path_behaviors'])}")
        report.append(f"Type Inconsistencies: {len(self.results['parameter_inconsistencies'])}")
        report.append(f"Response Anomalies: {len(self.results['response_anomalies'])}")
        report.append(f"Encoding Behaviors: {len(self.results['encoding_behaviors'])}")
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
    print(f"\n{Fore.GREEN}[+] Starting Input Validation & Weak Signal Detection{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = InputValidationAnalyzer(target_url)
    
    # Define scan stages
    stages = [
        ("Baseline Collection", analyzer.get_baseline),
        ("Reflected Input Detection", analyzer.test_reflected_input),
        ("Error Message Analysis", analyzer.analyze_error_messages),
        ("Stack Trace Detection", analyzer.detect_stack_traces),
        ("SQL Error Detection", analyzer.detect_sql_errors),
        ("Template Injection Hints", analyzer.detect_template_injection),
        ("File Path Handling", analyzer.test_file_path_handling),
        ("Parameter Type Inconsistency", analyzer.test_parameter_type_inconsistency),
        ("Response Anomaly Detection", analyzer.detect_response_anomalies),
        ("Encoding & Sanitization", analyzer.test_encoding_sanitization),
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
        
        print(f"{Fore.YELLOW}[✓] Parameters Tested: {analyzer.results['parameters_tested']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Reflected Inputs: {len(analyzer.results['reflected_inputs'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Error Messages: {len(analyzer.results['error_messages'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Stack Traces: {len(analyzer.results['stack_traces'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] SQL Errors: {len(analyzer.results['sql_errors'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Template Hints: {len(analyzer.results['template_injection_hints'])}{Style.RESET_ALL}")
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
        print("Usage: python validation.py <target_url>")
