#!/usr/bin/env python3
"""
Error Pattern Analyzer
Analyzes error messages and extracts information disclosure
"""

import requests
import sys
import re

class ErrorAnalyzer:
    def __init__(self, url):
        self.url = url
        
        self.patterns = {
            'version_info': [
                r'(PHP|Apache|nginx|MySQL|PostgreSQL|Oracle|MongoDB)/[\d\.]+',
                r'Version\s*[\d\.]+',
                r'Server:\s*(.+)',
            ],
            'file_paths': [
                r'[a-zA-Z]:\\[\w\\]+\.[\w]+',
                r'/(?:var|usr|home|etc)/[\w/]+\.[\w]+',
                r'in\s+([/\\][\w/\\]+\.[\w]+)',
            ],
            'database_info': [
                r'Database:\s*(\w+)',
                r'Table\s*[\'"](\w+)[\'"]',
                r'Column\s*[\'"](\w+)[\'"]',
            ],
            'usernames': [
                r'User\s*[\'"](\w+)[\'"]',
                r'Username:\s*(\w+)',
                r'root@localhost',
            ],
            'internal_ips': [
                r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                r'\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b',
                r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            ]
        }
    
    def analyze(self, content):
        """Analyze content for error patterns"""
        print("="*60)
        print("ERROR PATTERN ANALYSIS")
        print("="*60)
        print()
        
        findings = {}
        
        for category, patterns in self.patterns.items():
            matches = []
            
            for pattern in patterns:
                found = re.findall(pattern, content, re.IGNORECASE)
                if found:
                    matches.extend(found)
            
            if matches:
                findings[category] = list(set(matches))
                
                print(f"[+] {category.upper().replace('_', ' ')}:")
                for match in set(matches):
                    if isinstance(match, tuple):
                        match = match[0]
                    print(f"    - {match}")
                print()
        
        if not findings:
            print("[*] No sensitive information patterns detected")
        
        return findings
    
    def analyze_url(self):
        """Fetch and analyze URL"""
        print(f"[*] Analyzing: {self.url}")
        print()
        
        try:
            response = requests.get(self.url, timeout=10, verify=False)
            
            print(f"[+] Status: {response.status_code}")
            print(f"[+] Length: {len(response.text)} bytes")
            print()
            
            findings = self.analyze(response.text)
            
            # Also check headers
            print("="*60)
            print("HEADER ANALYSIS")
            print("="*60)
            print()
            
            interesting_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version',
                'X-Generator', 'X-Backend-Server'
            ]
            
            for header in interesting_headers:
                if header in response.headers:
                    print(f"[+] {header}: {response.headers[header]}")
            
            return findings
        
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            return {}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python error_analyzer.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    analyzer = ErrorAnalyzer(url)
    analyzer.analyze_url()
