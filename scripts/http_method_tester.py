#!/usr/bin/env python3
"""
HTTP Method Testing Script
Tests all HTTP methods on endpoints to discover allowed methods
"""

import requests
import sys
from urllib.parse import urlparse

class HTTPMethodTester:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        self.methods = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH',
            'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'
        ]
    
    def test_method(self, method):
        """Test a specific HTTP method"""
        try:
            response = self.session.request(
                method,
                self.url,
                timeout=5,
                verify=False,
                allow_redirects=False
            )
            
            return {
                'method': method,
                'status': response.status_code,
                'allowed': response.status_code != 405,
                'headers': dict(response.headers)
            }
        except Exception as e:
            return {
                'method': method,
                'status': None,
                'allowed': False,
                'error': str(e)
            }
    
    def test_all_methods(self):
        """Test all HTTP methods"""
        print(f"[*] Testing HTTP methods on: {self.url}\n")
        
        results = []
        
        for method in self.methods:
            result = self.test_method(method)
            results.append(result)
            
            if result['allowed']:
                print(f"[+] {method.ljust(10)} : {result['status']} (ALLOWED)")
            else:
                status = result.get('status', 'ERROR')
                print(f"[-] {method.ljust(10)} : {status} (NOT ALLOWED)")
        
        # Check Allow header from OPTIONS
        options_result = next((r for r in results if r['method'] == 'OPTIONS'), None)
        if options_result and 'allow' in options_result.get('headers', {}):
            print(f"\n[*] Allow header: {options_result['headers']['allow']}")
        
        return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python http_method_tester.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    tester = HTTPMethodTester(url)
    results = tester.test_all_methods()
    
    allowed = [r for r in results if r['allowed']]
    print(f"\n[*] Allowed methods: {', '.join([r['method'] for r in allowed])}")
