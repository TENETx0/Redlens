#!/usr/bin/env python3
"""
Advanced Parameter Discovery Script
Discovers hidden parameters through fuzzing, wordlists, and analysis
"""

import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor
import time

class ParameterDiscovery:
    def __init__(self, url):
        self.url = url
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Common parameter names from various sources
        self.common_params = [
            # Pagination & Filtering
            'id', 'page', 'limit', 'offset', 'count', 'max', 'min',
            'sort', 'order', 'orderby', 'sortby', 'dir', 'direction',
            'filter', 'q', 'search', 'query', 'keyword', 'term',
            
            # Categories & Tags
            'category', 'cat', 'type', 'tag', 'tags', 'group',
            'section', 'topic', 'subject', 'class', 'classification',
            
            # Time & Date
            'from', 'to', 'start', 'end', 'date', 'time', 'year',
            'month', 'day', 'timestamp', 'since', 'until', 'before', 'after',
            
            # User & Session
            'user', 'userid', 'uid', 'username', 'email', 'session',
            'token', 'key', 'apikey', 'api_key', 'auth', 'access_token',
            
            # Actions & Operations
            'action', 'cmd', 'command', 'op', 'operation', 'method',
            'mode', 'view', 'display', 'show', 'format', 'output',
            
            # Navigation & Redirect
            'next', 'prev', 'return', 'redirect', 'url', 'link',
            'ref', 'referer', 'source', 'origin', 'callback', 'continue',
            
            # Content & Data
            'data', 'content', 'body', 'text', 'message', 'value',
            'name', 'title', 'description', 'comment', 'note',
            
            # Files & Media
            'file', 'filename', 'path', 'dir', 'folder', 'upload',
            'download', 'image', 'img', 'photo', 'video', 'doc',
            
            # Internationalization
            'lang', 'language', 'locale', 'region', 'country', 'timezone',
            
            # Analytics & Tracking
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'gclid', 'fbclid', 'ref_src', 'tracking', 'track',
            
            # Debug & Development
            'debug', 'test', 'dev', 'admin', 'config', 'settings',
            'verbose', 'trace', 'log', 'level', 'env', 'environment',
            
            # Versioning
            'v', 'version', 'ver', 'revision', 'build',
            
            # API Specific
            'fields', 'include', 'exclude', 'expand', 'embed',
            'pretty', 'indent', 'callback', 'jsonp',
            
            # E-commerce
            'product', 'item', 'sku', 'price', 'quantity', 'qty',
            'cart', 'checkout', 'payment', 'shipping', 'discount', 'coupon',
            
            # Forms
            'submit', 'confirm', 'accept', 'agree', 'terms',
            'subscribe', 'unsubscribe', 'newsletter',
            
            # Security
            'csrf', 'nonce', 'signature', 'hash', 'checksum',
            
            # Common Variations
            'p', 'q', 's', 't', 'u', 'v', 'x', 'y', 'z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        ]
    
    def test_parameter(self, param_name):
        """Test if a parameter affects the response"""
        try:
            # Baseline request
            baseline = self.session.get(self.url, timeout=5, verify=False)
            baseline_len = len(baseline.content)
            baseline_code = baseline.status_code
            
            # Test with parameter
            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{param_name}=test"
            test_resp = self.session.get(test_url, timeout=5, verify=False)
            test_len = len(test_resp.content)
            test_code = test_resp.status_code
            
            # Check for differences
            if abs(test_len - baseline_len) > 10 or test_code != baseline_code:
                return {
                    'param': param_name,
                    'found': True,
                    'diff_size': abs(test_len - baseline_len),
                    'status_diff': test_code != baseline_code
                }
        except:
            pass
        
        return None
    
    def discover(self, max_workers=10):
        """Discover parameters using fuzzing"""
        print(f"[*] Testing {len(self.common_params)} parameters...")
        found_params = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(self.test_parameter, self.common_params)
            
            for result in results:
                if result and result['found']:
                    found_params.append(result)
                    print(f"[+] Found parameter: {result['param']} (size diff: {result['diff_size']})")
        
        return found_params

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python param_discovery.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    discoverer = ParameterDiscovery(url)
    found = discoverer.discover()
    
    print(f"\n[*] Found {len(found)} parameters")
    for param in found:
        print(f"  - {param['param']}")
