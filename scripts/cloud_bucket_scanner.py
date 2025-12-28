#!/usr/bin/env python3
"""
Advanced Cloud Bucket Scanner
Scans for exposed cloud storage buckets and tests permissions
"""

import requests
import sys
import re
from urllib.parse import urlparse
import time

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    END = '\033[0m'

class BucketScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Bucket-Scanner/1.0'}
        
        # Comprehensive bucket name patterns
        self.bucket_patterns = [
            '{company}',
            '{company}-backup',
            '{company}-backups',
            '{company}-dev',
            '{company}-staging',
            '{company}-prod',
            '{company}-production',
            '{company}-test',
            '{company}-data',
            '{company}-files',
            '{company}-uploads',
            '{company}-assets',
            '{company}-static',
            '{company}-media',
            '{company}-logs',
            '{company}-archive',
            '{company}-public',
            '{company}-private',
            'backup-{company}',
            'dev-{company}',
            'prod-{company}',
            'www-{company}',
            'api-{company}',
            '{company}.com',
            '{company}.io',
            '{company}-website',
            '{company}-web',
            '{company}-app',
            '{company}-storage',
            '{company}-bucket',
            '{company}-s3',
        ]
        
        # Cloud storage endpoints
        self.storage_endpoints = {
            'AWS S3': [
                'https://{bucket}.s3.amazonaws.com',
                'https://s3.amazonaws.com/{bucket}',
                'https://{bucket}.s3-us-east-1.amazonaws.com',
                'https://{bucket}.s3-us-west-2.amazonaws.com',
                'https://{bucket}.s3-eu-west-1.amazonaws.com',
            ],
            'Azure Blob': [
                'https://{bucket}.blob.core.windows.net',
            ],
            'GCP Storage': [
                'https://storage.googleapis.com/{bucket}',
                'https://{bucket}.storage.googleapis.com',
            ],
            'DigitalOcean Spaces': [
                'https://{bucket}.nyc3.digitaloceanspaces.com',
                'https://{bucket}.sfo2.digitaloceanspaces.com',
            ]
        }
    
    def generate_bucket_names(self, company_name):
        """Generate potential bucket names"""
        buckets = []
        
        # Clean company name
        company = company_name.lower().replace(' ', '').replace('.', '')
        
        for pattern in self.bucket_patterns:
            bucket = pattern.format(company=company)
            buckets.append(bucket)
        
        return buckets
    
    def test_bucket(self, bucket_name, storage_type, endpoint_template):
        """Test if bucket exists and is accessible"""
        endpoint = endpoint_template.format(bucket=bucket_name)
        
        try:
            response = self.session.get(endpoint, timeout=5, verify=False)
            
            if response.status_code == 200:
                return {
                    'status': 'PUBLIC',
                    'severity': 'CRITICAL',
                    'url': endpoint,
                    'size': len(response.text)
                }
            elif response.status_code == 403:
                return {
                    'status': 'EXISTS (Private)',
                    'severity': 'INFO',
                    'url': endpoint
                }
            elif response.status_code == 404:
                return None
            else:
                return {
                    'status': f'UNKNOWN ({response.status_code})',
                    'severity': 'UNKNOWN',
                    'url': endpoint
                }
        
        except Exception as e:
            return None
    
    def scan(self, company_name):
        """Scan for buckets"""
        print(f"{Colors.CYAN}[*] Scanning for cloud storage buckets{Colors.END}")
        print(f"    Company: {company_name}\n")
        
        bucket_names = self.generate_bucket_names(company_name)
        print(f"[*] Testing {len(bucket_names)} bucket names across {len(self.storage_endpoints)} platforms\n")
        
        findings = []
        tested = 0
        
        for bucket in bucket_names:
            for storage_type, endpoints in self.storage_endpoints.items():
                for endpoint_template in endpoints:
                    tested += 1
                    result = self.test_bucket(bucket, storage_type, endpoint_template)
                    
                    if result:
                        findings.append({
                            'bucket': bucket,
                            'type': storage_type,
                            **result
                        })
                        
                        # Print finding
                        color = Colors.RED if result['status'] == 'PUBLIC' else Colors.YELLOW
                        print(f"{color}[{result['status']}]{Colors.END} {storage_type}: {bucket}")
                        print(f"    URL: {result['url']}")
                        if result['status'] == 'PUBLIC':
                            print(f"    {Colors.RED}⚠ EXPOSED TO PUBLIC{Colors.END}")
                        print()
            
            # Progress
            if tested % 10 == 0:
                print(f"{Colors.CYAN}Progress: {tested} tests completed...{Colors.END}", end='\r')
        
        print()
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.YELLOW}SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
        
        if findings:
            public = [f for f in findings if f['status'] == 'PUBLIC']
            private = [f for f in findings if 'Private' in f['status']]
            
            if public:
                print(f"{Colors.RED}[!] {len(public)} PUBLIC bucket(s) found{Colors.END}")
                for f in public:
                    print(f"    • {f['type']}: {f['bucket']}")
            
            if private:
                print(f"\n{Colors.YELLOW}[i] {len(private)} private bucket(s) detected{Colors.END}")
        else:
            print(f"{Colors.GREEN}[✓] No exposed buckets found{Colors.END}")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python cloud_bucket_scanner.py <company_name>{Colors.END}")
        print(f"\nExample: python cloud_bucket_scanner.py example")
        sys.exit(1)
    
    company = sys.argv[1]
    scanner = BucketScanner(company)
    scanner.scan(company)

if __name__ == "__main__":
    main()
