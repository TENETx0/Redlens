#!/usr/bin/env python3
"""
Container & Orchestration Platform Detector
Detects Docker, Kubernetes, and other container platforms
"""

import requests
import sys
import re

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    END = '\033[0m'

class ContainerDetector:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        
        # Container patterns
        self.patterns = {
            'Docker': {
                'headers': ['X-Docker-Registry-Version'],
                'content': [r'docker', r'dockerfile', r'\.dockerignore'],
                'paths': ['/.dockerenv', '/var/run/docker.sock']
            },
            'Kubernetes': {
                'headers': [],
                'content': [r'kubernetes', r'k8s', r'kubectl', r'kube-system'],
                'paths': ['/api/v1/namespaces', '/apis', '/healthz']
            },
            'OpenShift': {
                'headers': [],
                'content': [r'openshift', r'\.apps\..*\.openshift'],
                'paths': ['/console', '/oauth']
            },
            'Rancher': {
                'headers': [],
                'content': [r'rancher', r'cattle'],
                'paths': ['/v3']
            },
            'Docker Swarm': {
                'headers': [],
                'content': [r'swarm', r'docker-swarm'],
                'paths': ['/swarm']
            }
        }
    
    def detect(self):
        """Detect container platforms"""
        print(f"{Colors.CYAN}[*] Container Platform Detection{Colors.END}")
        print(f"    Target: {self.target}\n")
        
        detected = []
        
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            
            for platform, config in self.patterns.items():
                evidence = []
                
                # Check headers
                for header in config['headers']:
                    if header in response.headers:
                        evidence.append(f"Header: {header}")
                
                # Check content
                for pattern in config['content']:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        evidence.append(f"Content: {pattern}")
                
                # Test paths
                for path in config['paths']:
                    try:
                        test_response = self.session.get(
                            self.target.rstrip('/') + path,
                            timeout=5,
                            verify=False
                        )
                        if test_response.status_code in [200, 401, 403]:
                            evidence.append(f"Path: {path} [{test_response.status_code}]")
                    except:
                        pass
                
                if evidence:
                    detected.append({
                        'platform': platform,
                        'evidence': evidence
                    })
                    
                    print(f"{Colors.GREEN}[✓] {platform}{Colors.END}")
                    for e in evidence:
                        print(f"    • {e}")
                    print()
            
            if not detected:
                print(f"{Colors.YELLOW}[i] No container platforms detected{Colors.END}")
        
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python container_detector.py <target_url>{Colors.END}")
        sys.exit(1)
    
    target = sys.argv[1]
    detector = ContainerDetector(target)
    detector.detect()

if __name__ == "__main__":
    main()
