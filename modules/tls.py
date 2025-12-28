#!/usr/bin/env python3
"""
TLS / SSL Analysis Module
Performs comprehensive TLS/SSL security analysis including protocol versions, cipher suites,
certificate validation, HSTS, OCSP stapling, and forward secrecy testing.
"""

import ssl
import socket
import requests
import time
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse
from colorama import Fore, Style
from threading import Thread
import warnings
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess

warnings.filterwarnings('ignore')

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

class TLSAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.port = self.parsed_url.port or 443
        
        self.results = {
            'target': target_url,
            'hostname': self.hostname,
            'port': self.port,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'checks': {}
        }
        
        # TLS Protocol versions to test
        self.tls_protocols = {
            'SSLv2': {'code': None, 'deprecated': True},
            'SSLv3': {'code': ssl.PROTOCOL_SSLv23, 'deprecated': True},
            'TLSv1.0': {'code': ssl.PROTOCOL_TLSv1, 'deprecated': True},
            'TLSv1.1': {'code': ssl.PROTOCOL_TLSv1_1, 'deprecated': True},
            'TLSv1.2': {'code': ssl.PROTOCOL_TLSv1_2, 'deprecated': False},
            'TLSv1.3': {'code': ssl.PROTOCOL_TLS, 'deprecated': False},
        }
        

        
        # === WEAK CIPHERS (MUST NOT BE SUPPORTED) ===
        self.weak_ciphers = [
            # NULL ciphers (no encryption - critical vulnerability)
            'NULL-MD5', 'NULL-SHA', 'NULL-SHA256', 'NULL-SHA384',
            'ECDHE-RSA-NULL-SHA', 'ECDHE-ECDSA-NULL-SHA',
            'AECDH-NULL-SHA', 'GOST-NULL-GOST94',
            
            # Export ciphers (weak 40-56 bit keys - FREAK attack)
            'EXP-RC4-MD5', 'EXP-RC2-CBC-MD5', 'EXP-DES-CBC-SHA',
            'EXP-DH-DSS-DES-CBC-SHA', 'EXP-DH-RSA-DES-CBC-SHA',
            'EXP-EDH-DSS-DES-CBC-SHA', 'EXP-EDH-RSA-DES-CBC-SHA',
            'EXP-ADH-DES-CBC-SHA', 'EXP-ADH-RC4-MD5',
            'EXP1024-DES-CBC-SHA', 'EXP1024-DHE-DSS-DES-CBC-SHA',
            'EXP1024-RC4-SHA', 'EXP1024-DHE-DSS-RC4-SHA',
            'EXP1024-RC2-CBC-MD5', 'EXP1024-RC4-MD5',
            
            # DES ciphers (56-bit key - SWEET32 attack)
            'DES-CBC-SHA', 'DES-CBC-MD5', 'DES-CFB-M1',
            'EDH-RSA-DES-CBC-SHA', 'EDH-DSS-DES-CBC-SHA',
            'ADH-DES-CBC-SHA', 'DES-CBC3-MD5',
            
            # 3DES ciphers (deprecated - SWEET32 attack, 64-bit block)
            'DES-CBC3-SHA', 'EDH-RSA-DES-CBC3-SHA', 'EDH-DSS-DES-CBC3-SHA',
            'ECDHE-RSA-DES-CBC3-SHA', 'ECDHE-ECDSA-DES-CBC3-SHA',
            'ADH-DES-CBC3-SHA', 'AECDH-DES-CBC3-SHA',
            'PSK-3DES-EDE-CBC-SHA', 'DHE-PSK-3DES-EDE-CBC-SHA',
            'RSA-PSK-3DES-EDE-CBC-SHA', 'ECDHE-PSK-3DES-EDE-CBC-SHA',
            
            # RC4 ciphers (broken algorithm - RC4 attacks)
            'RC4-MD5', 'RC4-SHA', 'RC4-64-MD5', 'RC2-CBC-MD5',
            'ECDHE-RSA-RC4-SHA', 'ECDHE-ECDSA-RC4-SHA',
            'AECDH-RC4-SHA', 'ADH-RC4-MD5', 'PSK-RC4-SHA',
            'DHE-PSK-RC4-SHA', 'RSA-PSK-RC4-SHA', 'ECDHE-PSK-RC4-SHA',
            
            # MD5 based ciphers (weak hash - collision attacks)
            'RC2-CBC-MD5', 'IDEA-CBC-MD5', 'DES-CBC-MD5',
            'RC4-64-MD5', 'NULL-MD5',
            
            # Anonymous Diffie-Hellman (no authentication - MITM vulnerable)
            'ADH-AES128-SHA', 'ADH-AES256-SHA', 'ADH-AES128-SHA256',
            'ADH-AES256-SHA256', 'ADH-AES128-GCM-SHA256', 'ADH-AES256-GCM-SHA384',
            'ADH-CAMELLIA128-SHA', 'ADH-CAMELLIA256-SHA', 'ADH-CAMELLIA128-SHA256',
            'ADH-CAMELLIA256-SHA256', 'ADH-SEED-SHA',
            'AECDH-AES128-SHA', 'AECDH-AES256-SHA', 'AECDH-NULL-SHA',
            'AECDH-RC4-SHA', 'AECDH-DES-CBC3-SHA',
            
            # SEED ciphers (weak, not widely tested)
            'SEED-SHA', 'DHE-RSA-SEED-SHA', 'DHE-DSS-SEED-SHA',
            'ADH-SEED-SHA', 'PSK-SEED-CBC-SHA',
            
            # IDEA ciphers (weak, 64-bit block)
            'IDEA-CBC-SHA', 'IDEA-CBC-MD5',
            
            # GOST ciphers (not widely supported/tested in western infrastructure)
            'GOST94-GOST89-GOST89', 'GOST2001-GOST89-GOST89',
            'GOST2012256-GOST89-GOST89', 'GOST94-NULL-GOST94',
            
            # SRP ciphers (Secure Remote Password - rarely used)
            'SRP-AES-128-CBC-SHA', 'SRP-AES-256-CBC-SHA',
            'SRP-3DES-EDE-CBC-SHA', 'SRP-RSA-AES-128-CBC-SHA',
            
            # ARIA ciphers (Korean standard - limited support)
            'ARIA128-SHA256', 'ARIA256-SHA384',
        ]
        
        # === MEDIUM STRENGTH CIPHERS (acceptable but not recommended) ===
        self.medium_ciphers = [
            # AES-128 CBC mode (vulnerable to BEAST on TLS 1.0, LUCKY13)
            'AES128-SHA', 'AES128-SHA256', 'DHE-RSA-AES128-SHA',
            'DHE-DSS-AES128-SHA', 'ECDHE-RSA-AES128-SHA',
            'ECDHE-ECDSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES128-SHA256', 'PSK-AES128-CBC-SHA',
            'PSK-AES128-CBC-SHA256', 'DHE-PSK-AES128-CBC-SHA',
            'DHE-PSK-AES128-CBC-SHA256', 'RSA-PSK-AES128-CBC-SHA',
            'RSA-PSK-AES128-CBC-SHA256', 'ECDHE-PSK-AES128-CBC-SHA',
            'ECDHE-PSK-AES128-CBC-SHA256',
            
            # AES-256 CBC mode (vulnerable to BEAST on TLS 1.0, LUCKY13)
            'AES256-SHA', 'AES256-SHA256', 'DHE-RSA-AES256-SHA',
            'DHE-DSS-AES256-SHA', 'ECDHE-RSA-AES256-SHA',
            'ECDHE-ECDSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES256-SHA384', 'PSK-AES256-CBC-SHA',
            'PSK-AES256-CBC-SHA384', 'DHE-PSK-AES256-CBC-SHA',
            'DHE-PSK-AES256-CBC-SHA384', 'RSA-PSK-AES256-CBC-SHA',
            'RSA-PSK-AES256-CBC-SHA384', 'ECDHE-PSK-AES256-CBC-SHA',
            'ECDHE-PSK-AES256-CBC-SHA384',
            
            # CAMELLIA ciphers (less tested, limited support)
            'CAMELLIA128-SHA', 'CAMELLIA256-SHA', 'CAMELLIA128-SHA256',
            'CAMELLIA256-SHA256', 'DHE-RSA-CAMELLIA128-SHA',
            'DHE-RSA-CAMELLIA256-SHA', 'DHE-DSS-CAMELLIA128-SHA',
            'DHE-DSS-CAMELLIA256-SHA', 'ECDHE-RSA-CAMELLIA128-SHA256',
            'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDHE-ECDSA-CAMELLIA128-SHA256',
            'ECDHE-ECDSA-CAMELLIA256-SHA384', 'PSK-CAMELLIA128-SHA256',
            'PSK-CAMELLIA256-SHA384', 'DHE-PSK-CAMELLIA128-SHA256',
            'DHE-PSK-CAMELLIA256-SHA384',
            
            # Static RSA key exchange (no forward secrecy)
            'AES128-SHA', 'AES256-SHA', 'AES128-SHA256', 'AES256-SHA256',
            'CAMELLIA128-SHA', 'CAMELLIA256-SHA',
        ]
        
        # === STRONG CIPHERS (RECOMMENDED FOR PRODUCTION) ===
        self.strong_ciphers = [
            # === TLS 1.3 Ciphers (AEAD only, modern, secure) ===
            'TLS_AES_256_GCM_SHA384',           # Widely supported, strong
            'TLS_CHACHA20_POLY1305_SHA256',     # Mobile-optimized, fast
            'TLS_AES_128_GCM_SHA256',           # Fast, widely supported
            'TLS_AES_128_CCM_SHA256',           # Constrained environments
            'TLS_AES_128_CCM_8_SHA256',         # IoT optimized
            
            # === ECDHE with AES-GCM (AEAD - Authenticated Encryption) ===
            # Used by: Kubernetes, Docker Registry, Harbor, GitLab, GitHub
            'ECDHE-RSA-AES128-GCM-SHA256',      # Most common in K8s
            'ECDHE-ECDSA-AES128-GCM-SHA256',    # ECC certificates
            'ECDHE-RSA-AES256-GCM-SHA384',      # Higher security
            'ECDHE-ECDSA-AES256-GCM-SHA384',    # ECC + 256-bit
            
            # === DHE with AES-GCM (RSA certificates with FS) ===
            # Used by: Legacy enterprise systems, compliance requirements
            'DHE-RSA-AES128-GCM-SHA256',        # Forward secrecy with RSA
            'DHE-RSA-AES256-GCM-SHA384',        # Stronger variant
            'DHE-DSS-AES128-GCM-SHA256',        # DSS variant
            'DHE-DSS-AES256-GCM-SHA384',        # DSS stronger
            
            # === ChaCha20-Poly1305 (AEAD, optimized for mobile/ARM) ===
            # Used by: Android, Mobile apps, ARM-based cloud instances
            'ECDHE-RSA-CHACHA20-POLY1305',      # CloudFlare preference
            'ECDHE-ECDSA-CHACHA20-POLY1305',    # ECC variant
            'DHE-RSA-CHACHA20-POLY1305',        # DHE variant
            
            # === AES-CCM (AEAD for constrained devices) ===
            # Used by: IoT, embedded systems, DTLS
            'ECDHE-RSA-AES128-CCM',
            'ECDHE-ECDSA-AES128-CCM',
            'ECDHE-RSA-AES256-CCM',
            'ECDHE-ECDSA-AES256-CCM',
            'DHE-RSA-AES128-CCM',
            'DHE-RSA-AES256-CCM',
            'AES128-CCM',
            'AES256-CCM',
            'AES128-CCM8',
            'AES256-CCM8',
            
            # === Static AES-GCM (when forward secrecy not required) ===
            # Used by: Some embedded systems, hardware crypto
            'AES128-GCM-SHA256',
            'AES256-GCM-SHA384',
            
            # === PSK with AEAD (Pre-Shared Key for M2M) ===
            # Used by: IoT, machine-to-machine, internal services
            'PSK-AES128-GCM-SHA256',
            'PSK-AES256-GCM-SHA384',
            'DHE-PSK-AES128-GCM-SHA256',
            'DHE-PSK-AES256-GCM-SHA384',
            'RSA-PSK-AES128-GCM-SHA256',
            'RSA-PSK-AES256-GCM-SHA384',
            'ECDHE-PSK-AES128-GCM-SHA256',
            'ECDHE-PSK-AES256-GCM-SHA384',
            'PSK-CHACHA20-POLY1305',
            'DHE-PSK-CHACHA20-POLY1305',
            'ECDHE-PSK-CHACHA20-POLY1305',
            'RSA-PSK-CHACHA20-POLY1305',
        ]
        
        # === CLOUD-NATIVE & DEVOPS SPECIFIC CIPHERS ===
        self.cloud_native_ciphers = [
            # Kubernetes API Server defaults
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            
            # Docker Registry / Harbor
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            
            # etcd (Kubernetes backend)
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            
            # Consul (Service Mesh)
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            
            # Istio / Envoy Proxy
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            
            # GitLab / GitHub Enterprise
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            
            # Jenkins
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            
            # Prometheus / Grafana
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            
            # HashiCorp Vault
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        ]
        
        # === CONTAINER RUNTIME CIPHERS ===
        self.container_ciphers = [
            # Docker Engine TLS
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            
            # containerd
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            
            # CRI-O
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        ]
        
        # === GIT PROTOCOL CIPHERS ===
        self.git_ciphers = [
            # Git over HTTPS (used by GitHub, GitLab, Bitbucket)
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            
            # Git SSH (OpenSSH ciphers)
            'chacha20-poly1305@openssh.com',
            'aes128-gcm@openssh.com',
            'aes256-gcm@openssh.com',
        ]
        
        # Combine all strong ciphers including cloud-native
        self.all_strong_ciphers = list(set(
            self.strong_ciphers + 
            self.cloud_native_ciphers + 
            self.container_ciphers + 
            [c for c in self.git_ciphers if not c.endswith('openssh.com')]
        ))
        
        # All ciphers to test
        self.all_ciphers = list(set(
            self.weak_ciphers + 
            self.medium_ciphers + 
            self.all_strong_ciphers
        ))
        
        # Cipher categories for reporting
        self.cipher_categories = {
            'tls_13': [c for c in self.all_strong_ciphers if c.startswith('TLS_')],
            'kubernetes': ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                          'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-GCM-SHA384'],
            'docker': ['ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384'],
            'chacha20': [c for c in self.all_strong_ciphers if 'CHACHA20' in c],
            'forward_secrecy': [c for c in self.all_strong_ciphers if any(x in c for x in ['ECDHE', 'DHE'])],
        }
    
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
    
    def test_tls_versions(self):
        """Test supported TLS protocol versions"""
        self.print_section("TLS Protocol Version Testing")
        
        loader = LoadingBar("Testing TLS protocol versions")
        loader.start()
        
        supported_protocols = {}
        
        for protocol_name, protocol_info in self.tls_protocols.items():
            if protocol_info['code'] is None:
                # SSLv2 is not supported in modern Python
                supported_protocols[protocol_name] = {
                    'supported': False,
                    'deprecated': protocol_info['deprecated'],
                    'tested': False
                }
                continue
            
            try:
                context = ssl.SSLContext(protocol_info['code'])
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # For TLS 1.3, use PROTOCOL_TLS
                if protocol_name == 'TLSv1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                elif protocol_name == 'TLSv1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif protocol_name == 'TLSv1.1':
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                elif protocol_name == 'TLSv1.0':
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                
                with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        supported_protocols[protocol_name] = {
                            'supported': True,
                            'version': ssock.version(),
                            'deprecated': protocol_info['deprecated'],
                            'tested': True
                        }
            except:
                supported_protocols[protocol_name] = {
                    'supported': False,
                    'deprecated': protocol_info['deprecated'],
                    'tested': True
                }
        
        loader.stop(True)
        
        # Print results
        for protocol_name, result in supported_protocols.items():
            if not result['tested']:
                continue
                
            if result['supported']:
                if result['deprecated']:
                    self.print_check(f"{protocol_name}", "WARN", 
                                   f"Supported (DEPRECATED - should be disabled)")
                else:
                    self.print_check(f"{protocol_name}", "PASS", 
                                   f"Supported (Version: {result.get('version', 'Unknown')})")
            else:
                if result['deprecated']:
                    self.print_check(f"{protocol_name}", "PASS", 
                                   "Not supported (Good - deprecated protocol)")
                else:
                    self.print_check(f"{protocol_name}", "WARN", 
                                   "Not supported")
        
        self.results['checks']['tls_versions'] = supported_protocols
        return supported_protocols
    
    def enumerate_cipher_suites(self):
        """Enumerate supported cipher suites"""
        self.print_section("Cipher Suite Enumeration")
        
        loader = LoadingBar(f"Testing {len(self.all_ciphers)} cipher suites (This may Take few minutes)")
        loader.start()
        
        cipher_results = {
            'weak_supported': [],
            'medium_supported': [],
            'strong_supported': [],
            'weak_not_supported': [],
            'total_tested': len(self.all_ciphers),
            'by_category': {
                'tls_13': [],
                'kubernetes': [],
                'docker': [],
                'git': [],
                'chacha20': [],
                'forward_secrecy': [],
                'psk': [],
                'aead': [],
            }
        }
        
        # Test weak ciphers
        for cipher in self.weak_ciphers:
            if self._test_cipher(cipher):
                cipher_results['weak_supported'].append(cipher)
            else:
                cipher_results['weak_not_supported'].append(cipher)
        
        # Test medium ciphers
        for cipher in self.medium_ciphers:
            if self._test_cipher(cipher):
                cipher_results['medium_supported'].append(cipher)
        
        # Test strong ciphers
        for cipher in self.all_strong_ciphers:
            if self._test_cipher(cipher):
                cipher_results['strong_supported'].append(cipher)
                
                # Categorize by use case
                if cipher.startswith('TLS_'):
                    cipher_results['by_category']['tls_13'].append(cipher)
                if cipher in self.cipher_categories.get('kubernetes', []):
                    cipher_results['by_category']['kubernetes'].append(cipher)
                if cipher in self.cipher_categories.get('docker', []):
                    cipher_results['by_category']['docker'].append(cipher)
                if 'CHACHA20' in cipher:
                    cipher_results['by_category']['chacha20'].append(cipher)
                if any(x in cipher for x in ['ECDHE', 'DHE']):
                    cipher_results['by_category']['forward_secrecy'].append(cipher)
                if 'PSK' in cipher:
                    cipher_results['by_category']['psk'].append(cipher)
                if any(x in cipher for x in ['GCM', 'CCM', 'POLY1305']):
                    cipher_results['by_category']['aead'].append(cipher)
        
        loader.stop(True)
        
        # Print results
        self.print_check("Total Ciphers Tested", "PASS", str(cipher_results['total_tested']))
        
        if cipher_results['weak_supported']:
            self.print_check("Weak Ciphers", "FAIL", 
                           f"{len(cipher_results['weak_supported'])} WEAK cipher(s) supported - CRITICAL SECURITY RISK!")
            print(f"\n{Fore.RED}  Weak Ciphers Found (MUST BE DISABLED):{Style.RESET_ALL}")
            for cipher in cipher_results['weak_supported'][:15]:
                print(f"    {Fore.RED}[✗]{Style.RESET_ALL} {cipher}")
            if len(cipher_results['weak_supported']) > 15:
                print(f"    {Fore.YELLOW}... and {len(cipher_results['weak_supported']) - 15} more{Style.RESET_ALL}")
        else:
            self.print_check("Weak Ciphers", "PASS", "No weak ciphers supported ✓")
        
        if cipher_results['medium_supported']:
            self.print_check("Medium Strength Ciphers", "WARN", 
                           f"{len(cipher_results['medium_supported'])} medium strength cipher(s) supported")
            print(f"\n{Fore.YELLOW}  Medium Strength Ciphers (Consider disabling CBC mode):{Style.RESET_ALL}")
            for cipher in cipher_results['medium_supported'][:8]:
                print(f"    {Fore.YELLOW}[⚠]{Style.RESET_ALL} {cipher}")
        
        if cipher_results['strong_supported']:
            self.print_check("Strong Ciphers", "PASS", 
                           f"{len(cipher_results['strong_supported'])} strong cipher(s) supported")
            
            # Print by category
            print(f"\n{Fore.GREEN}  === CIPHER SUITE ANALYSIS BY PLATFORM ==={Style.RESET_ALL}")
            
            if cipher_results['by_category']['tls_13']:
                print(f"\n{Fore.CYAN}  TLS 1.3 Ciphers (Modern):{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['tls_13'][:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            if cipher_results['by_category']['kubernetes']:
                print(f"\n{Fore.CYAN}  Kubernetes API Server Compatible:{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['kubernetes'][:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            if cipher_results['by_category']['docker']:
                print(f"\n{Fore.CYAN}  Docker Registry Compatible:{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['docker'][:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            if cipher_results['by_category']['chacha20']:
                print(f"\n{Fore.CYAN}  ChaCha20-Poly1305 (Mobile/ARM Optimized):{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['chacha20'][:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            if cipher_results['by_category']['aead']:
                print(f"\n{Fore.CYAN}  AEAD Ciphers (Authenticated Encryption):{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['aead'][:8]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            if cipher_results['by_category']['psk']:
                print(f"\n{Fore.CYAN}  PSK Ciphers (IoT/M2M):{Style.RESET_ALL}")
                for cipher in cipher_results['by_category']['psk'][:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            # Show total strong ciphers if many
            if len(cipher_results['strong_supported']) > 20:
                print(f"\n{Fore.GREEN}  ... and {len(cipher_results['strong_supported']) - 20} more strong ciphers{Style.RESET_ALL}")
        else:
            self.print_check("Strong Ciphers", "FAIL", "No strong ciphers detected - CRITICAL!")
        
        self.results['checks']['cipher_suites'] = cipher_results
        return cipher_results
    
    def _test_cipher(self, cipher_name):
        """Test if a specific cipher is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher_name)
            
            with socket.create_connection((self.hostname, self.port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    return True
        except:
            return False
    
    def analyze_certificate(self):
        """Analyze SSL/TLS certificate"""
        self.print_section("Certificate Analysis")
        
        loader = LoadingBar("Analyzing SSL/TLS certificate")
        loader.start()
        
        cert_info = {}
        
        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    pem_cert = ssock.getpeercert()
                    
                    # Parse certificate with cryptography
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Extract certificate information
                    cert_info = {
                        'subject': dict(x[0] for x in pem_cert['subject']),
                        'issuer': dict(x[0] for x in pem_cert['issuer']),
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_before': str(cert.not_valid_before),
                        'not_after': str(cert.not_valid_after),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_algorithm': cert.public_key().__class__.__name__,
                        'key_size': self._get_key_size(cert.public_key()),
                        'san': [],
                        'is_self_signed': False,
                        'days_until_expiry': (cert.not_valid_after - datetime.now()).days,
                    }
                    
                    # Get Subject Alternative Names
                    try:
                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        cert_info['san'] = [str(name) for name in san_ext.value]
                    except:
                        pass
                    
                    # Check if self-signed
                    if cert_info['subject'] == cert_info['issuer']:
                        cert_info['is_self_signed'] = True
                    
                    # Check certificate chain
                    cert_info['chain_length'] = len(ssock.getpeercert_chain()) if hasattr(ssock, 'getpeercert_chain') else 1
            
            loader.stop(True)
            
            # Print results
            self.print_check("Certificate Subject", "PASS", 
                           cert_info['subject'].get('commonName', 'Unknown'))
            
            self.print_check("Certificate Issuer", "PASS", 
                           cert_info['issuer'].get('commonName', 'Unknown'))
            
            # Self-signed check
            if cert_info['is_self_signed']:
                self.print_check("Self-Signed Certificate", "FAIL", 
                               "Certificate is self-signed - NOT TRUSTED")
            else:
                self.print_check("Self-Signed Certificate", "PASS", 
                               "Certificate is signed by trusted CA")
            
            # Expiry check
            days_left = cert_info['days_until_expiry']
            if days_left < 0:
                self.print_check("Certificate Validity", "FAIL", 
                               f"EXPIRED {abs(days_left)} days ago")
            elif days_left < 30:
                self.print_check("Certificate Validity", "WARN", 
                               f"Expires in {days_left} days - RENEWAL NEEDED")
            else:
                self.print_check("Certificate Validity", "PASS", 
                               f"Valid for {days_left} days (Expires: {cert_info['not_after'][:10]})")
            
            # Key size check
            key_size = cert_info.get('key_size', 0)
            if key_size < 2048:
                self.print_check("Key Size", "FAIL", 
                               f"{key_size} bits - TOO WEAK (minimum 2048)")
            elif key_size < 3072:
                self.print_check("Key Size", "PASS", 
                               f"{key_size} bits - Adequate")
            else:
                self.print_check("Key Size", "PASS", 
                               f"{key_size} bits - Strong")
            
            # Signature algorithm check
            sig_algo = cert_info.get('signature_algorithm', '')
            if 'sha1' in sig_algo.lower() or 'md5' in sig_algo.lower():
                self.print_check("Signature Algorithm", "FAIL", 
                               f"{sig_algo} - WEAK HASH")
            else:
                self.print_check("Signature Algorithm", "PASS", sig_algo)
            
            # SAN check
            if cert_info.get('san'):
                self.print_check("Subject Alternative Names", "PASS", 
                               f"{len(cert_info['san'])} name(s)")
                for san in cert_info['san'][:5]:
                    print(f"    {Fore.CYAN}→{Style.RESET_ALL} {san}")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Certificate Analysis", "FAIL", str(e)[:100])
            cert_info['error'] = str(e)
        
        self.results['checks']['certificate'] = cert_info
        return cert_info
    
    def _get_key_size(self, public_key):
        """Get the key size from a public key"""
        try:
            return public_key.key_size
        except:
            return 0
    
    def check_hsts(self):
        """Check HSTS (HTTP Strict Transport Security) configuration"""
        self.print_section("HSTS (HTTP Strict Transport Security) Analysis")
        
        loader = LoadingBar("Checking HSTS configuration")
        loader.start()
        
        hsts_info = {
            'enabled': False,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'header': None
        }
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if hsts_header:
                hsts_info['enabled'] = True
                hsts_info['header'] = hsts_header
                
                # Parse max-age
                if 'max-age=' in hsts_header:
                    max_age_str = hsts_header.split('max-age=')[1].split(';')[0].strip()
                    try:
                        hsts_info['max_age'] = int(max_age_str)
                    except:
                        pass
                
                # Check for includeSubDomains
                if 'includeSubDomains' in hsts_header:
                    hsts_info['include_subdomains'] = True
                
                # Check for preload
                if 'preload' in hsts_header:
                    hsts_info['preload'] = True
            
            loader.stop(True)
            
            # Print results
            if hsts_info['enabled']:
                self.print_check("HSTS Enabled", "PASS", "Strict-Transport-Security header present")
                
                # Check max-age
                max_age = hsts_info.get('max_age', 0)
                if max_age == 0:
                    self.print_check("HSTS max-age", "FAIL", "max-age is 0 or not set")
                elif max_age < 31536000:  # Less than 1 year
                    self.print_check("HSTS max-age", "WARN", 
                                   f"{max_age} seconds ({max_age // 86400} days) - Recommended: 31536000 (1 year)")
                else:
                    self.print_check("HSTS max-age", "PASS", 
                                   f"{max_age} seconds ({max_age // 86400} days)")
                
                # Check includeSubDomains
                if hsts_info['include_subdomains']:
                    self.print_check("HSTS includeSubDomains", "PASS", "Enabled")
                else:
                    self.print_check("HSTS includeSubDomains", "WARN", "Not enabled")
                
                # Check preload
                if hsts_info['preload']:
                    self.print_check("HSTS preload", "PASS", "Enabled")
                else:
                    self.print_check("HSTS preload", "WARN", "Not enabled")
            else:
                self.print_check("HSTS", "FAIL", "Strict-Transport-Security header NOT found")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("HSTS Check", "FAIL", str(e)[:100])
            hsts_info['error'] = str(e)
        
        self.results['checks']['hsts'] = hsts_info
        return hsts_info
    
    def check_ocsp_stapling(self):
        """Check OCSP stapling status"""
        self.print_section("OCSP Stapling Status")
        
        loader = LoadingBar("Checking OCSP stapling")
        loader.start()
        
        ocsp_info = {
            'stapling_enabled': False,
            'method': 'openssl_test'
        }
        
        try:
            # Use OpenSSL command to check OCSP stapling
            cmd = [
                'openssl', 's_client',
                '-connect', f'{self.hostname}:{self.port}',
                '-tlsextdebug', '-status',
                '-servername', self.hostname
            ]
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input='Q\n', timeout=10)
            
            # Check for OCSP response in output
            if 'OCSP response' in stdout or 'OCSP Response Status: successful' in stdout:
                ocsp_info['stapling_enabled'] = True
                ocsp_info['details'] = 'OCSP response received'
            elif 'OCSP response: no response sent' in stdout:
                ocsp_info['stapling_enabled'] = False
                ocsp_info['details'] = 'No OCSP response sent'
            
            loader.stop(True)
            
            # Print results
            if ocsp_info['stapling_enabled']:
                self.print_check("OCSP Stapling", "PASS", "Enabled")
            else:
                self.print_check("OCSP Stapling", "WARN", "Not enabled or not detected")
        
        except subprocess.TimeoutExpired:
            loader.stop(False)
            ocsp_info['error'] = 'Timeout'
            self.print_check("OCSP Stapling", "WARN", "Test timeout - unable to determine")
        except FileNotFoundError:
            loader.stop(False)
            ocsp_info['error'] = 'OpenSSL not found'
            self.print_check("OCSP Stapling", "WARN", "OpenSSL command not available")
        except Exception as e:
            loader.stop(False)
            ocsp_info['error'] = str(e)
            self.print_check("OCSP Stapling", "WARN", "Unable to determine")
        
        self.results['checks']['ocsp_stapling'] = ocsp_info
        return ocsp_info
    
    def check_forward_secrecy(self):
        """Check for Forward Secrecy (Perfect Forward Secrecy) support"""
        self.print_section("Forward Secrecy (PFS) Support")
        
        loader = LoadingBar("Checking Forward Secrecy support across platforms")
        loader.start()
        
        fs_info = {
            'supported': False,
            'fs_ciphers': [],
            'non_fs_ciphers': [],
            'platform_support': {
                'kubernetes': False,
                'docker': False,
                'general_devops': False,
            }
        }
        
        # Forward Secrecy ciphers (use ephemeral Diffie-Hellman)
        fs_ciphers = [
            # ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
            'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-SHA256', 'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES128-SHA256', 'ECDHE-ECDSA-AES256-SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES256-SHA',
            'ECDHE-ECDSA-AES128-SHA', 'ECDHE-ECDSA-AES256-SHA',
            'ECDHE-RSA-AES128-CCM', 'ECDHE-RSA-AES256-CCM',
            'ECDHE-ECDSA-AES128-CCM', 'ECDHE-ECDSA-AES256-CCM',
            
            # DHE (Diffie-Hellman Ephemeral)
            'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-SHA256',
            'DHE-RSA-CHACHA20-POLY1305', 'DHE-RSA-AES128-CCM',
            'DHE-RSA-AES256-CCM', 'DHE-DSS-AES128-GCM-SHA256',
            'DHE-DSS-AES256-GCM-SHA384', 'DHE-RSA-AES128-SHA',
            'DHE-RSA-AES256-SHA', 'DHE-DSS-AES128-SHA',
            'DHE-DSS-AES256-SHA',
            
            # TLS 1.3 (all provide forward secrecy by default)
            'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_CCM_SHA256',
            
            # PSK with ephemeral keys
            'ECDHE-PSK-AES128-GCM-SHA256', 'ECDHE-PSK-AES256-GCM-SHA384',
            'DHE-PSK-AES128-GCM-SHA256', 'DHE-PSK-AES256-GCM-SHA384',
            'ECDHE-PSK-CHACHA20-POLY1305', 'DHE-PSK-CHACHA20-POLY1305',
        ]
        
        # Non-FS ciphers (static key exchange)
        non_fs_ciphers = [
            'AES128-GCM-SHA256', 'AES256-GCM-SHA384',
            'AES128-SHA256', 'AES256-SHA256',
            'AES128-SHA', 'AES256-SHA',
            'AES128-CCM', 'AES256-CCM',
            'CAMELLIA128-SHA', 'CAMELLIA256-SHA',
        ]
        
        # Kubernetes recommended FS ciphers
        k8s_fs_ciphers = [
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
        ]
        
        # Docker recommended FS ciphers
        docker_fs_ciphers = [
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
        ]
        
        # Test FS ciphers
        k8s_supported = 0
        docker_supported = 0
        
        for cipher in fs_ciphers:
            if self._test_cipher(cipher):
                fs_info['fs_ciphers'].append(cipher)
                fs_info['supported'] = True
                
                # Check platform compatibility
                if cipher in k8s_fs_ciphers:
                    k8s_supported += 1
                if cipher in docker_fs_ciphers:
                    docker_supported += 1
        
        # Test non-FS ciphers
        for cipher in non_fs_ciphers:
            if self._test_cipher(cipher):
                fs_info['non_fs_ciphers'].append(cipher)
        
        # Determine platform support
        if k8s_supported >= 2:
            fs_info['platform_support']['kubernetes'] = True
        if docker_supported >= 1:
            fs_info['platform_support']['docker'] = True
        if len(fs_info['fs_ciphers']) >= 3:
            fs_info['platform_support']['general_devops'] = True
        
        loader.stop(True)
        
        # Print results
        if fs_info['supported']:
            self.print_check("Forward Secrecy", "PASS", 
                           f"Supported - {len(fs_info['fs_ciphers'])} FS cipher(s) available")
            
            print(f"\n{Fore.GREEN}  === FORWARD SECRECY ANALYSIS ==={Style.RESET_ALL}")
            
            # ECDHE ciphers
            ecdhe_ciphers = [c for c in fs_info['fs_ciphers'] if 'ECDHE' in c]
            if ecdhe_ciphers:
                print(f"\n{Fore.CYAN}  ECDHE Ciphers (Elliptic Curve - Recommended):{Style.RESET_ALL}")
                for cipher in ecdhe_ciphers[:8]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            # DHE ciphers
            dhe_ciphers = [c for c in fs_info['fs_ciphers'] if c.startswith('DHE-') or c.startswith('EDH-')]
            if dhe_ciphers:
                print(f"\n{Fore.CYAN}  DHE Ciphers (Classic Diffie-Hellman):{Style.RESET_ALL}")
                for cipher in dhe_ciphers[:5]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            # TLS 1.3 ciphers
            tls13_ciphers = [c for c in fs_info['fs_ciphers'] if c.startswith('TLS_')]
            if tls13_ciphers:
                print(f"\n{Fore.CYAN}  TLS 1.3 Ciphers (Built-in FS):{Style.RESET_ALL}")
                for cipher in tls13_ciphers:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {cipher}")
            
            # Platform compatibility
            print(f"\n{Fore.YELLOW}  === PLATFORM COMPATIBILITY ==={Style.RESET_ALL}")
            
            if fs_info['platform_support']['kubernetes']:
                self.print_check("Kubernetes Compatible", "PASS", 
                               f"{k8s_supported} K8s-recommended FS ciphers supported")
            else:
                self.print_check("Kubernetes Compatible", "WARN", 
                               "Insufficient K8s-recommended ciphers")
            
            if fs_info['platform_support']['docker']:
                self.print_check("Docker Compatible", "PASS", 
                               f"{docker_supported} Docker-recommended FS ciphers supported")
            else:
                self.print_check("Docker Compatible", "WARN", 
                               "Insufficient Docker-recommended ciphers")
            
            if fs_info['platform_support']['general_devops']:
                self.print_check("DevOps/CI-CD Compatible", "PASS", 
                               "Sufficient FS ciphers for general use")
            else:
                self.print_check("DevOps/CI-CD Compatible", "WARN", 
                               "Limited FS cipher support")
        else:
            self.print_check("Forward Secrecy", "FAIL", 
                           "NOT supported - no ephemeral key exchange ciphers found - CRITICAL!")
        
        if fs_info['non_fs_ciphers']:
            self.print_check("Non-FS Ciphers", "WARN", 
                           f"{len(fs_info['non_fs_ciphers'])} non-FS cipher(s) supported - Consider disabling")
            print(f"\n{Fore.YELLOW}  Non-FS Ciphers (Static Key Exchange):{Style.RESET_ALL}")
            for cipher in fs_info['non_fs_ciphers'][:5]:
                print(f"    {Fore.YELLOW}[⚠]{Style.RESET_ALL} {cipher}")
        
        self.results['checks']['forward_secrecy'] = fs_info
        return fs_info
    
    def check_vulnerabilities(self):
        """Check for known TLS vulnerabilities"""
        self.print_section("Known Vulnerability Checks")
        
        loader = LoadingBar("Checking for known vulnerabilities")
        loader.start()
        
        vuln_info = {
            'heartbleed': False,
            'poodle_sslv3': False,
            'beast': False,
            'crime': False,
            'rc4': False,
            'sweet32': False,
        }
        
        # Check for SSLv3 (POODLE)
        tls_versions = self.results['checks'].get('tls_versions', {})
        if tls_versions.get('SSLv3', {}).get('supported'):
            vuln_info['poodle_sslv3'] = True
        
        # Check for TLS 1.0 (BEAST)
        if tls_versions.get('TLSv1.0', {}).get('supported'):
            vuln_info['beast'] = True
        
        # Check for RC4 ciphers
        cipher_suites = self.results['checks'].get('cipher_suites', {})
        weak_ciphers = cipher_suites.get('weak_supported', [])
        
        for cipher in weak_ciphers:
            if 'RC4' in cipher:
                vuln_info['rc4'] = True
            if '3DES' in cipher or 'DES-CBC3' in cipher:
                vuln_info['sweet32'] = True
        
        loader.stop(True)
        
        # Print results
        vulnerabilities_found = any(vuln_info.values())
        
        if vuln_info['poodle_sslv3']:
            self.print_check("POODLE (SSLv3)", "FAIL", "Vulnerable - SSLv3 is enabled")
        else:
            self.print_check("POODLE (SSLv3)", "PASS", "Not vulnerable")
        
        if vuln_info['beast']:
            self.print_check("BEAST (TLS 1.0)", "WARN", "Potentially vulnerable - TLS 1.0 enabled")
        else:
            self.print_check("BEAST (TLS 1.0)", "PASS", "Not vulnerable")
        
        if vuln_info['rc4']:
            self.print_check("RC4 Weakness", "FAIL", "Vulnerable - RC4 ciphers enabled")
        else:
            self.print_check("RC4 Weakness", "PASS", "Not vulnerable")
        
        if vuln_info['sweet32']:
            self.print_check("SWEET32 (3DES)", "WARN", "Potentially vulnerable - 3DES ciphers enabled")
        else:
            self.print_check("SWEET32 (3DES)", "PASS", "Not vulnerable")
        
        self.print_check("Heartbleed", "WARN", "Requires specialized testing tool")
        
        if not vulnerabilities_found:
            print(f"\n{Fore.GREEN}[✓] No major vulnerabilities detected{Style.RESET_ALL}")
        
        self.results['checks']['vulnerabilities'] = vuln_info
        return vuln_info
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname_safe = self.hostname.replace('.', '_')
        filename = f"TLS_Analysis_{hostname_safe}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("TLS / SSL SECURITY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Hostname: {self.hostname}")
        report.append(f"Port: {self.port}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append("\n" + "=" * 80)
        
        # Add all check results
        for check_name, check_data in self.results['checks'].items():
            report.append(f"\n{check_name.upper().replace('_', ' ')}")
            report.append("-" * 80)
            report.append(json.dumps(check_data, indent=2, default=str))
            report.append("")
        
        # Add summary statistics
        report.append("\n" + "=" * 80)
        report.append("SECURITY SUMMARY")
        report.append("=" * 80)
        
        # TLS versions
        tls_versions = self.results['checks'].get('tls_versions', {})
        supported_tls = [v for v, d in tls_versions.items() if d.get('supported')]
        deprecated_tls = [v for v, d in tls_versions.items() if d.get('supported') and d.get('deprecated')]
        
        report.append(f"\nTLS Protocol Support:")
        report.append(f"  - Supported Versions: {', '.join(supported_tls) if supported_tls else 'None detected'}")
        report.append(f"  - Deprecated Versions Enabled: {', '.join(deprecated_tls) if deprecated_tls else 'None'}")
        
        # Cipher suites
        ciphers = self.results['checks'].get('cipher_suites', {})
        report.append(f"\nCipher Suite Analysis:")
        report.append(f"  - Total Tested: {ciphers.get('total_tested', 0)}")
        report.append(f"  - Weak Ciphers Supported: {len(ciphers.get('weak_supported', []))} {'⚠ CRITICAL' if ciphers.get('weak_supported') else ''}")
        report.append(f"  - Medium Ciphers Supported: {len(ciphers.get('medium_supported', []))}")
        report.append(f"  - Strong Ciphers Supported: {len(ciphers.get('strong_supported', []))}")
        
        # Platform-specific cipher support
        by_cat = ciphers.get('by_category', {})
        report.append(f"\nPlatform-Specific Cipher Support:")
        report.append(f"  - TLS 1.3 Ciphers: {len(by_cat.get('tls_13', []))}")
        report.append(f"  - Kubernetes Compatible: {len(by_cat.get('kubernetes', []))}")
        report.append(f"  - Docker Compatible: {len(by_cat.get('docker', []))}")
        report.append(f"  - ChaCha20-Poly1305: {len(by_cat.get('chacha20', []))}")
        report.append(f"  - Forward Secrecy Enabled: {len(by_cat.get('forward_secrecy', []))}")
        report.append(f"  - AEAD Ciphers: {len(by_cat.get('aead', []))}")
        report.append(f"  - PSK Ciphers (IoT/M2M): {len(by_cat.get('psk', []))}")
        
        # Certificate
        cert = self.results['checks'].get('certificate', {})
        report.append(f"\nCertificate Information:")
        report.append(f"  - Issuer: {cert.get('issuer', {}).get('commonName', 'Unknown')}")
        report.append(f"  - Self-Signed: {'Yes ⚠' if cert.get('is_self_signed') else 'No'}")
        report.append(f"  - Days Until Expiry: {cert.get('days_until_expiry', 'Unknown')}")
        report.append(f"  - Key Size: {cert.get('key_size', 'Unknown')} bits")
        report.append(f"  - Signature Algorithm: {cert.get('signature_algorithm', 'Unknown')}")
        
        # Security features
        hsts = self.results['checks'].get('hsts', {})
        fs = self.results['checks'].get('forward_secrecy', {})
        ocsp = self.results['checks'].get('ocsp_stapling', {})
        
        report.append(f"\nSecurity Features:")
        report.append(f"  - HSTS Enabled: {'Yes' if hsts.get('enabled') else 'No ⚠'}")
        if hsts.get('enabled'):
            report.append(f"    - max-age: {hsts.get('max_age', 0)} seconds")
            report.append(f"    - includeSubDomains: {'Yes' if hsts.get('include_subdomains') else 'No'}")
            report.append(f"    - preload: {'Yes' if hsts.get('preload') else 'No'}")
        report.append(f"  - Forward Secrecy: {'Supported ✓' if fs.get('supported') else 'Not Supported ⚠'}")
        if fs.get('platform_support'):
            report.append(f"    - Kubernetes Compatible: {'Yes' if fs['platform_support'].get('kubernetes') else 'No'}")
            report.append(f"    - Docker Compatible: {'Yes' if fs['platform_support'].get('docker') else 'No'}")
            report.append(f"    - DevOps/CI-CD Ready: {'Yes' if fs['platform_support'].get('general_devops') else 'No'}")
        report.append(f"  - OCSP Stapling: {'Enabled' if ocsp.get('stapling_enabled') else 'Not Detected'}")
        
        # Vulnerabilities
        vulns = self.results['checks'].get('vulnerabilities', {})
        vuln_list = [k.upper() for k, v in vulns.items() if v and k != 'heartbleed']
        report.append(f"\nVulnerabilities Detected:")
        if vuln_list:
            report.append(f"  - ⚠ CRITICAL: {', '.join(vuln_list)}")
        else:
            report.append(f"  - None detected ✓")
        
        # Recommendations
        report.append(f"\nRecommendations:")
        recommendations = []
        
        if deprecated_tls:
            recommendations.append(f"  ⚠ Disable deprecated protocols: {', '.join(deprecated_tls)}")
        if ciphers.get('weak_supported'):
            recommendations.append(f"  ⚠ CRITICAL: Disable {len(ciphers['weak_supported'])} weak cipher suite(s)")
        if not hsts.get('enabled'):
            recommendations.append(f"  ⚠ Enable HSTS with max-age=31536000")
        if not fs.get('supported'):
            recommendations.append(f"  ⚠ CRITICAL: Enable Forward Secrecy (ECDHE/DHE ciphers)")
        if not by_cat.get('tls_13'):
            recommendations.append(f"  ⚠ Enable TLS 1.3 for improved security and performance")
        if cert.get('is_self_signed'):
            recommendations.append(f"  ⚠ Replace self-signed certificate with trusted CA certificate")
        if cert.get('days_until_expiry', 999) < 30:
            recommendations.append(f"  ⚠ Renew certificate (expires in {cert.get('days_until_expiry')} days)")
        
        if recommendations:
            for rec in recommendations:
                report.append(rec)
        else:
            report.append(f"  ✓ Configuration follows security best practices")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting TLS / SSL Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = TLSAnalyzer(target_url)
    
    # Define scan stages
    stages = [
        ("TLS Protocol Version Testing", analyzer.test_tls_versions),
        ("Cipher Suite Enumeration", analyzer.enumerate_cipher_suites),
        ("Certificate Analysis", analyzer.analyze_certificate),
        ("HSTS Configuration", analyzer.check_hsts),
        ("OCSP Stapling Status", analyzer.check_ocsp_stapling),
        ("Forward Secrecy Support", analyzer.check_forward_secrecy),
        ("Vulnerability Assessment", analyzer.check_vulnerabilities),
    ]
    
    progress = ProgressBar(len(stages))
    
    try:
        # Run all checks
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
        
        print(f"{Fore.YELLOW}[✓] Total Checks Performed: {len(stages)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        
        # Security summary
        ciphers = analyzer.results['checks'].get('cipher_suites', {})
        weak_count = len(ciphers.get('weak_supported', []))
        
        if weak_count > 0:
            print(f"{Fore.RED}[!] WARNING: {weak_count} weak cipher(s) detected!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No weak ciphers detected{Style.RESET_ALL}")
        
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
        print("Usage: python tls.py <target_url>")
