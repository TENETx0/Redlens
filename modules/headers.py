#!/usr/bin/env python3
"""
HTTP Security Header Analysis Module
Performs comprehensive analysis of HTTP security headers including CSP, HSTS, CORS,
and modern cloud-native/DevOps/DevSecOps security practices.
"""

import requests
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, Back
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
import hashlib
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

class HTTPSecurityHeaderAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'checks': {},
            'security_score': 0,
            'total_possible_score': 0
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Comprehensive security headers list (100+ headers)
        self.security_headers = {
            # Transport Security
            'Strict-Transport-Security': {
                'category': 'Transport Security',
                'severity': 'CRITICAL',
                'score': 15,
                'description': 'Enforces HTTPS connections'
            },
            'Expect-CT': {
                'category': 'Transport Security',
                'severity': 'HIGH',
                'score': 5,
                'description': 'Certificate Transparency enforcement'
            },
            'Public-Key-Pins': {
                'category': 'Transport Security',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Public Key Pinning (deprecated but still used)'
            },
            'Public-Key-Pins-Report-Only': {
                'category': 'Transport Security',
                'severity': 'LOW',
                'score': 2,
                'description': 'HPKP in report-only mode'
            },
            
            # Content Security
            'Content-Security-Policy': {
                'category': 'Content Security',
                'severity': 'CRITICAL',
                'score': 15,
                'description': 'Controls resource loading and XSS prevention'
            },
            'Content-Security-Policy-Report-Only': {
                'category': 'Content Security',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'CSP in monitoring mode'
            },
            'X-Content-Type-Options': {
                'category': 'Content Security',
                'severity': 'HIGH',
                'score': 8,
                'description': 'Prevents MIME-type sniffing'
            },
            'X-Frame-Options': {
                'category': 'Content Security',
                'severity': 'HIGH',
                'score': 8,
                'description': 'Clickjacking protection'
            },
            
            # Browser Security Features
            'X-XSS-Protection': {
                'category': 'Browser Security',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Legacy XSS filter (deprecated but still useful)'
            },
            'X-DNS-Prefetch-Control': {
                'category': 'Browser Security',
                'severity': 'LOW',
                'score': 2,
                'description': 'Controls DNS prefetching'
            },
            'X-WebKit-CSP': {
                'category': 'Browser Security',
                'severity': 'LOW',
                'score': 2,
                'description': 'Legacy WebKit CSP header'
            },
            'X-Content-Security-Policy': {
                'category': 'Browser Security',
                'severity': 'LOW',
                'score': 2,
                'description': 'Legacy Firefox CSP header'
            },
            'X-Download-Options': {
                'category': 'Browser Security',
                'severity': 'LOW',
                'score': 2,
                'description': 'IE8+ download behavior control'
            },
            'X-Permitted-Cross-Domain-Policies': {
                'category': 'Browser Security',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'Adobe Flash/PDF cross-domain policy'
            },
            'X-UA-Compatible': {
                'category': 'Browser Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'IE compatibility mode control'
            },
            
            # Security & Attack Prevention
            'X-Attack-Mitigation': {
                'category': 'Attack Prevention',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'Custom attack mitigation header'
            },
            'X-Content-Options': {
                'category': 'Attack Prevention',
                'severity': 'LOW',
                'score': 2,
                'description': 'Additional content security options'
            },
            'X-Robots-Tag': {
                'category': 'SEO/Privacy',
                'severity': 'LOW',
                'score': 1,
                'description': 'Search engine indexing directives'
            },
            'X-Recruiting': {
                'category': 'Information',
                'severity': 'INFO',
                'score': 0,
                'description': 'Recruiting/hiring message'
            },
            
            # Privacy & Referrer Control
            'Referrer-Policy': {
                'category': 'Privacy',
                'severity': 'MEDIUM',
                'score': 6,
                'description': 'Controls referrer information leakage'
            },
            
            # Permissions & Feature Policy
            'Permissions-Policy': {
                'category': 'Permissions',
                'severity': 'HIGH',
                'score': 7,
                'description': 'Controls browser features and APIs'
            },
            'Feature-Policy': {
                'category': 'Permissions',
                'severity': 'MEDIUM',
                'score': 5,
                'description': 'Legacy feature policy (replaced by Permissions-Policy)'
            },
            
            # Caching & Storage
            'Cache-Control': {
                'category': 'Caching',
                'severity': 'MEDIUM',
                'score': 5,
                'description': 'HTTP caching directives'
            },
            'Pragma': {
                'category': 'Caching',
                'severity': 'LOW',
                'score': 2,
                'description': 'Legacy cache control'
            },
            'Clear-Site-Data': {
                'category': 'Privacy',
                'severity': 'LOW',
                'score': 2,
                'description': 'Clears browser data on logout'
            },
            
            # CORS
            'Access-Control-Allow-Origin': {
                'category': 'CORS',
                'severity': 'HIGH',
                'score': 8,
                'description': 'Cross-Origin Resource Sharing control'
            },
            'Access-Control-Allow-Credentials': {
                'category': 'CORS',
                'severity': 'HIGH',
                'score': 5,
                'description': 'Allows credentials in CORS requests'
            },
            'Access-Control-Allow-Methods': {
                'category': 'CORS',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'Allowed HTTP methods for CORS'
            },
            'Access-Control-Allow-Headers': {
                'category': 'CORS',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'Allowed headers for CORS'
            },
            'Access-Control-Expose-Headers': {
                'category': 'CORS',
                'severity': 'LOW',
                'score': 2,
                'description': 'Headers exposed to client in CORS'
            },
            'Access-Control-Max-Age': {
                'category': 'CORS',
                'severity': 'LOW',
                'score': 2,
                'description': 'CORS preflight cache duration'
            },
            'Cross-Origin-Embedder-Policy': {
                'category': 'CORS',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Cross-origin isolation enforcement'
            },
            'Cross-Origin-Opener-Policy': {
                'category': 'CORS',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Cross-origin window opening policy'
            },
            'Cross-Origin-Resource-Policy': {
                'category': 'CORS',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Cross-origin resource loading policy'
            },
            
            # Information Disclosure
            'Server': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -5,  # Negative score if present with version info
                'description': 'Server software identification'
            },
            'X-Powered-By': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -5,  # Negative score if present
                'description': 'Technology stack disclosure'
            },
            'X-Generator': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -4,
                'description': 'CMS/Framework generator disclosure'
            },
            'X-Powered-CMS': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -4,
                'description': 'CMS platform disclosure'
            },
            'X-Runtime': {
                'category': 'Information Disclosure',
                'severity': 'LOW',
                'score': -2,
                'description': 'Runtime/execution time disclosure'
            },
            'X-Turbo-Charged-By': {
                'category': 'Information Disclosure',
                'severity': 'LOW',
                'score': -2,
                'description': 'Technology accelerator disclosure'
            },
            'X-Redirect-By': {
                'category': 'Information Disclosure',
                'severity': 'LOW',
                'score': -1,
                'description': 'Redirect mechanism disclosure'
            },
            'X-Pingback': {
                'category': 'Information Disclosure',
                'severity': 'LOW',
                'score': -1,
                'description': 'XML-RPC pingback endpoint'
            },
            'Link': {
                'category': 'Information Disclosure',
                'severity': 'LOW',
                'score': 0,
                'description': 'REST API and resource links'
            },
            
            # WAF Headers
            'X-WAF': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Generic WAF detection'
            },
            'X-WAF-Event-ID': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'WAF event identifier'
            },
            'X-Sucuri-ID': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Sucuri WAF identifier'
            },
            'X-Sucuri-Cache': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Sucuri cache status'
            },
            'X-Mod-Security': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'ModSecurity WAF'
            },
            'X-NAXSI-SIG': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'NAXSI WAF signature'
            },
            'X-DataDome': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'DataDome bot protection'
            },
            'X-DataDome-CID': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'DataDome client ID'
            },
            'X-Distil-CS': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Distil Networks protection'
            },
            'X-Protected-By': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Protection service identifier'
            },
            'X-Security': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Security service header'
            },
            'X-Fw-Hash': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Firewall hash'
            },
            'X-BotDetect-ChallengeId': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Bot detection challenge'
            },
            'X-Reblaze': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Reblaze WAF'
            },
            'X-SL-COMP': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'SafeLine WAF'
            },
            'X-Shield': {
                'category': 'WAF',
                'severity': 'INFO',
                'score': 0,
                'description': 'Shield protection service'
            },
            
            # CDN Headers
            'CF-RAY': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Cloudflare ray ID'
            },
            'CF-Cache-Status': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Cloudflare cache status'
            },
            'CF-Request-ID': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Cloudflare request ID'
            },
            'X-CDN': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Generic CDN identifier'
            },
            'X-Cache': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Cache service status'
            },
            'X-Cache-Hits': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Number of cache hits'
            },
            'X-Served-By': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'CDN server identifier'
            },
            'Via': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Proxy/CDN chain'
            },
            'X-Fastly-Request-ID': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Fastly CDN request ID'
            },
            'X-Akamai-Transformed': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Akamai transformation'
            },
            'X-Edge-Location': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'CDN edge location'
            },
            'X-CDN-Pop': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'CDN point of presence'
            },
            'X-Varnish': {
                'category': 'CDN',
                'severity': 'INFO',
                'score': 0,
                'description': 'Varnish cache identifier'
            },
            
            # Debugging & Development Headers
            'X-Debug': {
                'category': 'Debugging',
                'severity': 'HIGH',
                'score': -10,
                'description': 'Debug mode enabled'
            },
            'X-Debug-Token': {
                'category': 'Debugging',
                'severity': 'HIGH',
                'score': -8,
                'description': 'Symfony debug token'
            },
            'X-Debug-Token-Link': {
                'category': 'Debugging',
                'severity': 'HIGH',
                'score': -8,
                'description': 'Symfony profiler link'
            },
            'X-Symfony-Cache': {
                'category': 'Debugging',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'Symfony cache information'
            },
            'X-Drupal-Cache': {
                'category': 'Debugging',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'Drupal cache status'
            },
            'X-Drupal-Dynamic-Cache': {
                'category': 'Debugging',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'Drupal dynamic cache'
            },
            'X-Application-Context': {
                'category': 'Debugging',
                'severity': 'MEDIUM',
                'score': -4,
                'description': 'Spring Boot application context'
            },
            'X-Sourcemap': {
                'category': 'Debugging',
                'severity': 'MEDIUM',
                'score': -5,
                'description': 'Source map location (exposes source code)'
            },
            
            # Monitoring & Observability
            'X-Request-ID': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Request correlation ID'
            },
            'X-Correlation-ID': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Request correlation tracking'
            },
            'X-Trace-ID': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Distributed trace ID'
            },
            'X-Span-ID': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Trace span identifier'
            },
            'X-Parent-Span-ID': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Parent span identifier'
            },
            'X-B3-TraceId': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Zipkin B3 trace ID'
            },
            'X-B3-SpanId': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Zipkin B3 span ID'
            },
            'X-B3-ParentSpanId': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Zipkin B3 parent span'
            },
            'X-B3-Sampled': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Zipkin sampling decision'
            },
            'X-B3-Flags': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Zipkin B3 flags'
            },
            'Traceparent': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'W3C trace context parent'
            },
            'Tracestate': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'W3C trace state'
            },
            'X-Amzn-Trace-Id': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'AWS X-Ray trace ID'
            },
            'X-Cloud-Trace-Context': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Google Cloud trace context'
            },
            'Server-Timing': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Server performance metrics'
            },
            'X-Response-Time': {
                'category': 'Monitoring',
                'severity': 'INFO',
                'score': 0,
                'description': 'Response time in milliseconds'
            },
            'X-DNS-Prefetch-Control': {
                'category': 'Performance',
                'severity': 'LOW',
                'score': 1,
                'description': 'DNS prefetch optimization'
            },
            'X-AspNet-Version': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'ASP.NET version disclosure'
            },
            'X-AspNetMvc-Version': {
                'category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'ASP.NET MVC version disclosure'
            },
            
            # Cloud & DevOps Headers
            'X-Cloud-Trace-Context': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Google Cloud trace context'
            },
            'X-Amz-Cf-Id': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Amazon CloudFront identifier'
            },
            'X-Azure-Ref': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Azure CDN reference'
            },
            'X-Vercel-Id': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Vercel deployment identifier'
            },
            'X-Vercel-Cache': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Vercel cache status'
            },
            'X-Netlify-Id': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'Netlify deployment identifier'
            },
            'X-GitHub-Request-Id': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'GitHub request tracking'
            },
            'X-Gitlab-Request-Id': {
                'category': 'Cloud/DevOps',
                'severity': 'INFO',
                'score': 0,
                'description': 'GitLab request tracking'
            },
            
            # Kubernetes & Container Headers
            'X-Kong-Upstream-Latency': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kong API Gateway latency'
            },
            'X-Kong-Proxy-Latency': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kong proxy latency'
            },
            'X-Kong-Request-Id': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kong request identifier'
            },
            'X-Envoy-Upstream-Service-Time': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Envoy proxy service time'
            },
            'X-Envoy-Decorator-Operation': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Envoy operation decorator'
            },
            'X-Envoy-Expected-Rq-Timeout-Ms': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Envoy request timeout'
            },
            'X-Envoy-Original-Path': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Envoy original request path'
            },
            'X-Istio-Attributes': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Istio service mesh attributes'
            },
            'X-Linkerd-Id': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Linkerd service mesh ID'
            },
            'X-Consul-Service': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Consul service discovery'
            },
            'X-Nomad-Job': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Nomad job identifier'
            },
            'X-Kubernetes-Service': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kubernetes service name'
            },
            'X-Kubernetes-Namespace': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kubernetes namespace'
            },
            'X-Pod-Name': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Kubernetes pod name'
            },
            'X-Container-Id': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Container identifier'
            },
            'X-Docker-Container': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Docker container ID'
            },
            'X-Traefik-Request-Id': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'Traefik proxy request ID'
            },
            'X-HAProxy-Server': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'HAProxy backend server'
            },
            'X-Nginx-Plus': {
                'category': 'Kubernetes/Container',
                'severity': 'INFO',
                'score': 0,
                'description': 'NGINX Plus identifier'
            },
            
            # API Gateway Headers
            'X-Apigee-Message-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'Apigee message identifier'
            },
            'X-Gateway-Request-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'API Gateway request ID'
            },
            'X-Amazon-ApiGateway-Api-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'AWS API Gateway ID'
            },
            'X-Tyk-Request-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'Tyk Gateway request ID'
            },
            'X-Mashery-Message-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'Mashery API Gateway message ID'
            },
            'X-3Scale-Request-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': '3Scale API Gateway request ID'
            },
            'X-Mulesoft-Request-Id': {
                'category': 'API Gateway',
                'severity': 'INFO',
                'score': 0,
                'description': 'MuleSoft request identifier'
            },
            
            # Rate Limiting & Quotas
            'X-RateLimit-Limit': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'API rate limit maximum'
            },
            'X-RateLimit-Remaining': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'API rate limit remaining'
            },
            'X-RateLimit-Reset': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'API rate limit reset time'
            },
            'X-Rate-Limit-Window': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Rate limit time window'
            },
            'X-RateLimit-Policy': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Rate limiting policy'
            },
            'RateLimit': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Standardized rate limit header'
            },
            'RateLimit-Limit': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Rate limit quota'
            },
            'RateLimit-Remaining': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Remaining quota'
            },
            'RateLimit-Reset': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Quota reset timestamp'
            },
            'Retry-After': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Retry delay for rate limited requests'
            },
            'X-Quota-Limit': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'API quota limit'
            },
            'X-Quota-Remaining': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'API quota remaining'
            },
            'X-Throttle-Limit': {
                'category': 'Rate Limiting',
                'severity': 'INFO',
                'score': 0,
                'description': 'Throttle limit'
            },
            
            # Load Balancing
            'X-Backend-Server': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Backend server identifier'
            },
            'X-Server-ID': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Server instance ID'
            },
            'X-Node-ID': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Node identifier in cluster'
            },
            'X-LB-ID': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Load balancer ID'
            },
            'X-Upstream-Addr': {
                'category': 'Load Balancing',
                'severity': 'MEDIUM',
                'score': -3,
                'description': 'Upstream server address (info disclosure)'
            },
            'X-Upstream-Status': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Upstream server status'
            },
            'X-Upstream-Response-Time': {
                'category': 'Load Balancing',
                'severity': 'INFO',
                'score': 0,
                'description': 'Upstream response time'
            },
            
            # Modern Security Headers
            'Origin-Agent-Cluster': {
                'category': 'Modern Security',
                'severity': 'MEDIUM',
                'score': 3,
                'description': 'Origin-keyed agent clustering'
            },
            'Accept-CH': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Client Hints acceptance'
            },
            'Accept-CH-Lifetime': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Client Hints persistence'
            },
            'Critical-CH': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Critical Client Hints'
            },
            'Observe-Browsing-Topics': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 0,
                'description': 'Topics API observation'
            },
            'Supports-Loading-Mode': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Loading mode support'
            },
            'Timing-Allow-Origin': {
                'category': 'Modern Security',
                'severity': 'MEDIUM',
                'score': 2,
                'description': 'Resource timing API access control'
            },
            'X-Robots-Tag': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Search engine directives'
            },
            'Sec-CH-UA': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'User agent client hint'
            },
            'Sec-CH-UA-Mobile': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Mobile client hint'
            },
            'Sec-CH-UA-Platform': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Platform client hint'
            },
            'Sec-Fetch-Site': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Fetch metadata site'
            },
            'Sec-Fetch-Mode': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Fetch metadata mode'
            },
            'Sec-Fetch-Dest': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Fetch metadata destination'
            },
            'Sec-Fetch-User': {
                'category': 'Modern Security',
                'severity': 'INFO',
                'score': 0,
                'description': 'Fetch metadata user activation'
            },
            'Sec-GPC': {
                'category': 'Modern Security',
                'severity': 'LOW',
                'score': 1,
                'description': 'Global Privacy Control'
            },
            
            # Security Monitoring
            'Report-To': {
                'category': 'Security Monitoring',
                'severity': 'MEDIUM',
                'score': 4,
                'description': 'Endpoint for security reports'
            },
            'NEL': {
                'category': 'Security Monitoring',
                'severity': 'LOW',
                'score': 2,
                'description': 'Network Error Logging'
            },
        }
        
        # CSP Directives - Comprehensive list
        self.csp_directives = {
            # Fetch Directives
            'default-src': 'Default source for all resource types',
            'script-src': 'Valid sources for JavaScript',
            'script-src-elem': 'Valid sources for <script> elements',
            'script-src-attr': 'Valid sources for inline event handlers',
            'style-src': 'Valid sources for stylesheets',
            'style-src-elem': 'Valid sources for <style> elements',
            'style-src-attr': 'Valid sources for inline styles',
            'img-src': 'Valid sources for images',
            'font-src': 'Valid sources for fonts',
            'connect-src': 'Valid sources for fetch, XHR, WebSocket, EventSource',
            'media-src': 'Valid sources for <audio> and <video>',
            'object-src': 'Valid sources for <object>, <embed>, <applet>',
            'frame-src': 'Valid sources for nested browsing contexts (iframes)',
            'child-src': 'Valid sources for web workers and nested contexts',
            'worker-src': 'Valid sources for Worker, SharedWorker, ServiceWorker',
            'manifest-src': 'Valid sources for manifest files',
            'prefetch-src': 'Valid sources for prefetch/prerender',
            
            # Document Directives
            'base-uri': 'Valid URLs for <base> element',
            'sandbox': 'Sandbox restrictions (similar to iframe sandbox)',
            
            # Navigation Directives
            'form-action': 'Valid endpoints for form submissions',
            'frame-ancestors': 'Valid parents for embedding (replaces X-Frame-Options)',
            'navigate-to': 'Valid navigation targets',
            
            # Reporting Directives
            'report-uri': 'Deprecated URI for CSP violation reports',
            'report-to': 'Reporting API endpoint for violations',
            
            # Other Directives
            'require-sri-for': 'Require Subresource Integrity for scripts/styles',
            'require-trusted-types-for': 'Require Trusted Types for DOM XSS sinks',
            'trusted-types': 'Control Trusted Types policies',
            'upgrade-insecure-requests': 'Upgrade HTTP to HTTPS automatically',
            'block-all-mixed-content': 'Block mixed content loads',
        }
        
        # CSP Source Values
        self.csp_sources = {
            "'none'": "Disallows all sources",
            "'self'": "Same origin (scheme, host, port)",
            "'unsafe-inline'": "Allows inline resources (DANGEROUS)",
            "'unsafe-eval'": "Allows eval() and similar (DANGEROUS)",
            "'unsafe-hashes'": "Allows specific inline event handlers",
            "'strict-dynamic'": "Allows dynamically loaded scripts from trusted sources",
            "'report-sample'": "Include code sample in violation reports",
            "'nonce-*'": "Cryptographic nonce for inline resources",
            "'sha256-*'": "SHA-256 hash of allowed inline resources",
            "'sha384-*'": "SHA-384 hash of allowed inline resources",
            "'sha512-*'": "SHA-512 hash of allowed inline resources",
            "https:": "Allows any HTTPS resource",
            "http:": "Allows any HTTP resource (INSECURE)",
            "data:": "Allows data: URIs",
            "blob:": "Allows blob: URIs",
            "filesystem:": "Allows filesystem: URIs",
        }
        
        # HSTS preload requirements
        self.hsts_preload_requirements = {
            'max-age': 31536000,  # Minimum 1 year (31536000 seconds)
            'includeSubDomains': True,
            'preload': True
        }
        
        # Referrer Policy values
        self.referrer_policies = {
            'no-referrer': 'Never send referrer',
            'no-referrer-when-downgrade': 'Send referrer only on same security level',
            'origin': 'Send only origin (no path)',
            'origin-when-cross-origin': 'Full URL for same-origin, origin only for cross-origin',
            'same-origin': 'Send referrer only for same-origin requests',
            'strict-origin': 'Send origin only on same security level',
            'strict-origin-when-cross-origin': 'Full URL for same-origin, origin for cross-origin on same security',
            'unsafe-url': 'Always send full URL (INSECURE)'
        }
        
        # Permissions Policy features (formerly Feature-Policy)
        self.permissions_policy_features = {
            # Powerful Features
            'accelerometer': 'Accelerometer sensor',
            'ambient-light-sensor': 'Ambient light sensor',
            'autoplay': 'Autoplay media',
            'battery': 'Battery status API',
            'camera': 'Camera access',
            'display-capture': 'Screen capture',
            'document-domain': 'document.domain modification',
            'encrypted-media': 'Encrypted Media Extensions',
            'execution-while-not-rendered': 'Script execution when not rendered',
            'execution-while-out-of-viewport': 'Script execution outside viewport',
            'fullscreen': 'Fullscreen API',
            'gamepad': 'Gamepad API',
            'geolocation': 'Geolocation API',
            'gyroscope': 'Gyroscope sensor',
            'hid': 'Human Interface Devices API',
            'idle-detection': 'Idle detection',
            'magnetometer': 'Magnetometer sensor',
            'microphone': 'Microphone access',
            'midi': 'Web MIDI API',
            'navigation-override': 'Navigation override',
            'payment': 'Payment Request API',
            'picture-in-picture': 'Picture-in-Picture',
            'publickey-credentials-get': 'WebAuthn get credentials',
            'screen-wake-lock': 'Screen Wake Lock API',
            'serial': 'Web Serial API',
            'speaker-selection': 'Speaker selection',
            'sync-xhr': 'Synchronous XHR',
            'usb': 'WebUSB API',
            'web-share': 'Web Share API',
            'xr-spatial-tracking': 'WebXR spatial tracking',
            
            # Privacy Features
            'attribution-reporting': 'Attribution Reporting API',
            'browsing-topics': 'Topics API (FLoC replacement)',
            'interest-cohort': 'FLoC interest cohort',
            'join-ad-interest-group': 'FLEDGE ad interest groups',
            'run-ad-auction': 'FLEDGE ad auction',
            'conversion-measurement': 'Conversion measurement',
            'focus-without-user-activation': 'Focus without user gesture',
            'vertical-scroll': 'Vertical scrolling',
            'clipboard-read': 'Clipboard read',
            'clipboard-write': 'Clipboard write',
        }
        
        # Cache-Control directives
        self.cache_control_directives = {
            # Request Directives
            'max-age': 'Maximum age in seconds',
            'max-stale': 'Accept stale responses',
            'min-fresh': 'Minimum freshness required',
            'no-cache': 'Revalidate before using cached copy',
            'no-store': 'Do not cache anything',
            'no-transform': 'Do not transform content',
            'only-if-cached': 'Only use cached response',
            
            # Response Directives
            'must-revalidate': 'Must revalidate stale responses',
            'public': 'May be cached by any cache',
            'private': 'Only cacheable by browser',
            'proxy-revalidate': 'Proxy must revalidate',
            's-maxage': 'Max age for shared caches',
            'immutable': 'Response will not change',
            'stale-while-revalidate': 'Serve stale while revalidating',
            'stale-if-error': 'Serve stale on error',
        }
        
        # X-Frame-Options values
        self.frame_options = {
            'DENY': 'Page cannot be displayed in frame',
            'SAMEORIGIN': 'Page can be displayed in frame on same origin',
            'ALLOW-FROM': 'Page can be displayed in frame on specified origin (obsolete)'
        }
        
        # Information disclosure patterns
        self.disclosure_patterns = {
            'version_numbers': r'\d+\.\d+(\.\d+)?',
            'internal_ips': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            'paths': r'[/\\][\w\-/\\]+',
            'technologies': [
                'apache', 'nginx', 'iis', 'tomcat', 'php', 'asp.net', 'express',
                'django', 'flask', 'rails', 'laravel', 'spring', 'node.js'
            ]
        }
        
        # Cloud platform indicators
        self.cloud_indicators = {
            'aws': ['cloudfront', 'amazonaws', 'aws', 'x-amz', 's3'],
            'gcp': ['google', 'gcp', 'cloud.google', 'appengine', 'x-goog'],
            'azure': ['azure', 'microsoft', 'windows.net', 'x-ms', 'x-azure'],
            'cloudflare': ['cloudflare', 'cf-ray', 'cf-cache'],
            'fastly': ['fastly', 'x-fastly'],
            'akamai': ['akamai', 'x-akamai'],
            'vercel': ['vercel', 'x-vercel'],
            'netlify': ['netlify', 'x-nf'],
            'heroku': ['heroku', 'x-heroku'],
            'digitalocean': ['digitalocean', 'x-do'],
        }
        
        # Container/Orchestration indicators
        self.orchestration_indicators = {
            'kubernetes': ['x-envoy', 'x-istio', 'x-b3', 'x-request-id'],
            'docker': ['x-docker', 'docker'],
            'service-mesh': ['x-envoy', 'x-istio', 'x-linkerd'],
            'api-gateway': ['x-kong', 'x-tyk', 'x-apigee', 'x-amazon-apigateway'],
            'load-balancer': ['x-haproxy', 'x-nginx', 'x-traefik'],
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
    
    def analyze_csp(self, csp_header):
        """Analyze Content-Security-Policy in detail"""
        analysis = {
            'present': True,
            'directives': {},
            'issues': [],
            'recommendations': [],
            'security_score': 0
        }
        
        # Parse CSP directives
        directives = [d.strip() for d in csp_header.split(';') if d.strip()]
        
        for directive in directives:
            parts = directive.split()
            if parts:
                directive_name = parts[0]
                sources = parts[1:] if len(parts) > 1 else []
                analysis['directives'][directive_name] = sources
        
        # Check for critical directives
        critical_directives = ['default-src', 'script-src', 'object-src']
        for directive in critical_directives:
            if directive not in analysis['directives']:
                analysis['issues'].append(f"Missing critical directive: {directive}")
            else:
                analysis['security_score'] += 10
        
        # Check for unsafe directives
        unsafe_keywords = ["'unsafe-inline'", "'unsafe-eval'"]
        for directive_name, sources in analysis['directives'].items():
            for source in sources:
                if source in unsafe_keywords:
                    analysis['issues'].append(f"Unsafe source '{source}' in {directive_name}")
                    analysis['security_score'] -= 15
        
        # Check for wildcards
        for directive_name, sources in analysis['directives'].items():
            for source in sources:
                if source == '*':
                    analysis['issues'].append(f"Wildcard (*) used in {directive_name} - too permissive")
                    analysis['security_score'] -= 10
        
        # Check for data: and blob: URIs
        risky_schemes = ['data:', 'blob:']
        for directive_name, sources in analysis['directives'].items():
            for source in sources:
                if source in risky_schemes:
                    analysis['issues'].append(f"Potentially risky scheme '{source}' in {directive_name}")
                    analysis['security_score'] -= 5
        
        # Check for nonces and hashes (good practices)
        has_nonces = any("'nonce-" in str(sources) for sources in analysis['directives'].values())
        has_hashes = any(any("'sha" in s for s in sources) for sources in analysis['directives'].values())
        
        if has_nonces or has_hashes:
            analysis['security_score'] += 20
            analysis['recommendations'].append("Good: Using nonces or hashes for inline scripts")
        
        # Check for strict-dynamic
        has_strict_dynamic = any("'strict-dynamic'" in sources for sources in analysis['directives'].values())
        if has_strict_dynamic:
            analysis['security_score'] += 10
            analysis['recommendations'].append("Good: Using 'strict-dynamic' for script loading")
        
        # Check for upgrade-insecure-requests
        if 'upgrade-insecure-requests' in analysis['directives']:
            analysis['security_score'] += 5
            analysis['recommendations'].append("Good: Upgrading insecure requests to HTTPS")
        
        # Check for frame-ancestors (clickjacking protection)
        if 'frame-ancestors' in analysis['directives']:
            analysis['security_score'] += 10
            frame_ancestors = analysis['directives']['frame-ancestors']
            if frame_ancestors == ["'none'"]:
                analysis['recommendations'].append("Good: Frame embedding completely blocked")
        else:
            analysis['recommendations'].append("Consider adding 'frame-ancestors' directive")
        
        # Recommendations
        if 'default-src' not in analysis['directives']:
            analysis['recommendations'].append("Add 'default-src' as fallback for undefined directives")
        
        if 'object-src' not in analysis['directives']:
            analysis['recommendations'].append("Add 'object-src' to prevent plugin-based attacks")
        
        if 'base-uri' not in analysis['directives']:
            analysis['recommendations'].append("Add 'base-uri' to prevent base tag injection")
        
        # Reporting
        if 'report-uri' not in analysis['directives'] and 'report-to' not in analysis['directives']:
            analysis['recommendations'].append("Add 'report-to' directive for violation monitoring")
        
        return analysis
    
    def analyze_hsts(self, hsts_header):
        """Analyze Strict-Transport-Security header"""
        analysis = {
            'present': True,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'issues': [],
            'recommendations': [],
            'preload_eligible': False,
            'security_score': 0
        }
        
        # Parse directives
        directives = [d.strip() for d in hsts_header.lower().split(';')]
        
        for directive in directives:
            if directive.startswith('max-age='):
                try:
                    analysis['max_age'] = int(directive.split('=')[1])
                except:
                    analysis['issues'].append("Invalid max-age value")
            elif directive == 'includesubdomains':
                analysis['include_subdomains'] = True
            elif directive == 'preload':
                analysis['preload'] = True
        
        # Check max-age
        if analysis['max_age'] is None:
            analysis['issues'].append("Missing max-age directive")
        elif analysis['max_age'] < 31536000:  # Less than 1 year
            analysis['issues'].append(f"max-age ({analysis['max_age']}s) is less than recommended 1 year (31536000s)")
            analysis['security_score'] -= 5
        else:
            analysis['security_score'] += 15
            if analysis['max_age'] >= 63072000:  # 2 years
                analysis['recommendations'].append("Excellent: max-age is 2 years or more")
        
        # Check includeSubDomains
        if analysis['include_subdomains']:
            analysis['security_score'] += 5
        else:
            analysis['recommendations'].append("Consider adding 'includeSubDomains' if all subdomains support HTTPS")
        
        # Check preload eligibility
        if (analysis['max_age'] >= 31536000 and 
            analysis['include_subdomains'] and 
            analysis['preload']):
            analysis['preload_eligible'] = True
            analysis['security_score'] += 10
            analysis['recommendations'].append("Eligible for HSTS preload list: https://hstspreload.org/")
        else:
            missing = []
            if analysis['max_age'] < 31536000:
                missing.append('max-age >= 1 year')
            if not analysis['include_subdomains']:
                missing.append('includeSubDomains')
            if not analysis['preload']:
                missing.append('preload directive')
            if missing:
                analysis['recommendations'].append(f"For HSTS preload, add: {', '.join(missing)}")
        
        return analysis
    
    def analyze_cors(self, headers):
        """Analyze CORS headers for security issues"""
        analysis = {
            'enabled': False,
            'headers': {},
            'issues': [],
            'recommendations': [],
            'security_score': 0
        }
        
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]
        
        for header in cors_headers:
            value = None
            for h, v in headers.items():
                if h.lower() == header.lower():
                    value = v
                    break
            
            if value:
                analysis['headers'][header] = value
                analysis['enabled'] = True
        
        if not analysis['enabled']:
            return analysis
        
        # Check Access-Control-Allow-Origin
        acao = analysis['headers'].get('Access-Control-Allow-Origin', '')
        if acao == '*':
            analysis['issues'].append("CRITICAL: Access-Control-Allow-Origin set to wildcard (*)")
            analysis['security_score'] -= 20
            
            # Check if credentials are also allowed (extremely dangerous)
            acac = analysis['headers'].get('Access-Control-Allow-Credentials', '').lower()
            if acac == 'true':
                analysis['issues'].append("CRITICAL: Wildcard CORS with credentials enabled - MAJOR SECURITY RISK")
                analysis['security_score'] -= 30
        elif acao:
            # Check if origin is validated
            if '://' in acao:
                analysis['security_score'] += 5
                analysis['recommendations'].append("CORS origin appears to be specific - ensure proper validation")
        
        # Check Access-Control-Allow-Credentials
        acac = analysis['headers'].get('Access-Control-Allow-Credentials', '').lower()
        if acac == 'true':
            if acao == '*':
                pass  # Already flagged above
            else:
                analysis['recommendations'].append("Credentials enabled - ensure origin validation is strict")
        
        # Check Access-Control-Allow-Methods
        methods = analysis['headers'].get('Access-Control-Allow-Methods', '')
        if methods:
            dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
            for method in dangerous_methods:
                if method in methods.upper():
                    analysis['issues'].append(f"Potentially dangerous HTTP method allowed: {method}")
                    analysis['security_score'] -= 3
        
        # Check Access-Control-Allow-Headers
        allowed_headers = analysis['headers'].get('Access-Control-Allow-Headers', '')
        if allowed_headers == '*':
            analysis['issues'].append("Wildcard (*) used for allowed headers - overly permissive")
            analysis['security_score'] -= 5
        
        # Check Access-Control-Max-Age
        max_age = analysis['headers'].get('Access-Control-Max-Age', '')
        if max_age:
            try:
                age = int(max_age)
                if age > 86400:  # More than 24 hours
                    analysis['recommendations'].append(f"Long preflight cache ({age}s) - consider if this is intentional")
            except:
                pass
        
        return analysis
    
    def analyze_cache_control(self, headers):
        """Analyze Cache-Control and related caching headers"""
        analysis = {
            'cache_control': None,
            'pragma': None,
            'expires': None,
            'directives': {},
            'issues': [],
            'recommendations': [],
            'sensitive_data_cached': False
        }
        
        # Get Cache-Control header
        for h, v in headers.items():
            if h.lower() == 'cache-control':
                analysis['cache_control'] = v
            elif h.lower() == 'pragma':
                analysis['pragma'] = v
            elif h.lower() == 'expires':
                analysis['expires'] = v
        
        if analysis['cache_control']:
            # Parse directives
            directives = [d.strip() for d in analysis['cache_control'].lower().split(',')]
            for directive in directives:
                if '=' in directive:
                    key, value = directive.split('=', 1)
                    analysis['directives'][key.strip()] = value.strip()
                else:
                    analysis['directives'][directive] = True
            
            # Check for no-store (best for sensitive data)
            if 'no-store' in analysis['directives']:
                analysis['recommendations'].append("Good: 'no-store' prevents caching of sensitive data")
            
            # Check for public with long max-age
            if 'public' in analysis['directives'] and 'max-age' in analysis['directives']:
                try:
                    max_age = int(analysis['directives']['max-age'])
                    if max_age > 31536000:  # More than 1 year
                        analysis['recommendations'].append(f"Very long cache duration: {max_age}s - ensure this is intentional")
                except:
                    pass
            
            # Check for private
            if 'private' in analysis['directives']:
                analysis['recommendations'].append("'private' directive - cached only by browser")
            
            # Check for no-cache
            if 'no-cache' in analysis['directives']:
                analysis['recommendations'].append("'no-cache' - requires revalidation before use")
            
            # Check for immutable
            if 'immutable' in analysis['directives']:
                analysis['recommendations'].append("Good: 'immutable' prevents unnecessary revalidation")
        else:
            analysis['issues'].append("No Cache-Control header found")
        
        # Check Pragma (legacy)
        if analysis['pragma']:
            if 'no-cache' in analysis['pragma'].lower():
                analysis['recommendations'].append("Legacy 'Pragma: no-cache' found - Cache-Control is preferred")
        
        return analysis
    
    def analyze_permissions_policy(self, header):
        """Analyze Permissions-Policy header"""
        analysis = {
            'present': True,
            'policies': {},
            'issues': [],
            'recommendations': [],
            'security_score': 0
        }
        
        # Parse policies
        policies = [p.strip() for p in header.split(',')]
        
        for policy in policies:
            if '=' in policy:
                feature, allowlist = policy.split('=', 1)
                feature = feature.strip()
                allowlist = allowlist.strip()
                analysis['policies'][feature] = allowlist
        
        # Check for dangerous features
        dangerous_features = [
            'camera', 'microphone', 'geolocation', 'payment', 
            'usb', 'serial', 'hid', 'clipboard-read', 'clipboard-write'
        ]
        
        for feature in dangerous_features:
            if feature in analysis['policies']:
                allowlist = analysis['policies'][feature]
                if allowlist == '*' or 'self' not in allowlist:
                    analysis['issues'].append(f"Permissive policy for sensitive feature: {feature}")
                    analysis['security_score'] -= 3
        
        # Check for privacy-invasive features
        privacy_features = ['interest-cohort', 'browsing-topics', 'attribution-reporting']
        for feature in privacy_features:
            if feature in analysis['policies']:
                if analysis['policies'][feature] == '()':
                    analysis['security_score'] += 5
                    analysis['recommendations'].append(f"Good: {feature} disabled for privacy")
        
        # Recommend disabling FLoC/Topics
        if 'interest-cohort' not in analysis['policies']:
            analysis['recommendations'].append("Consider disabling FLoC: interest-cohort=()")
        
        return analysis
    
    def detect_cloud_platform(self, headers):
        """Detect cloud platform and services from headers"""
        detected = {
            'platforms': [],
            'services': [],
            'orchestration': [],
            'details': {}
        }
        
        # Convert all headers to lowercase for matching
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Detect cloud platforms
        for platform, indicators in self.cloud_indicators.items():
            for indicator in indicators:
                for header, value in headers_lower.items():
                    if indicator in header or indicator in value.lower():
                        if platform not in detected['platforms']:
                            detected['platforms'].append(platform)
                            detected['details'][platform] = []
                        detected['details'][platform].append(f"{header}: {value}")
        
        # Detect container/orchestration
        for tech, indicators in self.orchestration_indicators.items():
            for indicator in indicators:
                for header, value in headers_lower.items():
                    if indicator in header:
                        if tech not in detected['orchestration']:
                            detected['orchestration'].append(tech)
        
        return detected
    
    def check_information_disclosure(self, headers):
        """Check for information disclosure in headers"""
        disclosures = {
            'server_info': [],
            'version_leaks': [],
            'path_leaks': [],
            'internal_info': [],
            'severity': 'NONE'
        }
        
        # Check Server header
        server = headers.get('Server', '')
        if server:
            disclosures['server_info'].append(server)
            
            # Check for version numbers
            if re.search(self.disclosure_patterns['version_numbers'], server):
                disclosures['version_leaks'].append(f"Server: {server}")
                disclosures['severity'] = 'MEDIUM'
        
        # Check X-Powered-By
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            disclosures['server_info'].append(f"X-Powered-By: {powered_by}")
            if re.search(self.disclosure_patterns['version_numbers'], powered_by):
                disclosures['version_leaks'].append(f"X-Powered-By: {powered_by}")
                disclosures['severity'] = 'MEDIUM'
        
        # Check for technology-specific headers
        tech_headers = ['X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Drupal-Cache', 
                       'X-Generator', 'X-Powered-CMS']
        for header in tech_headers:
            value = headers.get(header, '')
            if value:
                disclosures['version_leaks'].append(f"{header}: {value}")
                disclosures['severity'] = 'HIGH'
        
        # Check for internal IPs
        for header, value in headers.items():
            internal_ips = re.findall(self.disclosure_patterns['internal_ips'], str(value))
            if internal_ips:
                disclosures['internal_info'].append(f"{header}: {value}")
                disclosures['severity'] = 'HIGH'
        
        # Check for path disclosures
        path_headers = ['X-Debug-Token-Link', 'X-Sourcemap', 'X-Original-Url']
        for header in path_headers:
            value = headers.get(header, '')
            if value:
                disclosures['path_leaks'].append(f"{header}: {value}")
                if disclosures['severity'] == 'NONE':
                    disclosures['severity'] = 'LOW'
        
        return disclosures
    
    def comprehensive_header_scan(self):
        """Perform comprehensive security header analysis with parallel scanning"""
        self.print_section("Comprehensive Security Header Analysis")
        
        loader = LoadingBar("Scanning headers with multiple methods and paths")
        loader.start()
        
        all_headers = {}
        header_variations = {}  # Track headers across different endpoints
        
        try:
            # Define test scenarios for maximum header discovery
            test_scenarios = [
                # Method-based tests
                {'method': 'GET', 'path': '/', 'description': 'GET /'},
                {'method': 'HEAD', 'path': '/', 'description': 'HEAD /'},
                {'method': 'OPTIONS', 'path': '/', 'description': 'OPTIONS /'},
                {'method': 'POST', 'path': '/', 'description': 'POST /'},
                
                # Common paths
                {'method': 'GET', 'path': '/api', 'description': 'GET /api'},
                {'method': 'GET', 'path': '/api/v1', 'description': 'GET /api/v1'},
                {'method': 'GET', 'path': '/robots.txt', 'description': 'GET /robots.txt'},
                {'method': 'GET', 'path': '/sitemap.xml', 'description': 'GET /sitemap.xml'},
                {'method': 'GET', 'path': '/.well-known/security.txt', 'description': 'GET security.txt'},
                
                # Error pages
                {'method': 'GET', 'path': '/404', 'description': 'GET /404'},
                {'method': 'GET', 'path': '/nonexistent', 'description': 'GET /nonexistent'},
            ]
            
            def fetch_headers_for_scenario(scenario):
                """Fetch headers for a specific scenario"""
                try:
                    url = urljoin(self.target_url, scenario['path'])
                    response = self.session.request(
                        scenario['method'],
                        url,
                        timeout=10,
                        verify=False,
                        allow_redirects=True
                    )
                    return scenario['description'], dict(response.headers)
                except:
                    return scenario['description'], {}
            
            # Parallel execution for speed
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(fetch_headers_for_scenario, scenario): scenario 
                          for scenario in test_scenarios}
                
                for future in as_completed(futures):
                    scenario_desc, headers = future.result()
                    
                    # Merge headers
                    for header, value in headers.items():
                        if header not in all_headers:
                            all_headers[header] = value
                            header_variations[header] = {scenario_desc: value}
                        else:
                            # Track variations
                            if header not in header_variations:
                                header_variations[header] = {}
                            if value != all_headers.get(header):
                                header_variations[header][scenario_desc] = value
            
            # Additional special requests to trigger specific headers
            special_tests = [
                # CORS preflight
                {'method': 'OPTIONS', 'headers': {'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'POST'}},
                
                # With various Accept headers
                {'method': 'GET', 'headers': {'Accept': 'application/json'}},
                {'method': 'GET', 'headers': {'Accept': 'application/xml'}},
                {'method': 'GET', 'headers': {'Accept': 'text/html'}},
                
                # With custom headers to trigger WAF/security
                {'method': 'GET', 'headers': {'X-Custom-Test': '<script>alert(1)</script>'}},
                {'method': 'GET', 'headers': {'User-Agent': 'sqlmap/1.0'}},
                
                # Range request
                {'method': 'GET', 'headers': {'Range': 'bytes=0-1023'}},
            ]
            
            for test in special_tests:
                try:
                    response = self.session.request(
                        test['method'],
                        self.target_url,
                        headers=test.get('headers', {}),
                        timeout=5,
                        verify=False
                    )
                    
                    for header, value in response.headers.items():
                        if header not in all_headers:
                            all_headers[header] = value
                
                except:
                    pass
            
            loader.stop(True)
            
            if not all_headers:
                loader.stop(False)
                self.print_check("Header Retrieval", "FAIL", "Unable to fetch headers")
                return {}
            
            self.print_check("Headers Retrieved", "PASS", f"Found {len(all_headers)} unique headers")
            
            # Analyze header variations
            varying_headers = {h: v for h, v in header_variations.items() if len(v) > 1}
            if varying_headers:
                print(f"\n{Fore.YELLOW}  Headers with variations across endpoints:{Style.RESET_ALL}")
                for header, variations in list(varying_headers.items())[:5]:
                    print(f"    {Fore.CYAN}{header}:{Style.RESET_ALL}")
                    for endpoint, value in list(variations.items())[:3]:
                        print(f"      {endpoint}: {value[:60]}")
                
                self.results['checks']['header_variations'] = varying_headers
            
        except Exception as e:
            loader.stop(False)
            self.print_check("Header Scan", "FAIL", str(e))
            return {}
        
        return all_headers
    
    def analyze_security_headers(self, headers):
        """Analyze presence and quality of security headers"""
        self.print_section("Security Headers Analysis")
        
        results = {
            'present': [],
            'missing': [],
            'analysis': {}
        }
        
        total_score = 0
        max_score = 0
        
        # Check each security header
        for header_name, header_info in self.security_headers.items():
            header_value = None
            
            # Case-insensitive header lookup
            for h, v in headers.items():
                if h.lower() == header_name.lower():
                    header_value = v
                    break
            
            max_score += abs(header_info['score']) if header_info['score'] > 0 else 0
            
            if header_value:
                results['present'].append(header_name)
                
                # Special analysis for specific headers
                if header_name == 'Content-Security-Policy':
                    csp_analysis = self.analyze_csp(header_value)
                    results['analysis']['csp'] = csp_analysis
                    total_score += max(0, csp_analysis['security_score'])
                    self.print_check(
                        "Content-Security-Policy",
                        "PASS",
                        f"Present with {len(csp_analysis['directives'])} directives (Score: {csp_analysis['security_score']})"
                    )
                
                elif header_name == 'Strict-Transport-Security':
                    hsts_analysis = self.analyze_hsts(header_value)
                    results['analysis']['hsts'] = hsts_analysis
                    total_score += max(0, hsts_analysis['security_score'])
                    self.print_check(
                        "Strict-Transport-Security",
                        "PASS",
                        f"max-age={hsts_analysis['max_age']}s, preload={hsts_analysis['preload']} (Score: {hsts_analysis['security_score']})"
                    )
                
                elif header_name == 'Permissions-Policy':
                    pp_analysis = self.analyze_permissions_policy(header_value)
                    results['analysis']['permissions_policy'] = pp_analysis
                    total_score += max(0, pp_analysis['security_score'])
                    self.print_check(
                        "Permissions-Policy",
                        "PASS",
                        f"Present with {len(pp_analysis['policies'])} policies"
                    )
                
                elif header_name in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']:
                    # Negative score for information disclosure
                    self.print_check(
                        header_name,
                        "WARN",
                        f"Information disclosure: {header_value}"
                    )
                    total_score += header_info['score']  # Negative score
                
                else:
                    # Standard header present
                    self.print_check(
                        header_name,
                        "PASS",
                        f"Value: {header_value[:100]}"
                    )
                    if header_info['score'] > 0:
                        total_score += header_info['score']
            
            else:
                # Header missing
                if header_info['severity'] in ['CRITICAL', 'HIGH']:
                    results['missing'].append(header_name)
                    self.print_check(
                        header_name,
                        "FAIL" if header_info['severity'] == 'CRITICAL' else "WARN",
                        f"Missing - {header_info['description']}"
                    )
        
        results['security_score'] = total_score
        results['max_score'] = max_score
        results['percentage'] = (total_score / max_score * 100) if max_score > 0 else 0
        
        return results
    
    def analyze_cors_comprehensive(self, headers):
        """Comprehensive CORS analysis"""
        self.print_section("CORS (Cross-Origin Resource Sharing) Analysis")
        
        cors_analysis = self.analyze_cors(headers)
        
        if not cors_analysis['enabled']:
            self.print_check("CORS", "PASS", "CORS not enabled (no CORS headers found)")
            return cors_analysis
        
        self.print_check("CORS Status", "WARN", "CORS is enabled")
        
        # Print CORS headers
        for header, value in cors_analysis['headers'].items():
            print(f"  {Fore.CYAN}{header}:{Style.RESET_ALL} {value}")
        
        # Print issues
        if cors_analysis['issues']:
            print(f"\n{Fore.RED}  Issues Found:{Style.RESET_ALL}")
            for issue in cors_analysis['issues']:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} {issue}")
        
        # Print recommendations
        if cors_analysis['recommendations']:
            print(f"\n{Fore.YELLOW}  Recommendations:{Style.RESET_ALL}")
            for rec in cors_analysis['recommendations']:
                print(f"    {Fore.YELLOW}•{Style.RESET_ALL} {rec}")
        
        return cors_analysis
    
    def analyze_caching_comprehensive(self, headers):
        """Comprehensive caching analysis"""
        self.print_section("Caching Headers Analysis")
        
        cache_analysis = self.analyze_cache_control(headers)
        
        if cache_analysis['cache_control']:
            self.print_check("Cache-Control", "PASS", cache_analysis['cache_control'])
            
            # Print directives
            if cache_analysis['directives']:
                print(f"\n{Fore.CYAN}  Parsed Directives:{Style.RESET_ALL}")
                for directive, value in cache_analysis['directives'].items():
                    if value is True:
                        print(f"    • {directive}")
                    else:
                        print(f"    • {directive} = {value}")
        else:
            self.print_check("Cache-Control", "WARN", "Header not found")
        
        if cache_analysis['pragma']:
            self.print_check("Pragma", "PASS", cache_analysis['pragma'])
        
        if cache_analysis['expires']:
            self.print_check("Expires", "PASS", cache_analysis['expires'])
        
        # Print recommendations
        if cache_analysis['recommendations']:
            print(f"\n{Fore.YELLOW}  Recommendations:{Style.RESET_ALL}")
            for rec in cache_analysis['recommendations']:
                print(f"    {Fore.YELLOW}•{Style.RESET_ALL} {rec}")
        
        return cache_analysis
    
    def detect_cloud_and_orchestration(self, headers):
        """Detect cloud platform and container orchestration"""
        self.print_section("Cloud Platform & Orchestration Detection")
        
        detection = self.detect_cloud_platform(headers)
        
        if detection['platforms']:
            for platform in detection['platforms']:
                self.print_check(f"Cloud Platform: {platform.upper()}", "PASS", "Detected")
                if platform in detection['details']:
                    for detail in detection['details'][platform][:3]:  # Show first 3
                        print(f"    {Fore.CYAN}└─{Style.RESET_ALL} {detail}")
        else:
            self.print_check("Cloud Platform", "WARN", "No specific cloud platform detected")
        
        if detection['orchestration']:
            for tech in detection['orchestration']:
                self.print_check(f"Orchestration: {tech.upper()}", "PASS", "Detected")
        else:
            self.print_check("Container Orchestration", "WARN", "No orchestration indicators found")
        
        return detection
    
    def check_information_disclosure_comprehensive(self, headers):
        """Comprehensive information disclosure check"""
        self.print_section("Information Disclosure Analysis")
        
        disclosure = self.check_information_disclosure(headers)
        
        if disclosure['server_info']:
            print(f"\n{Fore.YELLOW}  Server Information:{Style.RESET_ALL}")
            for info in disclosure['server_info']:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {info}")
        
        if disclosure['version_leaks']:
            print(f"\n{Fore.RED}  Version Leaks (SECURITY RISK):{Style.RESET_ALL}")
            for leak in disclosure['version_leaks']:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} {leak}")
        
        if disclosure['internal_info']:
            print(f"\n{Fore.RED}  Internal Information Leaks:{Style.RESET_ALL}")
            for leak in disclosure['internal_info']:
                print(f"    {Fore.RED}✗{Style.RESET_ALL} {leak}")
        
        if disclosure['path_leaks']:
            print(f"\n{Fore.YELLOW}  Path Disclosures:{Style.RESET_ALL}")
            for leak in disclosure['path_leaks']:
                print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {leak}")
        
        if disclosure['severity'] == 'NONE':
            self.print_check("Information Disclosure", "PASS", "No sensitive information detected")
        else:
            self.print_check("Information Disclosure", "FAIL", f"Severity: {disclosure['severity']}")
        
        return disclosure
    
    def detect_http_version_and_features(self, headers):
        """Detect HTTP version and advanced protocol features"""
        self.print_section("HTTP Protocol Analysis")
        
        protocol_info = {
            'http_version': None,
            'http2_support': False,
            'http3_support': False,
            'tls_version': None,
            'alpn_protocol': None,
            'compression': [],
            'features': []
        }
        
        try:
            # Make a request to detect protocol
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # HTTP version detection
            if hasattr(response.raw, 'version'):
                version = response.raw.version
                if version == 11:
                    protocol_info['http_version'] = 'HTTP/1.1'
                elif version == 20:
                    protocol_info['http_version'] = 'HTTP/2'
                    protocol_info['http2_support'] = True
                    protocol_info['features'].append('HTTP/2 Multiplexing')
                    protocol_info['features'].append('Server Push Capable')
                else:
                    protocol_info['http_version'] = f'HTTP/{version/10}'
            
            # Check for HTTP/3 (QUIC) via Alt-Svc header
            alt_svc = headers.get('Alt-Svc', '') or headers.get('alt-svc', '')
            if alt_svc:
                if 'h3' in alt_svc.lower() or 'quic' in alt_svc.lower():
                    protocol_info['http3_support'] = True
                    protocol_info['features'].append('HTTP/3 (QUIC) Support')
                self.print_check("Alt-Svc Header", "PASS", alt_svc)
            
            # Compression detection
            content_encoding = headers.get('Content-Encoding', '')
            if content_encoding:
                encodings = [e.strip() for e in content_encoding.split(',')]
                protocol_info['compression'] = encodings
                for encoding in encodings:
                    if encoding in ['br', 'gzip', 'deflate', 'zstd']:
                        protocol_info['features'].append(f'{encoding.upper()} Compression')
            
            # Check for Brotli support
            if 'br' in protocol_info['compression']:
                self.print_check("Brotli Compression", "PASS", "Enabled (modern compression)")
            
            # Check for Early Hints (103 status)
            link_header = headers.get('Link', '')
            if link_header:
                protocol_info['features'].append('Resource Hints (Link header)')
            
            # Server Push detection
            if 'Link' in headers and 'preload' in headers['Link'].lower():
                protocol_info['features'].append('HTTP/2 Server Push Hints')
            
            # Protocol info display
            if protocol_info['http_version']:
                self.print_check("HTTP Version", "PASS", protocol_info['http_version'])
            
            if protocol_info['http2_support']:
                self.print_check("HTTP/2 Support", "PASS", "Enabled")
            else:
                self.print_check("HTTP/2 Support", "WARN", "Not detected (consider upgrading)")
            
            if protocol_info['http3_support']:
                self.print_check("HTTP/3 Support", "PASS", "Enabled (cutting edge)")
            
            if protocol_info['compression']:
                self.print_check("Compression", "PASS", ', '.join(protocol_info['compression']))
            
            # Display features
            if protocol_info['features']:
                print(f"\n{Fore.GREEN}  Protocol Features Detected:{Style.RESET_ALL}")
                for feature in protocol_info['features']:
                    print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {feature}")
        
        except Exception as e:
            self.print_check("Protocol Detection", "FAIL", str(e))
        
        return protocol_info
    
    def analyze_security_txt(self):
        """Check for security.txt file (RFC 9116)"""
        self.print_section("Security.txt Analysis (RFC 9116)")
        
        security_txt_data = {
            'present': False,
            'location': None,
            'contacts': [],
            'expires': None,
            'canonical': None,
            'policy': None,
            'hiring': None,
            'acknowledgments': None
        }
        
        # Check both locations per RFC 9116
        locations = [
            '/.well-known/security.txt',
            '/security.txt'
        ]
        
        for location in locations:
            try:
                url = urljoin(self.target_url, location)
                response = self.session.get(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    security_txt_data['present'] = True
                    security_txt_data['location'] = location
                    
                    # Parse security.txt content
                    content = response.text
                    
                    # Extract fields
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('Contact:'):
                            security_txt_data['contacts'].append(line.split(':', 1)[1].strip())
                        elif line.startswith('Expires:'):
                            security_txt_data['expires'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Canonical:'):
                            security_txt_data['canonical'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Policy:'):
                            security_txt_data['policy'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Hiring:'):
                            security_txt_data['hiring'] = line.split(':', 1)[1].strip()
                        elif line.startswith('Acknowledgments:'):
                            security_txt_data['acknowledgments'] = line.split(':', 1)[1].strip()
                    
                    self.print_check("security.txt Found", "PASS", f"Location: {location}")
                    
                    if security_txt_data['contacts']:
                        print(f"\n{Fore.GREEN}  Security Contacts:{Style.RESET_ALL}")
                        for contact in security_txt_data['contacts']:
                            print(f"    {Fore.CYAN}•{Style.RESET_ALL} {contact}")
                    
                    if security_txt_data['policy']:
                        self.print_check("Security Policy", "PASS", security_txt_data['policy'])
                    
                    break
            
            except:
                continue
        
        if not security_txt_data['present']:
            self.print_check("security.txt", "WARN", 
                           "Not found - consider implementing RFC 9116")
            print(f"    {Fore.YELLOW}ℹ{Style.RESET_ALL}  https://securitytxt.org/")
        
        return security_txt_data
    
    def analyze_cookies(self):
        """Analyze cookie security attributes"""
        self.print_section("Cookie Security Analysis")
        
        cookie_analysis = {
            'cookies': [],
            'issues': [],
            'recommendations': [],
            'security_score': 0
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            cookies = response.cookies
            
            if not cookies:
                self.print_check("Cookies", "PASS", "No cookies set")
                return cookie_analysis
            
            for cookie in cookies:
                cookie_data = {
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': bool(cookie.has_nonstandard_attr('HttpOnly')),
                    'samesite': cookie.get_nonstandard_attr('SameSite', None),
                    'expires': cookie.expires,
                    'issues': []
                }
                
                # Security checks
                if not cookie.secure and self.parsed_url.scheme == 'https':
                    cookie_data['issues'].append("Missing Secure flag on HTTPS site")
                    cookie_analysis['issues'].append(f"{cookie.name}: Missing Secure flag")
                    cookie_analysis['security_score'] -= 5
                
                if not cookie_data['httponly']:
                    cookie_data['issues'].append("Missing HttpOnly flag (XSS risk)")
                    cookie_analysis['issues'].append(f"{cookie.name}: Missing HttpOnly")
                    cookie_analysis['security_score'] -= 5
                
                if not cookie_data['samesite']:
                    cookie_data['issues'].append("Missing SameSite attribute (CSRF risk)")
                    cookie_analysis['issues'].append(f"{cookie.name}: Missing SameSite")
                    cookie_analysis['security_score'] -= 3
                elif cookie_data['samesite'].lower() == 'none' and not cookie.secure:
                    cookie_data['issues'].append("SameSite=None without Secure flag")
                    cookie_analysis['issues'].append(f"{cookie.name}: Invalid SameSite=None")
                    cookie_analysis['security_score'] -= 8
                
                # Check for sensitive names
                sensitive_names = ['session', 'sess', 'token', 'auth', 'jwt', 'api']
                if any(s in cookie.name.lower() for s in sensitive_names):
                    if not cookie.secure or not cookie_data['httponly']:
                        cookie_data['issues'].append("Sensitive cookie without proper protection")
                        cookie_analysis['security_score'] -= 10
                
                cookie_analysis['cookies'].append(cookie_data)
            
            # Display results
            self.print_check("Cookies Found", "PASS", f"{len(cookies)} cookie(s) detected")
            
            for cookie_data in cookie_analysis['cookies']:
                print(f"\n{Fore.CYAN}  Cookie: {cookie_data['name']}{Style.RESET_ALL}")
                print(f"    Secure: {Fore.GREEN if cookie_data['secure'] else Fore.RED}{cookie_data['secure']}{Style.RESET_ALL}")
                print(f"    HttpOnly: {Fore.GREEN if cookie_data['httponly'] else Fore.RED}{cookie_data['httponly']}{Style.RESET_ALL}")
                print(f"    SameSite: {Fore.GREEN if cookie_data['samesite'] else Fore.RED}{cookie_data['samesite'] or 'Not Set'}{Style.RESET_ALL}")
                
                if cookie_data['issues']:
                    print(f"    {Fore.RED}Issues:{Style.RESET_ALL}")
                    for issue in cookie_data['issues']:
                        print(f"      {Fore.RED}✗{Style.RESET_ALL} {issue}")
            
            # Recommendations
            if cookie_analysis['issues']:
                print(f"\n{Fore.YELLOW}  Cookie Security Recommendations:{Style.RESET_ALL}")
                print(f"    {Fore.YELLOW}•{Style.RESET_ALL} Set Secure flag on all cookies (HTTPS only)")
                print(f"    {Fore.YELLOW}•{Style.RESET_ALL} Set HttpOnly flag to prevent XSS cookie theft")
                print(f"    {Fore.YELLOW}•{Style.RESET_ALL} Set SameSite attribute (Strict/Lax) for CSRF protection")
        
        except Exception as e:
            self.print_check("Cookie Analysis", "FAIL", str(e))
        
        return cookie_analysis
    
    def generate_detailed_recommendations(self):
        self.print_section("Security Recommendations")
        
        recommendations = []
        
        # Analyze results and generate recommendations
        if 'security_headers' in self.results['checks']:
            headers_result = self.results['checks']['security_headers']
            
            if 'Content-Security-Policy' in headers_result['missing']:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'header': 'Content-Security-Policy',
                    'recommendation': "Implement a strict CSP to prevent XSS attacks",
                    'example': "Content-Security-Policy: default-src 'self'; script-src 'self' 'sha256-...'; object-src 'none';"
                })
            
            if 'Strict-Transport-Security' in headers_result['missing']:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'header': 'Strict-Transport-Security',
                    'recommendation': "Enable HSTS to enforce HTTPS",
                    'example': "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                })
            
            if 'X-Frame-Options' in headers_result['missing']:
                recommendations.append({
                    'priority': 'HIGH',
                    'header': 'X-Frame-Options',
                    'recommendation': "Prevent clickjacking attacks",
                    'example': "X-Frame-Options: DENY"
                })
            
            if 'X-Content-Type-Options' in headers_result['missing']:
                recommendations.append({
                    'priority': 'HIGH',
                    'header': 'X-Content-Type-Options',
                    'recommendation': "Prevent MIME-type sniffing",
                    'example': "X-Content-Type-Options: nosniff"
                })
            
            if 'Referrer-Policy' in headers_result['missing']:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'header': 'Referrer-Policy',
                    'recommendation': "Control referrer information leakage",
                    'example': "Referrer-Policy: strict-origin-when-cross-origin"
                })
            
            if 'Permissions-Policy' in headers_result['missing']:
                recommendations.append({
                    'priority': 'HIGH',
                    'header': 'Permissions-Policy',
                    'recommendation': "Restrict browser features and APIs",
                    'example': "Permissions-Policy: geolocation=(), microphone=(), camera=()"
                })
        
        # Print recommendations
        if recommendations:
            for rec in recommendations:
                priority_color = Fore.RED if rec['priority'] == 'CRITICAL' else Fore.YELLOW if rec['priority'] == 'HIGH' else Fore.CYAN
                print(f"\n{priority_color}[{rec['priority']}] {rec['header']}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}{rec['recommendation']}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Example:{Style.RESET_ALL} {rec['example']}")
        else:
            print(f"{Fore.GREEN}No critical recommendations - security headers are well configured!{Style.RESET_ALL}")
        
        self.results['checks']['recommendations'] = recommendations
        return recommendations
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"HTTPHeaders_{hostname}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("HTTP SECURITY HEADERS ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Scan Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # Security Score
        if 'security_headers' in self.results['checks']:
            headers_result = self.results['checks']['security_headers']
            report.append("\n" + "=" * 80)
            report.append("SECURITY SCORE")
            report.append("=" * 80)
            report.append(f"\nOverall Score: {headers_result['security_score']}/{headers_result['max_score']}")
            report.append(f"Percentage: {headers_result['percentage']:.1f}%")
            report.append(f"\nHeaders Present: {len(headers_result['present'])}")
            report.append(f"Critical/High Headers Missing: {len(headers_result['missing'])}")
        
        # Add all check results
        for check_name, check_data in self.results['checks'].items():
            report.append(f"\n{'=' * 80}")
            report.append(f"{check_name.upper().replace('_', ' ')}")
            report.append("=" * 80)
            report.append(json.dumps(check_data, indent=2))
            report.append("")
        
        # Summary
        report.append("\n" + "=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)
        
        if 'security_headers' in self.results['checks']:
            headers_result = self.results['checks']['security_headers']
            
            report.append(f"\nSecurity Posture:")
            if headers_result['percentage'] >= 80:
                report.append("  Status: EXCELLENT - Strong security header implementation")
            elif headers_result['percentage'] >= 60:
                report.append("  Status: GOOD - Decent security, room for improvement")
            elif headers_result['percentage'] >= 40:
                report.append("  Status: FAIR - Several critical headers missing")
            else:
                report.append("  Status: POOR - Significant security gaps detected")
            
            report.append(f"\nCritical Issues:")
            critical_missing = [h for h in headers_result['missing'] 
                              if self.security_headers[h]['severity'] == 'CRITICAL']
            if critical_missing:
                for header in critical_missing:
                    report.append(f"  - Missing: {header}")
            else:
                report.append("  - None")
        
        # CORS Summary
        if 'cors_analysis' in self.results['checks']:
            cors = self.results['checks']['cors_analysis']
            report.append(f"\nCORS Configuration:")
            if cors['enabled']:
                report.append(f"  Status: Enabled")
                report.append(f"  Issues: {len(cors['issues'])}")
                if cors['issues']:
                    for issue in cors['issues']:
                        report.append(f"    - {issue}")
            else:
                report.append("  Status: Not enabled")
        
        # Cloud Platform
        if 'cloud_detection' in self.results['checks']:
            cloud = self.results['checks']['cloud_detection']
            report.append(f"\nCloud Platform Detection:")
            if cloud['platforms']:
                report.append(f"  Platforms: {', '.join(cloud['platforms'])}")
            if cloud['orchestration']:
                report.append(f"  Orchestration: {', '.join(cloud['orchestration'])}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting HTTP Security Header Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = HTTPSecurityHeaderAnalyzer(target_url)
    
    # Define scan stages (expanded to 12 stages)
    stages = [
        ("Comprehensive Header Scan", analyzer.comprehensive_header_scan),
        ("Security Headers Analysis", None),  # Uses headers from previous stage
        ("CSP Deep Analysis", None),
        ("CORS Analysis", None),
        ("Caching Analysis", None),
        ("HTTP Protocol Analysis", None),
        ("Cookie Security Analysis", None),
        ("Security.txt Check", None),
        ("Cloud & Orchestration Detection", None),
        ("Information Disclosure Check", None),
        ("WAF/CDN Detection", None),
        ("Generate Recommendations", None),
    ]
    
    progress = ProgressBar(len(stages))
    
    try:
        # Stage 1: Fetch headers with parallel scanning
        progress.update(stages[0][0])
        headers = stages[0][1]()
        
        if not headers:
            print(f"\n{Fore.RED}[!] Failed to retrieve headers. Cannot continue.{Style.RESET_ALL}")
            return
        
        # Stage 2: Analyze security headers
        progress.update(stages[1][0])
        headers_result = analyzer.analyze_security_headers(headers)
        analyzer.results['checks']['security_headers'] = headers_result
        
        # Stage 3: Deep CSP analysis (if present)
        progress.update(stages[2][0])
        if 'csp' in headers_result.get('analysis', {}):
            print(f"\n{Fore.CYAN}═══ CSP Detailed Breakdown ═══{Style.RESET_ALL}\n")
            csp_result = headers_result['analysis']['csp']
            if csp_result['directives']:
                for directive, sources in csp_result['directives'].items():
                    print(f"  {Fore.YELLOW}{directive}:{Style.RESET_ALL} {' '.join(sources) if sources else '(no sources)'}")
            if csp_result['issues']:
                print(f"\n{Fore.RED}  CSP Issues:{Style.RESET_ALL}")
                for issue in csp_result['issues']:
                    print(f"    {Fore.RED}✗{Style.RESET_ALL} {issue}")
        
        # Stage 4: CORS analysis
        progress.update(stages[3][0])
        cors_result = analyzer.analyze_cors_comprehensive(headers)
        analyzer.results['checks']['cors_analysis'] = cors_result
        
        # Stage 5: Caching analysis
        progress.update(stages[4][0])
        cache_result = analyzer.analyze_caching_comprehensive(headers)
        analyzer.results['checks']['caching_analysis'] = cache_result
        
        # Stage 6: HTTP protocol analysis
        progress.update(stages[5][0])
        protocol_result = analyzer.detect_http_version_and_features(headers)
        analyzer.results['checks']['protocol_analysis'] = protocol_result
        
        # Stage 7: Cookie security analysis
        progress.update(stages[6][0])
        cookie_result = analyzer.analyze_cookies()
        analyzer.results['checks']['cookie_analysis'] = cookie_result
        
        # Stage 8: Security.txt check
        progress.update(stages[7][0])
        security_txt_result = analyzer.analyze_security_txt()
        analyzer.results['checks']['security_txt'] = security_txt_result
        
        # Stage 9: Cloud detection
        progress.update(stages[8][0])
        cloud_result = analyzer.detect_cloud_and_orchestration(headers)
        analyzer.results['checks']['cloud_detection'] = cloud_result
        
        # Stage 10: Information disclosure
        progress.update(stages[9][0])
        disclosure_result = analyzer.check_information_disclosure_comprehensive(headers)
        analyzer.results['checks']['information_disclosure'] = disclosure_result
        
        # Stage 11: WAF/CDN specific detection
        progress.update(stages[10][0])
        analyzer.print_section("WAF & CDN Detailed Analysis")
        waf_cdn_details = {
            'waf': [],
            'cdn': [],
            'headers': {}
        }
        
        # Extract WAF/CDN specific headers
        for header, value in headers.items():
            header_lower = header.lower()
            if any(waf in header_lower for waf in ['waf', 'security', 'firewall', 'protection']):
                waf_cdn_details['waf'].append(f"{header}: {value}")
                waf_cdn_details['headers'][header] = value
            if any(cdn in header_lower for cdn in ['cdn', 'cache', 'edge', 'cloudflare', 'fastly', 'akamai']):
                waf_cdn_details['cdn'].append(f"{header}: {value}")
                waf_cdn_details['headers'][header] = value
        
        if waf_cdn_details['waf']:
            print(f"{Fore.GREEN}  WAF Headers Detected:{Style.RESET_ALL}")
            for header_info in waf_cdn_details['waf'][:10]:
                print(f"    {Fore.CYAN}•{Style.RESET_ALL} {header_info}")
        else:
            analyzer.print_check("WAF Headers", "WARN", "No WAF-specific headers found")
        
        if waf_cdn_details['cdn']:
            print(f"\n{Fore.GREEN}  CDN Headers Detected:{Style.RESET_ALL}")
            for header_info in waf_cdn_details['cdn'][:10]:
                print(f"    {Fore.CYAN}•{Style.RESET_ALL} {header_info}")
        else:
            analyzer.print_check("CDN Headers", "WARN", "No CDN-specific headers found")
        
        analyzer.results['checks']['waf_cdn_details'] = waf_cdn_details
        
        # Stage 12: Recommendations
        progress.update(stages[11][0])
        analyzer.generate_detailed_recommendations()
        
        # Generate report
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  Finalizing Comprehensive Report")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        loader = LoadingBar("Generating comprehensive report")
        loader.start()
        time.sleep(1)
        report_path = analyzer.generate_report()
        loader.stop(True)
        
        # Final summary with comprehensive statistics
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # Display comprehensive statistics
        if 'security_headers' in analyzer.results['checks']:
            headers_result = analyzer.results['checks']['security_headers']
            score_color = Fore.GREEN if headers_result['percentage'] >= 80 else Fore.YELLOW if headers_result['percentage'] >= 60 else Fore.RED
            print(f"{score_color}[✓] Security Score: {headers_result['security_score']}/{headers_result['max_score']} ({headers_result['percentage']:.1f}%){Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[✓] Total Headers Analyzed: {len(headers)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Security Headers Present: {len(headers_result.get('present', []))}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Critical Headers Missing: {len([h for h in headers_result.get('missing', []) if analyzer.security_headers[h]['severity'] == 'CRITICAL'])}{Style.RESET_ALL}")
        
        # Protocol info
        if 'protocol_analysis' in analyzer.results['checks']:
            protocol = analyzer.results['checks']['protocol_analysis']
            if protocol.get('http2_support'):
                print(f"{Fore.GREEN}[✓] HTTP/2: Enabled{Style.RESET_ALL}")
            if protocol.get('http3_support'):
                print(f"{Fore.GREEN}[✓] HTTP/3: Enabled{Style.RESET_ALL}")
        
        # Cloud/Orchestration info
        if 'cloud_detection' in analyzer.results['checks']:
            cloud = analyzer.results['checks']['cloud_detection']
            if cloud['platforms']:
                print(f"{Fore.CYAN}[✓] Cloud Platform: {', '.join(cloud['platforms'])}{Style.RESET_ALL}")
            if cloud['orchestration']:
                print(f"{Fore.CYAN}[✓] Orchestration: {', '.join(cloud['orchestration'])}{Style.RESET_ALL}")
        
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
    # For testing
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python headers.py <target_url>")
