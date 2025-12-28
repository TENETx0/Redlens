#!/usr/bin/env python3
"""
Cloud & Hosting Exposure Analysis Module
Comprehensive cloud infrastructure detection and security analysis including
AWS, Azure, GCP, Oracle Cloud, DigitalOcean, Linode, Alibaba Cloud, IBM Cloud,
and modern DevOps/MLOps platforms (Docker, Kubernetes, CI/CD, serverless)
"""

import requests
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style
from threading import Thread
from collections import defaultdict, Counter
import warnings
import socket
import dns.resolver

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class LoadingBar:
    """Animated loading bar"""
    def __init__(self, description="Processing"):
        self.description = description
        self.running = False
        self.thread = None
    
    def animate(self):
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while self.running:
            sys.stdout.write(f"\r{Fore.CYAN}[{chars[idx % len(chars)]}] {self.description}...{Style.RESET_ALL}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)
    
    def start(self):
        self.running = True
        self.thread = Thread(target=self.animate)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self, success=True):
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
        self.current += 1
        percentage = (self.current / self.total) * 100
        filled = int(percentage / 2)
        bar = "█" * filled + "░" * (50 - filled)
        print(f"\n{Fore.YELLOW}{stage_name.center(70)}{Style.RESET_ALL}")
        print(f"[{Fore.GREEN}{bar}{Style.RESET_ALL}] {percentage:.1f}% ({self.current}/{self.total})\n")

class CloudExposureAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc.split(':')[0]
        
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'cloud_provider': None,
            'cloud_indicators': [],
            'storage_exposures': [],
            'metadata_endpoints': [],
            'infrastructure': {},
            'serverless_hints': [],
            'environment_leaks': [],
            'security_issues': []
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Comprehensive cloud provider fingerprints
        self.cloud_providers = {
            'AWS': {
                'headers': {
                    'X-Amz-Request-Id': 'AWS Request ID',
                    'X-Amz-Id-2': 'AWS Extended Request ID',
                    'X-Amz-Cf-Id': 'CloudFront Distribution',
                    'X-Amz-Cf-Pop': 'CloudFront Edge Location',
                    'X-Amzn-RequestId': 'AWS Request ID',
                    'X-Amzn-Trace-Id': 'AWS X-Ray Trace',
                    'Server': 'AmazonS3'
                },
                'patterns': [
                    r'\.amazonaws\.com',
                    r'\.cloudfront\.net',
                    r's3\.amazonaws\.com',
                    r's3-[a-z0-9-]+\.amazonaws\.com',
                    r'\.s3\.amazonaws\.com',
                    r'\.elasticbeanstalk\.com',
                    r'\.elb\.amazonaws\.com',
                    r'\.execute-api\..*\.amazonaws\.com',
                    r'\.lambda-url\..*\.on\.aws',
                    r'amplifyapp\.com'
                ],
                'services': {
                    's3': 'S3 Object Storage',
                    'cloudfront': 'CloudFront CDN',
                    'elb': 'Elastic Load Balancer',
                    'lambda': 'AWS Lambda Serverless',
                    'elasticbeanstalk': 'Elastic Beanstalk',
                    'api-gateway': 'API Gateway',
                    'amplify': 'AWS Amplify'
                }
            },
            'Azure': {
                'headers': {
                    'X-Ms-Request-Id': 'Azure Request ID',
                    'X-Ms-Version': 'Azure Storage Version',
                    'X-Azure-Ref': 'Azure Reference',
                    'X-Azure-RequestId': 'Azure Request ID',
                    'X-Powered-By': 'ASP.NET'
                },
                'patterns': [
                    r'\.azurewebsites\.net',
                    r'\.azure\.com',
                    r'\.blob\.core\.windows\.net',
                    r'\.cloudapp\.azure\.com',
                    r'\.trafficmanager\.net',
                    r'\.azurefd\.net',
                    r'\.azureedge\.net',
                    r'\.azure-api\.net',
                    r'\.database\.windows\.net'
                ],
                'services': {
                    'blob': 'Azure Blob Storage',
                    'azurewebsites': 'App Service',
                    'trafficmanager': 'Traffic Manager',
                    'azurefd': 'Azure Front Door',
                    'azureedge': 'Azure CDN'
                }
            },
            'GCP': {
                'headers': {
                    'X-Goog-Generation': 'Google Cloud Storage Generation',
                    'X-Goog-Metageneration': 'Google Cloud Storage Metageneration',
                    'X-GUploader-UploadID': 'Google Uploader ID',
                    'X-Cloud-Trace-Context': 'GCP Trace Context',
                    'Server': 'Google Frontend'
                },
                'patterns': [
                    r'\.appspot\.com',
                    r'\.googleapis\.com',
                    r'storage\.googleapis\.com',
                    r'\.cloudfunctions\.net',
                    r'\.run\.app',
                    r'\.cloudrun\.app',
                    r'\.appengine\.google\.com',
                    r'\.firebaseapp\.com',
                    r'\.web\.app'
                ],
                'services': {
                    'appengine': 'App Engine',
                    'cloudfunctions': 'Cloud Functions',
                    'run': 'Cloud Run',
                    'storage': 'Cloud Storage',
                    'firebase': 'Firebase'
                }
            },
            'Oracle Cloud': {
                'headers': {
                    'X-Oracle-Dms-Ecid': 'Oracle ECID',
                    'X-Oracle-Dms-Rid': 'Oracle RID'
                },
                'patterns': [
                    r'\.oraclecloud\.com',
                    r'\.oci\.oraclecloud\.com',
                    r'objectstorage\..*\.oraclecloud\.com',
                    r'\.ocp\.oraclecloud\.com'
                ],
                'services': {
                    'objectstorage': 'Object Storage',
                    'oci': 'Oracle Cloud Infrastructure'
                }
            },
            'DigitalOcean': {
                'headers': {
                    'X-DO-Request-Id': 'DigitalOcean Request ID'
                },
                'patterns': [
                    r'\.digitaloceanspaces\.com',
                    r'\.ondigitalocean\.app',
                    r'cdn\.digitaloceanspaces\.com'
                ],
                'services': {
                    'spaces': 'Spaces Object Storage',
                    'app': 'App Platform'
                }
            },
            'Linode': {
                'headers': {},
                'patterns': [
                    r'\.linode\.com',
                    r'\.linodeobjects\.com',
                    r'\.linode-rancher\.com'
                ],
                'services': {
                    'objects': 'Object Storage'
                }
            },
            'Alibaba Cloud': {
                'headers': {
                    'X-Oss-Request-Id': 'Alibaba OSS Request ID'
                },
                'patterns': [
                    r'\.aliyuncs\.com',
                    r'\.oss-.*\.aliyuncs\.com',
                    r'\.alibabacloud\.com'
                ],
                'services': {
                    'oss': 'Object Storage Service'
                }
            },
            'IBM Cloud': {
                'headers': {
                    'X-IBM-Client-IP': 'IBM Client IP'
                },
                'patterns': [
                    r'\.ibmcloud\.com',
                    r'\.cloud\.ibm\.com',
                    r'\.mybluemix\.net'
                ],
                'services': {
                    'mybluemix': 'Cloud Foundry'
                }
            },
            'Cloudflare': {
                'headers': {
                    'CF-RAY': 'Cloudflare Ray ID',
                    'CF-Cache-Status': 'Cloudflare Cache',
                    'Server': 'cloudflare'
                },
                'patterns': [
                    r'\.pages\.dev',
                    r'\.workers\.dev',
                    r'cloudflare'
                ],
                'services': {
                    'pages': 'Cloudflare Pages',
                    'workers': 'Cloudflare Workers'
                }
            },
            'Vercel': {
                'headers': {
                    'X-Vercel-Id': 'Vercel Deployment ID',
                    'X-Vercel-Cache': 'Vercel Cache Status',
                    'Server': 'Vercel'
                },
                'patterns': [
                    r'\.vercel\.app',
                    r'\.now\.sh'
                ],
                'services': {
                    'app': 'Vercel Deployment'
                }
            },
            'Netlify': {
                'headers': {
                    'X-NF-Request-ID': 'Netlify Request ID',
                    'Server': 'Netlify'
                },
                'patterns': [
                    r'\.netlify\.app',
                    r'\.netlify\.com'
                ],
                'services': {
                    'app': 'Netlify Hosting'
                }
            },
            'Heroku': {
                'headers': {
                    'Server': 'Cowboy'
                },
                'patterns': [
                    r'\.herokuapp\.com',
                    r'\.herokussl\.com'
                ],
                'services': {
                    'app': 'Heroku Dyno'
                }
            },
            'Fastly': {
                'headers': {
                    'X-Fastly-Request-ID': 'Fastly Request ID',
                    'Fastly-Debug-Digest': 'Fastly Debug'
                },
                'patterns': [
                    r'\.fastly\.net'
                ],
                'services': {
                    'cdn': 'Fastly CDN'
                }
            }
        }
        
        # Container & orchestration patterns
        self.container_patterns = {
            'Docker': [
                r'docker',
                r'\.docker\.io',
                r'dockerhub',
                r'registry\.hub\.docker\.com'
            ],
            'Kubernetes': [
                r'k8s',
                r'kubernetes',
                r'\.svc\.cluster\.local',
                r'kube-system',
                r'kubectl'
            ],
            'Docker Swarm': [
                r'swarm',
                r'docker-swarm'
            ],
            'Rancher': [
                r'rancher',
                r'cattle'
            ],
            'OpenShift': [
                r'openshift',
                r'\.apps\..*\.openshift\.com'
            ]
        }
        
        # CI/CD platform patterns
        self.cicd_patterns = {
            'Jenkins': [r'jenkins', r'/job/', r'/build/'],
            'GitLab CI': [r'gitlab-ci', r'\.gitlab-ci\.yml'],
            'GitHub Actions': [r'github\.com/.*?/actions', r'\.github/workflows'],
            'CircleCI': [r'circleci', r'circle-ci'],
            'Travis CI': [r'travis-ci', r'\.travis\.yml'],
            'Azure DevOps': [r'dev\.azure\.com', r'visualstudio\.com'],
            'TeamCity': [r'teamcity'],
            'Bamboo': [r'bamboo'],
            'ArgoCD': [r'argocd', r'argo-cd'],
            'Spinnaker': [r'spinnaker'],
            'Drone': [r'drone\.io']
        }
        
        # MLOps platform patterns
        self.mlops_patterns = {
            'MLflow': [r'mlflow'],
            'Kubeflow': [r'kubeflow'],
            'SageMaker': [r'sagemaker', r'\.notebook\..*\.sagemaker\.aws'],
            'Databricks': [r'databricks', r'\.azuredatabricks\.net'],
            'Vertex AI': [r'vertex', r'aiplatform\.googleapis\.com'],
            'Neptune': [r'neptune\.ai'],
            'Weights & Biases': [r'wandb'],
            'TensorBoard': [r'tensorboard']
        }
        
        # Storage bucket patterns
        self.bucket_patterns = {
            'AWS S3': [
                r's3://([a-zA-Z0-9.\-_]+)',
                r'([a-zA-Z0-9.\-_]+)\.s3\.amazonaws\.com',
                r's3\.amazonaws\.com/([a-zA-Z0-9.\-_]+)',
                r'([a-zA-Z0-9.\-_]+)\.s3-[a-z0-9-]+\.amazonaws\.com'
            ],
            'Azure Blob': [
                r'([a-zA-Z0-9]+)\.blob\.core\.windows\.net'
            ],
            'GCP Storage': [
                r'storage\.googleapis\.com/([a-zA-Z0-9.\-_]+)',
                r'([a-zA-Z0-9.\-_]+)\.storage\.googleapis\.com'
            ],
            'DigitalOcean Spaces': [
                r'([a-zA-Z0-9.\-_]+)\.digitaloceanspaces\.com'
            ],
            'Alibaba OSS': [
                r'([a-zA-Z0-9.\-_]+)\.oss-[a-z-]+\.aliyuncs\.com'
            ]
        }
        
        # Metadata endpoints
        self.metadata_endpoints = {
            'AWS': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/dynamic/instance-identity/'
            ],
            'Azure': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
            ],
            'GCP': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/'
            ],
            'Oracle Cloud': [
                'http://169.254.169.254/opc/v1/instance/'
            ],
            'DigitalOcean': [
                'http://169.254.169.254/metadata/v1/'
            ]
        }
        
        # Serverless function patterns
        self.serverless_patterns = {
            'AWS Lambda': [
                r'lambda',
                r'\.lambda-url\..*\.on\.aws',
                r'execute-api\..*\.amazonaws\.com'
            ],
            'Azure Functions': [
                r'azurewebsites\.net/api/',
                r'\.azurewebsites\.net.*function'
            ],
            'Google Cloud Functions': [
                r'cloudfunctions\.net',
                r'\.run\.app'
            ],
            'Cloudflare Workers': [
                r'workers\.dev'
            ],
            'Vercel Serverless': [
                r'vercel\.app/api/'
            ],
            'Netlify Functions': [
                r'netlify\.app/\.netlify/functions/'
            ]
        }
        
        # Environment variable leak patterns
        self.env_leak_patterns = [
            r'AWS_ACCESS_KEY_ID',
            r'AWS_SECRET_ACCESS_KEY',
            r'AZURE_CLIENT_ID',
            r'AZURE_CLIENT_SECRET',
            r'GOOGLE_APPLICATION_CREDENTIALS',
            r'DATABASE_URL',
            r'DB_PASSWORD',
            r'API_KEY',
            r'SECRET_KEY',
            r'PRIVATE_KEY',
            r'GITHUB_TOKEN',
            r'NPM_TOKEN',
            r'SLACK_TOKEN'
        ]
        
        # Infrastructure naming patterns
        self.naming_patterns = {
            'environment': [
                r'(dev|development)',
                r'(staging|stage|stg)',
                r'(prod|production)',
                r'(test|testing|qa)',
                r'(uat|preprod)'
            ],
            'region': [
                r'us-east-1',
                r'us-west-[12]',
                r'eu-west-[123]',
                r'ap-southeast-[12]'
            ],
            'service': [
                r'(api|web|app|db|cache)',
                r'(frontend|backend)',
                r'(master|slave|replica)'
            ]
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
            for line in details.split('\n'):
                if line.strip():
                    print(f"    {Fore.WHITE}{line}{Style.RESET_ALL}")
    
    def fingerprint_cloud_provider(self):
        """Detect cloud provider"""
        self.print_section("Cloud Provider Fingerprinting")
        
        loader = LoadingBar("Analyzing cloud infrastructure")
        loader.start()
        
        detected_providers = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            # Check headers
            for provider, config in self.cloud_providers.items():
                provider_detected = False
                evidence = []
                
                # Check headers
                for header, description in config['headers'].items():
                    if header in response.headers:
                        provider_detected = True
                        evidence.append(f"Header: {header} = {response.headers[header][:50]}")
                
                # Check URL patterns
                for pattern in config['patterns']:
                    if re.search(pattern, self.target_url, re.IGNORECASE):
                        provider_detected = True
                        evidence.append(f"URL Pattern: {pattern}")
                    
                    # Check in response body
                    if re.search(pattern, response.text[:10000], re.IGNORECASE):
                        provider_detected = True
                        evidence.append(f"Body Pattern: {pattern}")
                
                if provider_detected:
                    detected_providers.append({
                        'provider': provider,
                        'evidence': evidence,
                        'confidence': 'HIGH' if len(evidence) > 2 else 'MEDIUM'
                    })
            
            # DNS-based detection
            try:
                dns_records = socket.gethostbyname_ex(self.hostname)
                cname_records = []
                
                try:
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(self.hostname, 'CNAME')
                    cname_records = [str(rdata) for rdata in answers]
                except:
                    pass
                
                for cname in cname_records:
                    for provider, config in self.cloud_providers.items():
                        for pattern in config['patterns']:
                            if re.search(pattern, cname, re.IGNORECASE):
                                if not any(p['provider'] == provider for p in detected_providers):
                                    detected_providers.append({
                                        'provider': provider,
                                        'evidence': [f'CNAME: {cname}'],
                                        'confidence': 'HIGH'
                                    })
            except:
                pass
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Cloud Fingerprinting", "FAIL", str(e))
            return
        
        loader.stop(True)
        
        if detected_providers:
            for detection in detected_providers:
                self.print_check(f"Cloud Provider: {detection['provider']}", 
                               "PASS", 
                               f"Confidence: {detection['confidence']}\nEvidence:\n" + '\n'.join(f"  • {e}" for e in detection['evidence']))
            
            self.results['cloud_provider'] = detected_providers[0]['provider']
            self.results['cloud_indicators'] = detected_providers
        else:
            self.print_check("Cloud Provider", "WARN", "No major cloud provider detected")
    
    def detect_load_balancers(self):
        """Detect load balancers"""
        self.print_section("Load Balancer Identification")
        
        lb_indicators = {
            'AWS ELB': ['X-Amzn-RequestId', 'X-Amzn-Trace-Id'],
            'Azure Load Balancer': ['X-Azure-Ref'],
            'GCP Load Balancer': ['Via.*Google'],
            'HAProxy': ['Server.*HAProxy'],
            'Nginx': ['Server.*nginx', 'X-Nginx'],
            'Apache Traffic Server': ['Server.*ATS'],
            'Varnish': ['Via.*varnish', 'X-Varnish'],
            'Cloudflare': ['Server.*cloudflare', 'CF-RAY']
        }
        
        detected_lbs = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            for lb_type, patterns in lb_indicators.items():
                for pattern in patterns:
                    # Check headers
                    for header, value in response.headers.items():
                        if re.search(pattern, f"{header}.*{value}", re.IGNORECASE):
                            detected_lbs.append({
                                'type': lb_type,
                                'evidence': f"{header}: {value}"
                            })
                            break
            
            if detected_lbs:
                for lb in detected_lbs:
                    self.print_check(f"Load Balancer: {lb['type']}", "PASS", lb['evidence'])
                self.results['infrastructure']['load_balancers'] = detected_lbs
            else:
                self.print_check("Load Balancer", "WARN", "No load balancer detected")
        
        except Exception as e:
            self.print_check("Load Balancer Detection", "FAIL", str(e))
    
    def scan_storage_exposures(self):
        """Detect object storage references"""
        self.print_section("Object Storage Reference Detection")
        
        loader = LoadingBar("Scanning for storage bucket references")
        loader.start()
        
        storage_refs = []
        
        try:
            # Scan main page
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:100000]  # First 100KB
            
            # Check all bucket patterns
            for storage_type, patterns in self.bucket_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    for match in set(matches):
                        bucket_name = match if isinstance(match, str) else match[0] if match else None
                        if bucket_name:
                            storage_refs.append({
                                'type': storage_type,
                                'bucket': bucket_name,
                                'pattern': pattern
                            })
            
            # Scan JavaScript files
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content)
            for js_file in js_files[:10]:  # Limit to 10 files
                try:
                    js_url = urljoin(self.target_url, js_file)
                    js_response = self.session.get(js_url, timeout=5, verify=False)
                    
                    for storage_type, patterns in self.bucket_patterns.items():
                        for pattern in patterns:
                            matches = re.findall(pattern, js_response.text[:50000])
                            for match in set(matches):
                                bucket_name = match if isinstance(match, str) else match[0] if match else None
                                if bucket_name and bucket_name not in [s['bucket'] for s in storage_refs]:
                                    storage_refs.append({
                                        'type': storage_type,
                                        'bucket': bucket_name,
                                        'location': js_file
                                    })
                except:
                    pass
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Storage Scanning", "FAIL", str(e))
            return
        
        loader.stop(True)
        
        if storage_refs:
            self.print_check("Storage References", "FAIL", 
                           f"{len(storage_refs)} bucket reference(s) found")
            
            # Group by type
            by_type = defaultdict(list)
            for ref in storage_refs:
                by_type[ref['type']].append(ref)
            
            for storage_type, refs in by_type.items():
                print(f"\n  {Fore.YELLOW}{storage_type}:{Style.RESET_ALL}")
                for ref in refs[:5]:
                    print(f"    • {ref['bucket']}")
                if len(refs) > 5:
                    print(f"    ... and {len(refs) - 5} more")
            
            self.results['storage_exposures'] = storage_refs
            
            # Check for public bucket access
            self.check_bucket_permissions(storage_refs)
        else:
            self.print_check("Storage References", "PASS", "No bucket references found")
    
    def check_bucket_permissions(self, storage_refs):
        """Check if buckets are publicly accessible"""
        print(f"\n{Fore.CYAN}Checking Bucket Permissions:{Style.RESET_ALL}\n")
        
        for ref in storage_refs[:5]:  # Test first 5
            bucket_name = ref['bucket']
            storage_type = ref['type']
            
            # Test AWS S3
            if storage_type == 'AWS S3':
                test_url = f"https://{bucket_name}.s3.amazonaws.com"
                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    if response.status_code == 200:
                        print(f"{Fore.RED}[!] PUBLIC: {bucket_name}{Style.RESET_ALL}")
                        self.results['security_issues'].append({
                            'severity': 'CRITICAL',
                            'issue': f'Public S3 bucket: {bucket_name}',
                            'impact': 'Data exposure'
                        })
                    elif response.status_code == 403:
                        print(f"{Fore.GREEN}[✓] PRIVATE: {bucket_name}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[?] UNKNOWN: {bucket_name}{Style.RESET_ALL}")
    
    def test_metadata_endpoints(self):
        """Test cloud metadata endpoints"""
        self.print_section("Cloud Metadata Endpoint Detection")
        
        print(f"{Fore.YELLOW}Testing metadata endpoints (SSRF indicators)...{Style.RESET_ALL}\n")
        
        metadata_accessible = []
        
        # Note: We're testing if the application might be vulnerable to SSRF
        # by checking if metadata patterns are referenced
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:50000]
            
            metadata_patterns = [
                r'169\.254\.169\.254',
                r'metadata\.google\.internal',
                r'metadata\.azure\.com'
            ]
            
            for pattern in metadata_patterns:
                if re.search(pattern, content):
                    self.print_check("Metadata Reference", "WARN", 
                                   f"Found reference to: {pattern}")
                    metadata_accessible.append(pattern)
                    
                    self.results['security_issues'].append({
                        'severity': 'HIGH',
                        'issue': f'Metadata endpoint reference: {pattern}',
                        'impact': 'Potential SSRF vulnerability'
                    })
            
            if not metadata_accessible:
                self.print_check("Metadata Endpoints", "PASS", "No metadata references found")
        
        except Exception as e:
            self.print_check("Metadata Testing", "FAIL", str(e))
    
    def analyze_naming_patterns(self):
        """Analyze infrastructure naming patterns"""
        self.print_section("Infrastructure Naming Pattern Analysis")
        
        patterns_found = defaultdict(list)
        
        try:
            # Analyze hostname
            hostname_lower = self.hostname.lower()
            
            for category, patterns in self.naming_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, hostname_lower, re.IGNORECASE)
                    if matches:
                        patterns_found[category].extend(matches)
            
            # Analyze response
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:20000]
            
            for category, patterns in self.naming_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        patterns_found[category].extend(matches)
            
            if patterns_found:
                for category, matches in patterns_found.items():
                    unique_matches = list(set(matches))
                    self.print_check(f"{category.capitalize()} Patterns", "WARN",
                                   f"Found: {', '.join(unique_matches[:5])}")
                
                self.results['infrastructure']['naming_patterns'] = dict(patterns_found)
            else:
                self.print_check("Naming Patterns", "PASS", "No obvious patterns detected")
        
        except Exception as e:
            self.print_check("Naming Analysis", "FAIL", str(e))
    
    def detect_serverless_functions(self):
        """Detect serverless function hints"""
        self.print_section("Serverless Function Detection")
        
        serverless_found = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:50000]
            
            # Check URL
            for platform, patterns in self.serverless_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, self.target_url, re.IGNORECASE):
                        serverless_found.append({
                            'platform': platform,
                            'evidence': f'URL pattern: {pattern}',
                            'location': 'URL'
                        })
            
            # Check headers
            serverless_headers = ['X-Amzn-RequestId', 'X-Azure-Functions', 'Function-Execution-Id']
            for header in serverless_headers:
                if header in response.headers:
                    serverless_found.append({
                        'platform': 'Unknown',
                        'evidence': f'Header: {header}',
                        'location': 'Headers'
                    })
            
            # Check content
            for platform, patterns in self.serverless_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        if not any(s['platform'] == platform for s in serverless_found):
                            serverless_found.append({
                                'platform': platform,
                                'evidence': f'Content pattern: {pattern}',
                                'location': 'Response body'
                            })
            
            if serverless_found:
                for finding in serverless_found:
                    self.print_check(f"Serverless: {finding['platform']}", "PASS", 
                                   finding['evidence'])
                self.results['serverless_hints'] = serverless_found
            else:
                self.print_check("Serverless Functions", "WARN", "No serverless patterns detected")
        
        except Exception as e:
            self.print_check("Serverless Detection", "FAIL", str(e))
    
    def scan_environment_leaks(self):
        """Scan for environment variable exposures"""
        self.print_section("Environment Variable & Config Leak Detection")
        
        loader = LoadingBar("Scanning for environment leaks")
        loader.start()
        
        env_leaks = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:100000]
            
            # Check for environment variable patterns
            for pattern in self.env_leak_patterns:
                matches = re.findall(f'{pattern}[\s=:]+([^\s<>"\']+)', content, re.IGNORECASE)
                for match in matches:
                    env_leaks.append({
                        'variable': pattern,
                        'value': match[:50] + '...' if len(match) > 50 else match,
                        'severity': 'CRITICAL' if 'KEY' in pattern or 'SECRET' in pattern else 'HIGH'
                    })
            
            # Check for common debug endpoints
            debug_endpoints = [
                '/debug', '/.env', '/config.json', '/env.json',
                '/.git/config', '/phpinfo.php', '/server-status',
                '/.env.local', '/.env.production'
            ]
            
            for endpoint in debug_endpoints:
                try:
                    test_url = self.base_url + endpoint
                    debug_response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if debug_response.status_code == 200 and len(debug_response.text) > 100:
                        env_leaks.append({
                            'variable': f'Debug endpoint: {endpoint}',
                            'value': f'Status: {debug_response.status_code}',
                            'severity': 'HIGH'
                        })
                except:
                    pass
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Environment Scan", "FAIL", str(e))
            return
        
        loader.stop(True)
        
        if env_leaks:
            # Group by severity
            critical = [e for e in env_leaks if e['severity'] == 'CRITICAL']
            high = [e for e in env_leaks if e['severity'] == 'HIGH']
            
            if critical:
                self.print_check("CRITICAL Leaks", "FAIL", f"{len(critical)} critical exposure(s)")
                for leak in critical[:3]:
                    print(f"    🔴 {leak['variable']}")
            
            if high:
                self.print_check("HIGH Risk Leaks", "FAIL", f"{len(high)} exposure(s)")
                for leak in high[:3]:
                    print(f"    🟡 {leak['variable']}")
            
            self.results['environment_leaks'] = env_leaks
            
            for leak in env_leaks:
                self.results['security_issues'].append({
                    'severity': leak['severity'],
                    'issue': f"Environment leak: {leak['variable']}",
                    'impact': 'Credential exposure'
                })
        else:
            self.print_check("Environment Leaks", "PASS", "No obvious leaks detected")
    
    def detect_container_orchestration(self):
        """Detect container and orchestration platforms"""
        self.print_section("Container & Orchestration Detection")
        
        detected_platforms = []
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            content = response.text[:50000]
            
            # Check all patterns
            all_patterns = {**self.container_patterns, **self.cicd_patterns, **self.mlops_patterns}
            
            for platform, patterns in all_patterns.items():
                for pattern in patterns:
                    # Check URL
                    if re.search(pattern, self.target_url, re.IGNORECASE):
                        detected_platforms.append({
                            'platform': platform,
                            'evidence': f'URL: {pattern}',
                            'type': self.categorize_platform(platform)
                        })
                        continue
                    
                    # Check headers
                    for header, value in response.headers.items():
                        if re.search(pattern, f"{header}:{value}", re.IGNORECASE):
                            detected_platforms.append({
                                'platform': platform,
                                'evidence': f'Header: {header}',
                                'type': self.categorize_platform(platform)
                            })
                            break
                    
                    # Check content
                    if re.search(pattern, content, re.IGNORECASE):
                        if not any(p['platform'] == platform for p in detected_platforms):
                            detected_platforms.append({
                                'platform': platform,
                                'evidence': f'Content pattern',
                                'type': self.categorize_platform(platform)
                            })
            
            if detected_platforms:
                # Group by type
                by_type = defaultdict(list)
                for p in detected_platforms:
                    by_type[p['type']].append(p)
                
                for ptype, platforms in by_type.items():
                    print(f"\n{Fore.YELLOW}{ptype}:{Style.RESET_ALL}")
                    for p in platforms:
                        self.print_check(p['platform'], "PASS", p['evidence'])
                
                self.results['infrastructure']['platforms'] = detected_platforms
            else:
                self.print_check("Container/Orchestration", "WARN", "No platforms detected")
        
        except Exception as e:
            self.print_check("Platform Detection", "FAIL", str(e))
    
    def categorize_platform(self, platform):
        """Categorize platform type"""
        if platform in self.container_patterns:
            return "Container Platform"
        elif platform in self.cicd_patterns:
            return "CI/CD Platform"
        elif platform in self.mlops_patterns:
            return "MLOps Platform"
        else:
            return "Platform"
    
    def generate_security_summary(self):
        """Generate security summary"""
        self.print_section("Security Issues Summary")
        
        if not self.results['security_issues']:
            print(f"{Fore.GREEN}[✓] No major security issues detected{Style.RESET_ALL}")
            return
        
        # Group by severity
        by_severity = defaultdict(list)
        for issue in self.results['security_issues']:
            by_severity[issue['severity']].append(issue)
        
        print(f"{Fore.RED}Total Issues: {len(self.results['security_issues'])}{Style.RESET_ALL}\n")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            issues = by_severity[severity]
            if issues:
                color = Fore.RED if severity in ['CRITICAL', 'HIGH'] else Fore.YELLOW
                print(f"{color}{severity}: {len(issues)} issue(s){Style.RESET_ALL}")
                for issue in issues[:3]:
                    print(f"  • {issue['issue']}")
                    print(f"    Impact: {issue['impact']}")
                if len(issues) > 3:
                    print(f"  ... and {len(issues) - 3} more")
                print()
    
    def generate_report(self):
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = self.hostname.replace('.', '_')
        filename = f"CloudExposure_{hostname}_{timestamp}.txt"
        
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("CLOUD & HOSTING EXPOSURE ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget: {self.target_url}")
        report.append(f"Date: {self.results['timestamp']}")
        report.append(f"Hostname: {self.hostname}\n")
        report.append("=" * 80)
        
        # Cloud Provider
        if self.results['cloud_provider']:
            report.append(f"\nCloud Provider: {self.results['cloud_provider']}")
            report.append(f"Indicators: {len(self.results['cloud_indicators'])}")
        
        # Storage
        if self.results['storage_exposures']:
            report.append(f"\nStorage Exposures: {len(self.results['storage_exposures'])}")
            for storage in self.results['storage_exposures'][:10]:
                report.append(f"  - {storage['type']}: {storage['bucket']}")
        
        # Security Issues
        if self.results['security_issues']:
            report.append(f"\nSecurity Issues: {len(self.results['security_issues'])}")
            for issue in self.results['security_issues']:
                report.append(f"  [{issue['severity']}] {issue['issue']}")
        
        report.append("\n" + "=" * 80)
        report.append(f"Scan Duration: {(time.time() - self.results['start_time']):.2f}s")
        report.append("=" * 80)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        # JSON report
        json_filepath = filepath.replace('.txt', '.json')
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        return filepath


def run(target_url):
    """Main execution"""
    print(f"\n{Fore.GREEN}[+] Starting Cloud & Hosting Exposure Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    analyzer = CloudExposureAnalyzer(target_url)
    
    stages = [
        ("Cloud Provider Fingerprinting", analyzer.fingerprint_cloud_provider),
        ("Load Balancer Identification", analyzer.detect_load_balancers),
        ("Object Storage Detection", analyzer.scan_storage_exposures),
        ("Metadata Endpoint Detection", analyzer.test_metadata_endpoints),
        ("Naming Pattern Analysis", analyzer.analyze_naming_patterns),
        ("Serverless Function Detection", analyzer.detect_serverless_functions),
        ("Environment Leak Scanning", analyzer.scan_environment_leaks),
        ("Container & Orchestration Detection", analyzer.detect_container_orchestration),
        ("Security Summary", analyzer.generate_security_summary),
    ]
    
    progress = ProgressBar(len(stages))
    
    try:
        for stage_name, stage_func in stages:
            progress.update(stage_name)
            stage_func()
            time.sleep(0.5)
        
        # Generate report
        loader = LoadingBar("Generating report")
        loader.start()
        report_path = analyzer.generate_report()
        loader.stop(True)
        
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[✓] Report: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python cloud.py <target_url>")
