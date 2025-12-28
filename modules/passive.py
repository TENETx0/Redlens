#!/usr/bin/env python3
"""
Passive Reconnaissance Module
Performs comprehensive passive information gathering including WHOIS, DNS enumeration,
subdomain discovery, ASN mapping, certificate transparency, and email security checks.
"""

import requests
import socket
import dns.resolver
import whois
import time
import json
import os
import sys
import re
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style
from threading import Thread
import warnings
import base64
import ssl

# Suppress warnings
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

class PassiveRecon:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc.split(':')[0]
        self.results = {
            'target': target_url,
            'domain': self.domain,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': time.time(),
            'checks': {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common subdomain prefixes for enumeration
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
            'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
            'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
            'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
            'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
            'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2',
            'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway',
            'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios',
            'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql',
            'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail',
            's', 'bbs', 'cs', 'ww', 'mrtg', 'git', 'image', 'director', 'promo', 'alpha',
            'testing', 'sandbox', 'jenkins', 'uat', 'prod', 'production', 'qa', 'development',
            'internal', 'dmz', 'corp', 'api-dev', 'api-staging', 'api-prod', 'vpn1', 'vpn2',
            'ssh', 'sftp', 'jenkins-prod', 'elk', 'grafana', 'prometheus', 'kibana', 'harbor',
            'registry', 'nexus', 'jira', 'confluence', 'gitlab', 'bitbucket', 'github',
            'docker', 'k8s', 'kubernetes', 'rancher', 'openshift', 'aws', 'azure', 'gcp',
            'ftp-admin', 'smtp-relay', 'mail-relay', 'webmail2', 'roundcube', 'squirrelmail',
            'horde', 'zimbra', 'exchange2016', 'exchange2019', 'ews', 'activesync',
            'smtp-out', 'smtp-in', 'pop3s', 'imaps', 'submission',
        ]
        
        # Certificate Transparency log servers
        self.ct_logs = [
            'https://crt.sh/?q=%25.{}&output=json',
            'https://certspotter.com/api/v1/issuances?domain={}&include_subdomains=true&expand=dns_names',
        ]
    
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
    
    def whois_lookup(self):
        """Perform WHOIS information gathering"""
        self.print_section("WHOIS Information Gathering")
        
        loader = LoadingBar("Querying WHOIS database")
        loader.start()
        
        whois_data = {}
        
        try:
            w = whois.whois(self.domain)
            
            # Extract key information
            whois_data = {
                'domain_name': w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0] if w.domain_name else None,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': w.org,
                'country': w.country,
                'registrant_name': getattr(w, 'name', None),
                'registrant_email': getattr(w, 'registrant_email', None),
            }
            
            loader.stop(True)
            
            # Print results
            if whois_data.get('domain_name'):
                self.print_check("Domain Name", "PASS", whois_data['domain_name'])
            
            if whois_data.get('registrar'):
                self.print_check("Registrar", "PASS", whois_data['registrar'])
            
            if whois_data.get('creation_date'):
                self.print_check("Creation Date", "PASS", whois_data['creation_date'])
            
            if whois_data.get('expiration_date'):
                self.print_check("Expiration Date", "PASS", whois_data['expiration_date'])
            
            if whois_data.get('name_servers'):
                ns_list = whois_data['name_servers']
                if isinstance(ns_list, list):
                    self.print_check("Name Servers", "PASS", f"Found {len(ns_list)} server(s)")
                    for ns in ns_list[:5]:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {ns}")
            
            if whois_data.get('status'):
                status_list = whois_data['status']
                if isinstance(status_list, list):
                    self.print_check("Domain Status", "PASS", f"{len(status_list)} status(es)")
                    for status in status_list[:3]:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {status}")
            
        except Exception as e:
            loader.stop(False)
            self.print_check("WHOIS Lookup", "FAIL", str(e)[:100])
            whois_data['error'] = str(e)
        
        self.results['checks']['whois'] = whois_data
        return whois_data
    
    def dns_enumeration(self):
        """Comprehensive DNS record enumeration"""
        self.print_section("DNS Record Enumeration")
        
        loader = LoadingBar("Enumerating DNS records")
        loader.start()
        
        dns_records = {}
        
        # DNS record types to query
        record_types = {
            'A': 'IPv4 Address',
            'AAAA': 'IPv6 Address',
            'MX': 'Mail Exchange',
            'TXT': 'Text Records',
            'NS': 'Name Servers',
            'SOA': 'Start of Authority',
            'CNAME': 'Canonical Name',
            'PTR': 'Pointer Record',
            'SRV': 'Service Record',
            'CAA': 'Certificate Authority Authorization',
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        for record_type, description in record_types.items():
            try:
                answers = resolver.resolve(self.domain, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == 'MX':
                        records.append({
                            'priority': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(rdata.mname),
                            'rname': str(rdata.rname),
                            'serial': rdata.serial,
                            'refresh': rdata.refresh,
                            'retry': rdata.retry,
                            'expire': rdata.expire,
                            'minimum': rdata.minimum,
                        })
                    elif record_type == 'SRV':
                        records.append({
                            'priority': rdata.priority,
                            'weight': rdata.weight,
                            'port': rdata.port,
                            'target': str(rdata.target),
                        })
                    else:
                        records.append(str(rdata))
                
                dns_records[record_type.lower()] = records
                
            except dns.resolver.NoAnswer:
                dns_records[record_type.lower()] = []
            except dns.resolver.NXDOMAIN:
                dns_records[record_type.lower()] = []
            except Exception:
                dns_records[record_type.lower()] = []
        
        loader.stop(True)
        
        # Print results
        for record_type, description in record_types.items():
            records = dns_records.get(record_type.lower(), [])
            if records:
                self.print_check(f"{record_type} Records ({description})", "PASS", f"Found {len(records)} record(s)")
                
                # Print details for important record types
                if record_type == 'A' and len(records) <= 5:
                    for record in records:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {record}")
                
                elif record_type == 'MX' and len(records) <= 5:
                    for record in records:
                        if isinstance(record, dict):
                            print(f"    {Fore.CYAN}→{Style.RESET_ALL} Priority: {record['priority']}, Exchange: {record['exchange']}")
                
                elif record_type == 'NS' and len(records) <= 5:
                    for record in records:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {record}")
                
                elif record_type == 'TXT' and len(records) <= 3:
                    for record in records:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {record[:100]}...")
        
        self.results['checks']['dns_records'] = dns_records
        return dns_records
    
    def subdomain_enumeration(self):
        """Passive subdomain enumeration"""
        self.print_section("Passive Subdomain Enumeration")
        
        loader = LoadingBar(f"Testing {len(self.subdomain_wordlist)} potential subdomains")
        loader.start()
        
        discovered_subdomains = []
        
        for subdomain in self.subdomain_wordlist:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(full_domain)
                discovered_subdomains.append({
                    'subdomain': full_domain,
                    'type': 'dns_bruteforce'
                })
            except socket.gaierror:
                pass
            except Exception:
                pass
        
        loader.stop(True)
        
        # Print results
        self.print_check("Subdomain Discovery", "PASS", f"Found {len(discovered_subdomains)} subdomain(s)")
        
        if discovered_subdomains:
            print(f"\n{Fore.YELLOW}  Discovered Subdomains:{Style.RESET_ALL}")
            for sub in discovered_subdomains[:20]:
                print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {sub['subdomain']}")
            
            if len(discovered_subdomains) > 20:
                print(f"    {Fore.YELLOW}... and {len(discovered_subdomains) - 20} more{Style.RESET_ALL}")
        
        self.results['checks']['subdomains'] = discovered_subdomains
        return discovered_subdomains
    
    def asn_ip_mapping(self):
        """ASN and IP ownership mapping"""
        self.print_section("ASN & IP Ownership Mapping")
        
        loader = LoadingBar("Mapping ASN and IP ownership")
        loader.start()
        
        asn_data = {}
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(self.domain)
            asn_data['ip_address'] = ip_address
            
            # Query IP-API for ASN information (free service)
            response = self.session.get(f'http://ip-api.com/json/{ip_address}', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                asn_data.update({
                    'asn': data.get('as', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'timezone': data.get('timezone', ''),
                    'hosting': data.get('hosting', False),
                })
            
            loader.stop(True)
            
            # Print results
            if asn_data.get('ip_address'):
                self.print_check("IP Address", "PASS", asn_data['ip_address'])
            
            if asn_data.get('asn'):
                self.print_check("ASN", "PASS", asn_data['asn'])
            
            if asn_data.get('isp'):
                self.print_check("ISP/Hosting", "PASS", asn_data['isp'])
            
            if asn_data.get('org'):
                self.print_check("Organization", "PASS", asn_data['org'])
            
            if asn_data.get('country'):
                self.print_check("Location", "PASS", f"{asn_data.get('city', 'Unknown')}, {asn_data.get('region', 'Unknown')}, {asn_data['country']}")
            
            if asn_data.get('hosting'):
                self.print_check("Hosting Provider", "WARN", "IP is identified as hosting/datacenter")
            
        except Exception as e:
            loader.stop(False)
            self.print_check("ASN Mapping", "FAIL", str(e)[:100])
            asn_data['error'] = str(e)
        
        self.results['checks']['asn_mapping'] = asn_data
        return asn_data
    
    def email_security_records(self):
        """Check email security records (SPF, DKIM, DMARC)"""
        self.print_section("Email Security Records")
        
        loader = LoadingBar("Checking SPF, DKIM, and DMARC records")
        loader.start()
        
        email_sec = {
            'spf': None,
            'dmarc': None,
            'dkim': None,
        }
        
        resolver = dns.resolver.Resolver()
        
        try:
            # Check SPF (in TXT records)
            try:
                answers = resolver.resolve(self.domain, 'TXT')
                for rdata in answers:
                    txt_string = str(rdata).strip('"')
                    if txt_string.startswith('v=spf1'):
                        email_sec['spf'] = txt_string
                        break
            except:
                pass
            
            # Check DMARC
            try:
                dmarc_domain = f'_dmarc.{self.domain}'
                answers = resolver.resolve(dmarc_domain, 'TXT')
                for rdata in answers:
                    txt_string = str(rdata).strip('"')
                    if txt_string.startswith('v=DMARC1'):
                        email_sec['dmarc'] = txt_string
                        break
            except:
                pass
            
            # Check common DKIM selectors
            dkim_selectors = ['default', 'google', 'k1', 'dkim', 'mail', 'smtp', 'selector1', 'selector2', 's1', 's2']
            dkim_found = []
            
            for selector in dkim_selectors:
                try:
                    dkim_domain = f'{selector}._domainkey.{self.domain}'
                    answers = resolver.resolve(dkim_domain, 'TXT')
                    for rdata in answers:
                        txt_string = str(rdata).strip('"')
                        if 'v=DKIM1' in txt_string or 'p=' in txt_string:
                            dkim_found.append({
                                'selector': selector,
                                'record': txt_string[:100] + '...' if len(txt_string) > 100 else txt_string
                            })
                            break
                except:
                    pass
            
            if dkim_found:
                email_sec['dkim'] = dkim_found
            
            loader.stop(True)
            
            # Print results
            if email_sec.get('spf'):
                self.print_check("SPF Record", "PASS", email_sec['spf'][:100])
            else:
                self.print_check("SPF Record", "WARN", "Not found")
            
            if email_sec.get('dmarc'):
                self.print_check("DMARC Record", "PASS", email_sec['dmarc'][:100])
            else:
                self.print_check("DMARC Record", "WARN", "Not found")
            
            if email_sec.get('dkim'):
                self.print_check("DKIM Records", "PASS", f"Found {len(email_sec['dkim'])} selector(s)")
                for dkim in email_sec['dkim']:
                    print(f"    {Fore.CYAN}→{Style.RESET_ALL} Selector: {dkim['selector']}")
            else:
                self.print_check("DKIM Records", "WARN", "Not found (checked common selectors)")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Email Security Check", "FAIL", str(e)[:100])
        
        self.results['checks']['email_security'] = email_sec
        return email_sec
    
    def third_party_services(self):
        """Discover third-party services"""
        self.print_section("Third-Party Service Discovery")
        
        loader = LoadingBar("Identifying third-party services")
        loader.start()
        
        services = {
            'cdn': [],
            'analytics': [],
            'email': [],
            'hosting': [],
            'dns': [],
            'other': []
        }
        
        try:
            # Check DNS records for third-party indicators
            dns_records = self.results['checks'].get('dns_records', {})
            
            # CDN indicators in CNAME
            cdn_indicators = {
                'cloudflare': 'Cloudflare',
                'akamai': 'Akamai',
                'fastly': 'Fastly',
                'cloudfront': 'Amazon CloudFront',
                'azureedge': 'Microsoft Azure CDN',
                'cdn77': 'CDN77',
                'stackpath': 'StackPath',
                'bunny': 'BunnyCDN',
            }
            
            cnames = dns_records.get('cname', [])
            for cname in cnames:
                for indicator, service in cdn_indicators.items():
                    if indicator in cname.lower():
                        services['cdn'].append(service)
            
            # Email service indicators in MX
            email_indicators = {
                'google': 'Google Workspace',
                'outlook': 'Microsoft 365',
                'mail.protection.outlook': 'Microsoft 365',
                'amazonses': 'Amazon SES',
                'mailgun': 'Mailgun',
                'sendgrid': 'SendGrid',
                'zoho': 'Zoho Mail',
                'protonmail': 'ProtonMail',
            }
            
            mx_records = dns_records.get('mx', [])
            for mx in mx_records:
                if isinstance(mx, dict):
                    exchange = mx.get('exchange', '').lower()
                    for indicator, service in email_indicators.items():
                        if indicator in exchange:
                            services['email'].append(service)
            
            # DNS service indicators in NS
            dns_indicators = {
                'cloudflare': 'Cloudflare DNS',
                'awsdns': 'Amazon Route 53',
                'azure-dns': 'Azure DNS',
                'nsone': 'NS1',
                'dnsimple': 'DNSimple',
                'afraid': 'FreeDNS',
                'he.net': 'Hurricane Electric',
            }
            
            ns_records = dns_records.get('ns', [])
            for ns in ns_records:
                for indicator, service in dns_indicators.items():
                    if indicator in ns.lower():
                        services['dns'].append(service)
            
            # Check TXT records for verification codes
            txt_records = dns_records.get('txt', [])
            for txt in txt_records:
                txt_lower = txt.lower()
                if 'google-site-verification' in txt_lower:
                    services['analytics'].append('Google Search Console')
                elif 'facebook-domain-verification' in txt_lower:
                    services['other'].append('Facebook Domain Verification')
                elif 'ms=' in txt_lower or 'ms-domain-verification' in txt_lower:
                    services['other'].append('Microsoft Domain Verification')
                elif 'amazonses' in txt_lower:
                    services['email'].append('Amazon SES')
            
            loader.stop(True)
            
            # Print results
            for service_type, service_list in services.items():
                if service_list:
                    unique_services = list(set(service_list))
                    self.print_check(f"{service_type.upper()} Services", "PASS", f"Found {len(unique_services)} service(s)")
                    for service in unique_services:
                        print(f"    {Fore.CYAN}→{Style.RESET_ALL} {service}")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Third-Party Discovery", "FAIL", str(e)[:100])
        
        self.results['checks']['third_party_services'] = services
        return services
    
    def certificate_transparency(self):
        """Certificate Transparency log lookup"""
        self.print_section("Certificate Transparency Log Lookup")
        
        loader = LoadingBar("Querying CT logs for certificates")
        loader.start()
        
        ct_data = {
            'certificates': [],
            'subdomains_from_ct': []
        }
        
        try:
            # Query crt.sh
            url = f'https://crt.sh/?q=%25.{self.domain}&output=json'
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                certs = response.json()
                
                # Extract unique subdomains
                subdomains = set()
                
                for cert in certs[:100]:  # Limit to first 100 certificates
                    name_value = cert.get('name_value', '')
                    common_name = cert.get('common_name', '')
                    
                    # Split by newlines (crt.sh returns multiple names separated by newlines)
                    names = name_value.split('\n') + [common_name]
                    
                    for name in names:
                        name = name.strip()
                        if name and self.domain in name:
                            # Remove wildcards
                            name = name.replace('*.', '')
                            if name not in subdomains:
                                subdomains.add(name)
                    
                    # Store certificate info
                    if len(ct_data['certificates']) < 10:
                        ct_data['certificates'].append({
                            'issuer': cert.get('issuer_name', ''),
                            'common_name': cert.get('common_name', ''),
                            'not_before': cert.get('not_before', ''),
                            'not_after': cert.get('not_after', ''),
                        })
                
                ct_data['subdomains_from_ct'] = list(subdomains)
            
            loader.stop(True)
            
            # Print results
            self.print_check("CT Certificates", "PASS", f"Found {len(ct_data.get('certificates', []))} recent certificate(s)")
            self.print_check("CT Subdomains", "PASS", f"Discovered {len(ct_data.get('subdomains_from_ct', []))} unique subdomain(s)")
            
            if ct_data.get('subdomains_from_ct'):
                print(f"\n{Fore.YELLOW}  Subdomains from CT Logs:{Style.RESET_ALL}")
                for subdomain in sorted(ct_data['subdomains_from_ct'])[:20]:
                    print(f"    {Fore.GREEN}[✓]{Style.RESET_ALL} {subdomain}")
                
                if len(ct_data['subdomains_from_ct']) > 20:
                    print(f"    {Fore.YELLOW}... and {len(ct_data['subdomains_from_ct']) - 20} more{Style.RESET_ALL}")
        
        except Exception as e:
            loader.stop(False)
            self.print_check("Certificate Transparency", "FAIL", str(e)[:100])
            ct_data['error'] = str(e)
        
        self.results['checks']['certificate_transparency'] = ct_data
        return ct_data
    
    def historical_dns_data(self):
        """Check for historical DNS data"""
        self.print_section("Historical DNS Data Analysis")
        
        loader = LoadingBar("Checking historical DNS records")
        loader.start()
        
        historical_data = {
            'note': 'Historical DNS data requires commercial services like SecurityTrails or PassiveTotal',
            'current_vs_whois': {}
        }
        
        try:
            # Compare current DNS with WHOIS name servers
            whois_data = self.results['checks'].get('whois', {})
            dns_data = self.results['checks'].get('dns_records', {})
            
            whois_ns = whois_data.get('name_servers', [])
            current_ns = dns_data.get('ns', [])
            
            if whois_ns and current_ns:
                # Convert to lowercase for comparison
                whois_ns_lower = [ns.lower() for ns in whois_ns if ns]
                current_ns_lower = [ns.lower().rstrip('.') for ns in current_ns if ns]
                
                if set(whois_ns_lower) != set(current_ns_lower):
                    historical_data['current_vs_whois']['difference_detected'] = True
                    historical_data['current_vs_whois']['whois_ns'] = whois_ns_lower
                    historical_data['current_vs_whois']['current_ns'] = current_ns_lower
                else:
                    historical_data['current_vs_whois']['difference_detected'] = False
            
            loader.stop(True)
            
            self.print_check("Historical DNS", "WARN", "Full historical data requires commercial services")
            
            if historical_data['current_vs_whois'].get('difference_detected'):
                self.print_check("NS Record Change", "WARN", "Name servers differ between WHOIS and current DNS")
        
        except Exception as e:
            loader.stop(False)
            historical_data['error'] = str(e)
        
        self.results['checks']['historical_dns'] = historical_data
        return historical_data
    
    def generate_report(self):
        """Generate and save the report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_safe = self.domain.replace('.', '_')
        filename = f"PassiveRecon_{domain_safe}_{timestamp}.txt"
        
        # Get the directory where the script is located
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(script_dir, 'Results')
        
        # Create Results directory if it doesn't exist
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        
        report = []
        report.append("=" * 80)
        report.append("PASSIVE RECONNAISSANCE REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget URL: {self.target_url}")
        report.append(f"Domain: {self.domain}")
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
        report.append("SUMMARY STATISTICS")
        report.append("=" * 80)
        
        # Subdomain stats
        subdomains = self.results['checks'].get('subdomains', [])
        ct_subdomains = self.results['checks'].get('certificate_transparency', {}).get('subdomains_from_ct', [])
        
        report.append(f"\nSubdomain Discovery:")
        report.append(f"  - DNS Bruteforce: {len(subdomains)} subdomain(s)")
        report.append(f"  - Certificate Transparency: {len(ct_subdomains)} subdomain(s)")
        report.append(f"  - Total Unique: {len(set([s['subdomain'] for s in subdomains] + ct_subdomains))}")
        
        # Email security
        email_sec = self.results['checks'].get('email_security', {})
        report.append(f"\nEmail Security:")
        report.append(f"  - SPF: {'Configured' if email_sec.get('spf') else 'Not Found'}")
        report.append(f"  - DMARC: {'Configured' if email_sec.get('dmarc') else 'Not Found'}")
        report.append(f"  - DKIM: {'Configured ({} selectors)'.format(len(email_sec.get('dkim', []))) if email_sec.get('dkim') else 'Not Found'}")
        
        # Third-party services
        services = self.results['checks'].get('third_party_services', {})
        total_services = sum(len(s) for s in services.values())
        report.append(f"\nThird-Party Services:")
        report.append(f"  - Total Services Detected: {total_services}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
        
        return filepath


def run(target_url):
    """Main execution function"""
    print(f"\n{Fore.GREEN}[+] Starting Passive Reconnaissance{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target: {target_url}{Style.RESET_ALL}\n")
    
    recon = PassiveRecon(target_url)
    
    # Define scan stages
    stages = [
        ("WHOIS Information Gathering", recon.whois_lookup),
        ("DNS Record Enumeration", recon.dns_enumeration),
        ("Passive Subdomain Enumeration", recon.subdomain_enumeration),
        ("ASN & IP Ownership Mapping", recon.asn_ip_mapping),
        ("Historical DNS Data Analysis", recon.historical_dns_data),
        ("Email Security Records", recon.email_security_records),
        ("Third-Party Service Discovery", recon.third_party_services),
        ("Certificate Transparency Logs", recon.certificate_transparency),
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
        report_path = recon.generate_report()
        loader.stop(True)
        
        # Final summary
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"  SCAN COMPLETED SUCCESSFULLY")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}[✓] Total Checks Performed: {len(stages)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[✓] Report Location: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
        
        # Additional statistics
        subdomains = recon.results['checks'].get('subdomains', [])
        ct_subs = recon.results['checks'].get('certificate_transparency', {}).get('subdomains_from_ct', [])
        print(f"{Fore.YELLOW}[✓] Total Subdomains Found: {len(subdomains) + len(ct_subs)}{Style.RESET_ALL}")
        
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
        print("Usage: python passive.py <target_url>")
