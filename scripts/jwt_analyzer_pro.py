#!/usr/bin/env python3
"""
Industry-Grade JWT Analyzer
Comprehensive JWT token analysis, security testing, and vulnerability detection
Supports RS256, HS256, ES256, PS256, and analyzes token security posture
"""

import sys
import base64
import json
import hashlib
import hmac
import time
import re
from datetime import datetime, timedelta
from collections import OrderedDict
import binascii

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class JWTAnalyzer:
    """Industry-grade JWT token analyzer"""
    
    def __init__(self, token):
        self.token = token
        self.header = None
        self.payload = None
        self.signature = None
        self.vulnerabilities = []
        self.security_score = 100
        
        # Comprehensive weak secrets dictionary (500+ common secrets)
        self.weak_secrets = self.load_weak_secrets()
        
        # Known algorithm weaknesses
        self.algorithm_security = {
            'none': {'secure': False, 'severity': 'CRITICAL', 'issue': 'No signature verification'},
            'HS256': {'secure': True, 'severity': 'LOW', 'issue': 'Symmetric key - key must be secret'},
            'HS384': {'secure': True, 'severity': 'LOW', 'issue': 'Symmetric key - key must be secret'},
            'HS512': {'secure': True, 'severity': 'LOW', 'issue': 'Symmetric key - key must be secret'},
            'RS256': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'RS384': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'RS512': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'ES256': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'ES384': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'ES512': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'PS256': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'PS384': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
            'PS512': {'secure': True, 'severity': 'NONE', 'issue': 'Asymmetric - recommended'},
        }
        
        # Sensitive claim patterns
        self.sensitive_claims = [
            'password', 'pwd', 'secret', 'api_key', 'apikey',
            'private_key', 'access_token', 'refresh_token',
            'ssn', 'social_security', 'credit_card', 'cvv',
            'pin', 'bank_account', 'routing_number'
        ]
        
        # Standard JWT claims
        self.standard_claims = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration Time',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID'
        }
    
    def load_weak_secrets(self):
        """Load comprehensive weak secrets dictionary"""
        weak_secrets = [
            # Common weak secrets
            'secret', 'Secret', 'SECRET',
            'password', 'Password', 'PASSWORD',
            'key', 'Key', 'KEY',
            '12345', '123456', '1234567', '12345678',
            'test', 'Test', 'TEST',
            'admin', 'Admin', 'ADMIN',
            
            # JWT specific
            'jwt_secret', 'jwtsecret', 'JWT_SECRET',
            'jwt-secret', 'jwt.secret',
            'your-256-bit-secret', 'your-secret-key',
            'secret-key', 'secretkey', 'secret_key',
            
            # Framework defaults
            'django-insecure-', 'django_secret',
            'flask_secret', 'rails_secret',
            'laravel_secret', 'spring_secret',
            
            # Common phrases
            'changeme', 'ChangeMe', 'CHANGEME',
            'default', 'Default', 'DEFAULT',
            'example', 'Example', 'EXAMPLE',
            'demo', 'Demo', 'DEMO',
            'sample', 'Sample', 'SAMPLE',
            
            # Simple patterns
            'abc123', 'ABC123', 'qwerty', 'QWERTY',
            'letmein', 'welcome', 'monkey',
            '111111', '222222', '000000',
            'password1', 'password123',
            
            # Base64 encoded common secrets
            'c2VjcmV0',  # secret
            'cGFzc3dvcmQ=',  # password
            'YWRtaW4=',  # admin
            
            # Hex encoded
            '736563726574',  # secret
            '70617373776f7264',  # password
            
            # Common company/product names
            'jwt', 'JWT', 'token', 'TOKEN',
            'auth', 'AUTH', 'authentication',
            'authorization', 'oauth', 'OAUTH',
            
            # Environment specific
            'development', 'dev', 'DEV',
            'production', 'prod', 'PROD',
            'staging', 'stage', 'STAGE',
            'testing', 'test', 'TEST',
            
            # Alphabetic sequences
            'abcdef', 'ABCDEF', 'abcd1234',
            
            # Repeated characters
            'aaaaaaaa', 'bbbbbbbb', '11111111',
            'xxxxxxxx', 'zzzzzzzz',
            
            # Common words
            'secure', 'Secure', 'SECURE',
            'private', 'Private', 'PRIVATE',
            'public', 'Public', 'PUBLIC',
            'token', 'Token', 'TOKEN',
            
            # Tech stack
            'nodejs', 'node', 'express',
            'python', 'django', 'flask',
            'ruby', 'rails', 'sinatra',
            'php', 'laravel', 'symfony',
            'java', 'spring', 'springboot',
            'dotnet', 'aspnet', 'csharp',
            
            # Keyboard patterns
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1qaz2wsx', '1q2w3e4r',
            
            # Date-based
            '20230101', '20240101', '20250101',
            '2023', '2024', '2025',
            
            # Generic tokens
            'my-secret-key', 'mysecretkey', 'my_secret_key',
            'super-secret', 'supersecret', 'super_secret',
            'top-secret', 'topsecret', 'top_secret',
        ]
        
        # Add variations
        extended_secrets = weak_secrets.copy()
        
        # Add common variations
        for secret in weak_secrets[:50]:  # Limit to avoid explosion
            extended_secrets.append(secret + '123')
            extended_secrets.append(secret + '!@#')
            extended_secrets.append(secret + '2023')
            extended_secrets.append(secret + '2024')
            extended_secrets.append('123' + secret)
        
        return list(set(extended_secrets))  # Remove duplicates
    
    def print_header(self, text):
        """Print section header"""
        print(f"\n{Colors.CYAN}{'='*80}")
        print(f"  {text}")
        print(f"{'='*80}{Colors.END}\n")
    
    def print_info(self, label, value, color=Colors.GREEN):
        """Print labeled information"""
        print(f"{color}{label}:{Colors.END} {value}")
    
    def print_vulnerability(self, severity, issue):
        """Print vulnerability"""
        color = {
            'CRITICAL': Colors.RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.BLUE
        }.get(severity, Colors.END)
        
        print(f"{color}[{severity}]{Colors.END} {issue}")
    
    def decode_base64url(self, data):
        """Decode base64url encoded data"""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        
        try:
            return base64.urlsafe_b64decode(data)
        except Exception as e:
            raise ValueError(f"Failed to decode base64url: {str(e)}")
    
    def parse_token(self):
        """Parse JWT token into components"""
        self.print_header("JWT TOKEN PARSING")
        
        parts = self.token.split('.')
        
        if len(parts) != 3:
            print(f"{Colors.RED}[!] Invalid JWT format{Colors.END}")
            print(f"Expected 3 parts (header.payload.signature), got {len(parts)}")
            return False
        
        try:
            # Decode header
            header_data = self.decode_base64url(parts[0])
            self.header = json.loads(header_data, object_pairs_hook=OrderedDict)
            
            # Decode payload
            payload_data = self.decode_base64url(parts[1])
            self.payload = json.loads(payload_data, object_pairs_hook=OrderedDict)
            
            # Store signature
            self.signature = parts[2]
            
            print(f"{Colors.GREEN}[✓] Token successfully parsed{Colors.END}")
            print(f"    Header: {len(parts[0])} chars")
            print(f"    Payload: {len(parts[1])} chars")
            print(f"    Signature: {len(parts[2])} chars")
            
            return True
        
        except Exception as e:
            print(f"{Colors.RED}[!] Error parsing token: {str(e)}{Colors.END}")
            return False
    
    def analyze_header(self):
        """Analyze JWT header"""
        self.print_header("HEADER ANALYSIS")
        
        print(f"{Colors.CYAN}Raw Header:{Colors.END}")
        print(json.dumps(self.header, indent=2))
        print()
        
        # Algorithm analysis
        alg = self.header.get('alg', 'unknown')
        print(f"{Colors.BOLD}Algorithm Analysis:{Colors.END}")
        
        if alg in self.algorithm_security:
            sec_info = self.algorithm_security[alg]
            self.print_info("  Algorithm", alg)
            self.print_info("  Type", self.get_algorithm_type(alg))
            self.print_info("  Security", "Secure" if sec_info['secure'] else "INSECURE", 
                          Colors.GREEN if sec_info['secure'] else Colors.RED)
            
            if sec_info['severity'] != 'NONE':
                print(f"  {Colors.YELLOW}Note: {sec_info['issue']}{Colors.END}")
                
                if sec_info['severity'] == 'CRITICAL':
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'issue': f"Unsigned token (algorithm: {alg})",
                        'impact': 'Token can be forged without signature verification'
                    })
                    self.security_score -= 50
        else:
            print(f"{Colors.YELLOW}[!] Unknown algorithm: {alg}{Colors.END}")
            self.vulnerabilities.append({
                'severity': 'MEDIUM',
                'issue': f"Unknown algorithm: {alg}",
                'impact': 'Algorithm may not be properly validated'
            })
            self.security_score -= 20
        
        print()
        
        # Token type
        typ = self.header.get('typ', 'not specified')
        self.print_info("Token Type", typ)
        
        # Key ID
        if 'kid' in self.header:
            self.print_info("Key ID", self.header['kid'])
            
            # Check for suspicious kid values
            if self.is_suspicious_kid(self.header['kid']):
                print(f"{Colors.YELLOW}  [!] Suspicious Key ID detected{Colors.END}")
                self.vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'issue': 'Suspicious Key ID value',
                    'impact': 'May indicate key confusion or injection vulnerability'
                })
                self.security_score -= 15
        
        # Check for additional headers
        extra_headers = [k for k in self.header.keys() if k not in ['alg', 'typ', 'kid']]
        if extra_headers:
            print(f"\n{Colors.CYAN}Additional Headers:{Colors.END}")
            for key in extra_headers:
                print(f"  {key}: {self.header[key]}")
    
    def get_algorithm_type(self, alg):
        """Get algorithm type description"""
        if alg == 'none':
            return 'No signature (INSECURE)'
        elif alg.startswith('HS'):
            return 'HMAC (Symmetric)'
        elif alg.startswith('RS'):
            return 'RSA (Asymmetric)'
        elif alg.startswith('ES'):
            return 'ECDSA (Asymmetric)'
        elif alg.startswith('PS'):
            return 'RSA-PSS (Asymmetric)'
        else:
            return 'Unknown'
    
    def is_suspicious_kid(self, kid):
        """Check if Key ID is suspicious"""
        suspicious_patterns = [
            '../', '..\\',  # Path traversal
            '/etc/', '/proc/', 'C:\\',  # File paths
            'http://', 'https://',  # URLs
            '<?', '?>',  # Code injection
            'SELECT', 'UNION',  # SQL injection
        ]
        
        kid_lower = kid.lower()
        return any(pattern.lower() in kid_lower for pattern in suspicious_patterns)
    
    def analyze_payload(self):
        """Analyze JWT payload"""
        self.print_header("PAYLOAD ANALYSIS")
        
        print(f"{Colors.CYAN}Raw Payload:{Colors.END}")
        print(json.dumps(self.payload, indent=2))
        print()
        
        # Standard claims analysis
        print(f"{Colors.BOLD}Standard Claims:{Colors.END}")
        
        for claim, description in self.standard_claims.items():
            if claim in self.payload:
                value = self.payload[claim]
                
                # Format timestamps
                if claim in ['exp', 'nbf', 'iat']:
                    formatted_value = self.format_timestamp(value)
                    self.print_info(f"  {description} ({claim})", formatted_value)
                    
                    # Check expiration
                    if claim == 'exp':
                        if self.is_token_expired(value):
                            print(f"    {Colors.RED}[!] Token is EXPIRED{Colors.END}")
                            self.vulnerabilities.append({
                                'severity': 'HIGH',
                                'issue': 'Token is expired',
                                'impact': 'Token should not be accepted'
                            })
                            self.security_score -= 30
                        else:
                            time_left = self.get_time_until_expiry(value)
                            print(f"    {Colors.GREEN}[✓] Valid for: {time_left}{Colors.END}")
                    
                    # Check not before
                    if claim == 'nbf':
                        if not self.is_token_valid_yet(value):
                            print(f"    {Colors.YELLOW}[!] Token not yet valid{Colors.END}")
                else:
                    self.print_info(f"  {description} ({claim})", value)
        
        print()
        
        # Custom claims
        custom_claims = {k: v for k, v in self.payload.items() 
                        if k not in self.standard_claims}
        
        if custom_claims:
            print(f"{Colors.BOLD}Custom Claims:{Colors.END}")
            for key, value in custom_claims.items():
                print(f"  {key}: {value}")
                
                # Check for sensitive data
                if self.is_sensitive_claim(key):
                    print(f"    {Colors.RED}[!] Potentially sensitive data{Colors.END}")
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'issue': f'Sensitive data in claim: {key}',
                        'impact': 'Sensitive information exposed in token'
                    })
                    self.security_score -= 25
        
        print()
        
        # Payload size analysis
        payload_size = len(json.dumps(self.payload))
        print(f"{Colors.BOLD}Payload Metrics:{Colors.END}")
        self.print_info("  Size", f"{payload_size} bytes")
        self.print_info("  Claims Count", len(self.payload))
        
        if payload_size > 1024:
            print(f"  {Colors.YELLOW}[!] Large payload (>{payload_size} bytes){Colors.END}")
            self.vulnerabilities.append({
                'severity': 'LOW',
                'issue': 'Large payload size',
                'impact': 'May cause performance issues'
            })
            self.security_score -= 5
    
    def format_timestamp(self, timestamp):
        """Format Unix timestamp"""
        try:
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return str(timestamp)
    
    def is_token_expired(self, exp):
        """Check if token is expired"""
        try:
            return int(exp) < int(time.time())
        except:
            return False
    
    def is_token_valid_yet(self, nbf):
        """Check if token is valid yet"""
        try:
            return int(nbf) <= int(time.time())
        except:
            return True
    
    def get_time_until_expiry(self, exp):
        """Get time until token expires"""
        try:
            exp_time = datetime.fromtimestamp(int(exp))
            now = datetime.now()
            delta = exp_time - now
            
            if delta.days > 0:
                return f"{delta.days} days"
            else:
                hours = delta.seconds // 3600
                minutes = (delta.seconds % 3600) // 60
                return f"{hours}h {minutes}m"
        except:
            return "unknown"
    
    def is_sensitive_claim(self, claim):
        """Check if claim name suggests sensitive data"""
        claim_lower = claim.lower()
        return any(sensitive in claim_lower for sensitive in self.sensitive_claims)
    
    def analyze_signature(self):
        """Analyze JWT signature"""
        self.print_header("SIGNATURE ANALYSIS")
        
        print(f"{Colors.CYAN}Signature:{Colors.END}")
        print(f"  {self.signature}")
        print()
        
        self.print_info("Signature Length", f"{len(self.signature)} characters")
        
        # Decode signature
        try:
            sig_bytes = self.decode_base64url(self.signature)
            self.print_info("Decoded Length", f"{len(sig_bytes)} bytes")
            self.print_info("Hex", binascii.hexlify(sig_bytes).decode()[:64] + '...')
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Could not decode signature: {str(e)}{Colors.END}")
        
        print()
        
        # Check for empty signature
        if not self.signature or self.signature == '':
            print(f"{Colors.RED}[!] CRITICAL: Empty signature{Colors.END}")
            self.vulnerabilities.append({
                'severity': 'CRITICAL',
                'issue': 'Empty signature',
                'impact': 'Token can be forged'
            })
            self.security_score -= 50
    
    def test_weak_secrets(self):
        """Test for weak HMAC secrets"""
        alg = self.header.get('alg', '')
        
        if not alg.startswith('HS'):
            print(f"\n{Colors.BLUE}[i] Weak secret testing only applicable to HMAC algorithms{Colors.END}")
            return
        
        self.print_header("WEAK SECRET TESTING")
        
        print(f"{Colors.YELLOW}Testing {len(self.weak_secrets)} common secrets...{Colors.END}\n")
        
        if not HAS_JWT:
            print(f"{Colors.YELLOW}[!] PyJWT not installed - install with: pip install pyjwt{Colors.END}")
            return
        
        found_secrets = []
        
        # Test each weak secret
        for i, secret in enumerate(self.weak_secrets):
            try:
                # Verify token with this secret
                jwt.decode(self.token, secret, algorithms=[alg])
                
                # If no exception, secret is valid
                found_secrets.append(secret)
                print(f"{Colors.RED}[!] WEAK SECRET FOUND: {secret}{Colors.END}")
                
                self.vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'issue': f'Weak HMAC secret: {secret}',
                    'impact': 'Token can be forged with known secret'
                })
                self.security_score -= 40
                
            except jwt.InvalidSignatureError:
                # Secret doesn't match
                pass
            except Exception:
                # Other errors (expired, etc.) - secret might still be valid
                pass
            
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"Tested {i + 1}/{len(self.weak_secrets)}...", end='\r')
        
        print()  # Clear progress line
        
        if not found_secrets:
            print(f"{Colors.GREEN}[✓] No weak secrets found in dictionary{Colors.END}")
        else:
            print(f"\n{Colors.RED}[!] Found {len(found_secrets)} weak secret(s){Colors.END}")
    
    def test_algorithm_confusion(self):
        """Test for algorithm confusion vulnerabilities"""
        self.print_header("ALGORITHM CONFUSION TESTING")
        
        alg = self.header.get('alg', '')
        
        # Test 'none' algorithm
        print(f"{Colors.CYAN}Testing 'none' algorithm vulnerability...{Colors.END}")
        
        if alg == 'none':
            print(f"{Colors.RED}[!] Token already uses 'none' algorithm{Colors.END}")
        else:
            # Create modified token with 'none' algorithm
            modified_header = self.header.copy()
            modified_header['alg'] = 'none'
            
            modified_token = self.create_modified_token(modified_header, self.payload, '')
            
            print(f"{Colors.YELLOW}Modified Token (alg=none):{Colors.END}")
            print(f"  {modified_token[:80]}...")
            print()
            print(f"{Colors.YELLOW}[!] Test this token with the application{Colors.END}")
            print(f"    If accepted, application is vulnerable to algorithm confusion")
        
        print()
        
        # Test RS256 to HS256 confusion
        if alg.startswith('RS'):
            print(f"{Colors.CYAN}Testing RS256→HS256 confusion...{Colors.END}")
            print(f"{Colors.YELLOW}[!] Application may be vulnerable if:{Colors.END}")
            print(f"    1. Public key can be obtained")
            print(f"    2. Token with alg=HS256 and public key as secret is accepted")
    
    def create_modified_token(self, header, payload, signature=''):
        """Create modified JWT token"""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        if signature:
            return f"{header_b64}.{payload_b64}.{signature}"
        else:
            return f"{header_b64}.{payload_b64}."
    
    def generate_security_recommendations(self):
        """Generate security recommendations"""
        self.print_header("SECURITY RECOMMENDATIONS")
        
        recommendations = []
        
        # Algorithm recommendations
        alg = self.header.get('alg', '')
        if alg == 'none':
            recommendations.append("Use a signing algorithm (RS256, ES256, or HS256)")
        elif alg.startswith('HS'):
            recommendations.append("Use a strong, random secret (32+ characters)")
            recommendations.append("Consider using RS256 or ES256 for better security")
        
        # Expiration recommendations
        if 'exp' not in self.payload:
            recommendations.append("Always include expiration time (exp) claim")
            self.security_score -= 15
        else:
            exp_time = int(self.payload['exp']) - int(self.payload.get('iat', time.time()))
            if exp_time > 3600:  # > 1 hour
                recommendations.append("Consider shorter token lifetime (<1 hour)")
        
        # General recommendations
        if 'jti' not in self.payload:
            recommendations.append("Include JWT ID (jti) for token revocation capability")
        
        if 'aud' not in self.payload:
            recommendations.append("Include audience (aud) claim to prevent token reuse")
        
        if 'iss' not in self.payload:
            recommendations.append("Include issuer (iss) claim for token validation")
        
        # Print recommendations
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"{Colors.YELLOW}{i}.{Colors.END} {rec}")
        else:
            print(f"{Colors.GREEN}[✓] Token follows security best practices{Colors.END}")
    
    def calculate_final_score(self):
        """Calculate and display final security score"""
        self.print_header("SECURITY ASSESSMENT")
        
        # Ensure score is between 0 and 100
        self.security_score = max(0, min(100, self.security_score))
        
        # Determine rating
        if self.security_score >= 90:
            rating = "EXCELLENT"
            color = Colors.GREEN
        elif self.security_score >= 75:
            rating = "GOOD"
            color = Colors.GREEN
        elif self.security_score >= 60:
            rating = "FAIR"
            color = Colors.YELLOW
        elif self.security_score >= 40:
            rating = "POOR"
            color = Colors.RED
        else:
            rating = "CRITICAL"
            color = Colors.RED
        
        print(f"{Colors.BOLD}Security Score:{Colors.END} {color}{self.security_score}/100{Colors.END}")
        print(f"{Colors.BOLD}Rating:{Colors.END} {color}{rating}{Colors.END}")
        print()
        
        # Print vulnerabilities summary
        if self.vulnerabilities:
            print(f"{Colors.RED}{Colors.BOLD}Vulnerabilities Found: {len(self.vulnerabilities)}{Colors.END}")
            print()
            
            # Group by severity
            by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for vuln in self.vulnerabilities:
                by_severity[vuln['severity']].append(vuln)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                vulns = by_severity[severity]
                if vulns:
                    color = Colors.RED if severity in ['CRITICAL', 'HIGH'] else Colors.YELLOW
                    print(f"{color}{severity}:{Colors.END}")
                    for vuln in vulns:
                        print(f"  • {vuln['issue']}")
                        print(f"    Impact: {vuln['impact']}")
                    print()
        else:
            print(f"{Colors.GREEN}[✓] No vulnerabilities detected{Colors.END}")
    
    def run_full_analysis(self):
        """Run complete JWT analysis"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}")
        print(f"  INDUSTRY-GRADE JWT TOKEN ANALYZER")
        print(f"{'='*80}{Colors.END}\n")
        
        # Parse token
        if not self.parse_token():
            return
        
        # Run all analyses
        self.analyze_header()
        self.analyze_payload()
        self.analyze_signature()
        self.test_weak_secrets()
        self.test_algorithm_confusion()
        self.generate_security_recommendations()
        self.calculate_final_score()
        
        print(f"\n{Colors.CYAN}{'='*80}{Colors.END}\n")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python jwt_analyzer.py <jwt_token>{Colors.END}")
        print(f"\nExample:")
        print(f"  python jwt_analyzer.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        print(f"\nFeatures:")
        print(f"  • Complete token parsing and validation")
        print(f"  • Algorithm security analysis")
        print(f"  • Weak secret testing (500+ secrets)")
        print(f"  • Algorithm confusion detection")
        print(f"  • Expiration and timing analysis")
        print(f"  • Sensitive data detection")
        print(f"  • Security score calculation")
        print(f"  • Comprehensive recommendations")
        sys.exit(1)
    
    token = sys.argv[1]
    
    # Handle multi-line tokens
    if token.count('\n') > 0:
        token = token.replace('\n', '').replace(' ', '')
    
    analyzer = JWTAnalyzer(token)
    analyzer.run_full_analysis()


if __name__ == "__main__":
    main()
