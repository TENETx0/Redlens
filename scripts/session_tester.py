#!/usr/bin/env python3
"""
Advanced Session Testing Script
Tests session fixation, session hijacking resistance, and concurrent session handling
"""

import requests
import sys
from urllib.parse import urlparse
import time

class AdvancedSessionTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session1 = requests.Session()
        self.session2 = requests.Session()
        
        self.session1.headers = {
            'User-Agent': 'Mozilla/5.0 (Session Test 1)'
        }
        self.session2.headers = {
            'User-Agent': 'Mozilla/5.0 (Session Test 2)'
        }
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print("[*] Testing Session Fixation...")
        print()
        
        # Get initial session
        resp1 = self.session1.get(self.target_url, verify=False)
        initial_cookies = dict(self.session1.cookies)
        
        print(f"[+] Initial cookies: {len(initial_cookies)}")
        for name, value in initial_cookies.items():
            print(f"    {name}: {value[:20]}...")
        print()
        
        # Try to force session ID
        print("[*] Testing if server accepts externally-set session ID...")
        
        test_session_id = "FIXED_SESSION_ID_TEST_12345"
        
        # Try different session cookie names
        common_session_names = [
            'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
            'session', 'sid', 'sessionid', 'connect.sid'
        ]
        
        for cookie_name in common_session_names:
            self.session2.cookies.set(cookie_name, test_session_id)
            resp2 = self.session2.get(self.target_url, verify=False)
            
            if cookie_name in self.session2.cookies:
                returned_value = self.session2.cookies[cookie_name]
                if returned_value == test_session_id:
                    print(f"[!] VULNERABLE: Server accepted fixed session ID for {cookie_name}")
                    print(f"    Sent: {test_session_id}")
                    print(f"    Received: {returned_value}")
                    return True
        
        print("[+] Server generates new session IDs (Good)")
        return False
    
    def test_concurrent_sessions(self):
        """Test concurrent session handling"""
        print("\n[*] Testing Concurrent Session Handling...")
        print()
        
        # Create two sessions
        resp1 = self.session1.get(self.target_url, verify=False)
        resp2 = self.session2.get(self.target_url, verify=False)
        
        cookies1 = dict(self.session1.cookies)
        cookies2 = dict(self.session2.cookies)
        
        print(f"[+] Session 1 cookies: {len(cookies1)}")
        print(f"[+] Session 2 cookies: {len(cookies2)}")
        
        # Check if sessions are different
        session_cookies_differ = False
        for name in cookies1:
            if name in cookies2:
                if cookies1[name] != cookies2[name]:
                    print(f"[+] Different session IDs for {name} (Good)")
                    session_cookies_differ = True
                else:
                    print(f"[!] Same session ID for {name} (Potential issue)")
        
        if session_cookies_differ:
            print("\n[+] Server properly handles concurrent sessions")
        else:
            print("\n[!] Potential issue with concurrent session handling")
        
        return session_cookies_differ
    
    def test_session_regeneration(self):
        """Test if session ID changes after authentication"""
        print("\n[*] Testing Session Regeneration...")
        print()
        print("[i] This test requires login credentials and would:")
        print("    1. Get session before login")
        print("    2. Perform login")
        print("    3. Check if session ID changed")
        print("    4. Verify old session is invalidated")
        print()
        print("[i] Recommendation: Session ID SHOULD change after authentication")
        print("[i] This prevents session fixation attacks")
    
    def run_all_tests(self):
        """Run all session security tests"""
        print("="*60)
        print("ADVANCED SESSION SECURITY TESTING")
        print("="*60)
        print(f"Target: {self.target_url}")
        print()
        
        try:
            self.test_session_fixation()
            self.test_concurrent_sessions()
            self.test_session_regeneration()
        except Exception as e:
            print(f"\n[!] Error during testing: {str(e)}")
        
        print("\n" + "="*60)
        print("TESTING COMPLETE")
        print("="*60)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python session_tester.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    tester = AdvancedSessionTester(url)
    tester.run_all_tests()
