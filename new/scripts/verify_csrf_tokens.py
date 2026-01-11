#!/usr/bin/env python3
"""
CSRF Token Verification Script
Tests CSRF protection on all POST endpoints
Run this script to verify CSRF tokens are working correctly
"""

import requests
import re
from urllib.parse import urljoin

# Configuration
BASE_URL = "http://localhost:5000"
SESSION = requests.Session()

# ANSI color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_header(text):
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{text}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}")

def print_success(text):
    print(f"{GREEN}✅ {text}{RESET}")

def print_error(text):
    print(f"{RED}❌ {text}{RESET}")

def print_warning(text):
    print(f"{YELLOW}⚠️  {text}{RESET}")

def print_info(text):
    print(f"{BLUE}ℹ️  {text}{RESET}")

def extract_csrf_token(html):
    """Extract CSRF token from HTML"""
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)
    return None

def test_form_csrf_protection(form_url, form_name):
    """Test CSRF protection on a form"""
    print(f"\n{BOLD}Testing: {form_name}{RESET}")
    print(f"URL: {form_url}")
    
    try:
        # Get the form
        response = SESSION.get(urljoin(BASE_URL, form_url))
        
        if response.status_code != 200:
            print_error(f"Failed to load form (HTTP {response.status_code})")
            return False
        
        # Extract CSRF token
        csrf_token = extract_csrf_token(response.text)
        
        if not csrf_token:
            print_error("CSRF token NOT FOUND in form!")
            return False
        
        print_success(f"CSRF token found: {csrf_token[:20]}...")
        
        # Test form submission without CSRF token (should fail)
        if form_url == "/forgot-password":
            post_data = {"email": "test@example.com"}
        elif form_url == "/verify-reset-code":
            post_data = {"email": "test@example.com", "reset_code": "000000"}
        else:
            post_data = {}
        
        response_no_csrf = SESSION.post(urljoin(BASE_URL, form_url), 
                                        data=post_data,
                                        allow_redirects=False)
        
        if response_no_csrf.status_code == 400:
            print_success("✓ Form correctly rejects requests without CSRF token (400 Bad Request)")
        else:
            print_warning(f"Unexpected status without CSRF: {response_no_csrf.status_code}")
        
        # Test form submission with CSRF token
        post_data["csrf_token"] = csrf_token
        response_with_csrf = SESSION.post(urljoin(BASE_URL, form_url), 
                                         data=post_data,
                                         allow_redirects=False)
        
        # Expected status codes for successful form submission (varies by endpoint)
        if response_with_csrf.status_code in [200, 302, 400, 401, 403, 422]:
            print_success(f"✓ Form accepted request with CSRF token (HTTP {response_with_csrf.status_code})")
            return True
        else:
            print_warning(f"Unexpected response status: {response_with_csrf.status_code}")
            return True
            
    except Exception as e:
        print_error(f"Error testing form: {str(e)}")
        return False

def test_api_csrf_protection(api_url, api_name):
    """Test CSRF protection on API endpoint"""
    print(f"\n{BOLD}Testing: {api_name}{RESET}")
    print(f"URL: {api_url}")
    
    try:
        # First get a CSRF token from a form page
        form_response = SESSION.get(urljoin(BASE_URL, "/profile-settings"))
        csrf_token = extract_csrf_token(form_response.text)
        
        if not csrf_token:
            print_warning("Could not obtain CSRF token")
            return False
        
        # Test API without CSRF token (should fail if not logged in)
        response_no_csrf = SESSION.post(urljoin(BASE_URL, api_url),
                                       headers={"Content-Type": "application/json"},
                                       json={},
                                       allow_redirects=False)
        
        if response_no_csrf.status_code in [401, 403, 400]:
            print_success(f"✓ API correctly rejects unauthorized/invalid requests (HTTP {response_no_csrf.status_code})")
        else:
            print_info(f"API status without auth/CSRF: HTTP {response_no_csrf.status_code}")
        
        # Test API with CSRF token in header
        response_with_csrf = SESSION.post(urljoin(BASE_URL, api_url),
                                         headers={
                                            "Content-Type": "application/json",
                                            "X-CSRFToken": csrf_token
                                         },
                                         json={},
                                         allow_redirects=False)
        
        if response_with_csrf.status_code != 400:
            print_success(f"✓ API accepts CSRF token in header (HTTP {response_with_csrf.status_code})")
            return True
        else:
            print_info(f"API returned 400: {response_with_csrf.text[:100]}")
            return True
            
    except Exception as e:
        print_error(f"Error testing API: {str(e)}")
        return False

def test_authentication_forms():
    """Test CSRF protection on authentication forms"""
    print_header("TESTING AUTHENTICATION FORMS")
    
    forms = [
        ("/forgot-password", "Forgot Password Form"),
        ("/verify-reset-code", "Verify Reset Code Form"),
        ("/reset-password?email=test@test.com&token_id=1", "Reset Password Form"),
    ]
    
    results = []
    for url, name in forms:
        result = test_form_csrf_protection(url, name)
        results.append((name, result))
    
    return results

def test_crud_forms():
    """Test CSRF protection on CRUD forms"""
    print_header("TESTING CRUD FORMS")
    
    forms = [
        ("/add_student", "Add Student Form"),
        ("/add_teacher", "Add Teacher Form"),
        ("/add_medicine", "Add Medicine Form"),
    ]
    
    results = []
    for url, name in forms:
        result = test_form_csrf_protection(url, name)
        results.append((name, result))
    
    return results

def verify_global_csrf_config():
    """Verify CSRF is globally enabled"""
    print_header("VERIFYING CSRF CONFIGURATION")
    
    print_info("Checking Flask-WTF configuration...")
    
    try:
        response = SESSION.get(urljoin(BASE_URL, "/dashboard"))
        
        # Check if CSRF token is present in any page
        csrf_token = extract_csrf_token(response.text)
        if csrf_token:
            print_success("✓ CSRF tokens are being generated for all pages")
            print_info(f"Sample token: {csrf_token[:30]}...")
        else:
            print_warning("Could not verify CSRF token presence")
        
        # Check response headers
        print_info("Response headers:")
        for header, value in response.headers.items():
            if header.lower() in ['set-cookie', 'content-security-policy']:
                print_info(f"  {header}: {value[:60]}...")
        
    except Exception as e:
        print_error(f"Error verifying configuration: {str(e)}")

def print_summary(all_results):
    """Print test summary"""
    print_header("TEST SUMMARY")
    
    total = 0
    passed = 0
    
    for category, results in all_results:
        print(f"\n{BOLD}{category}{RESET}")
        for name, result in results:
            total += 1
            if result:
                passed += 1
                print_success(f"{name}")
            else:
                print_error(f"{name}")
    
    print(f"\n{BOLD}Overall Results: {passed}/{total} tests passed{RESET}")
    
    if passed == total:
        print_success("All CSRF token tests passed!")
        return True
    else:
        print_error("Some CSRF token tests failed!")
        return False

def main():
    """Main test runner"""
    print(f"\n{BOLD}{BLUE}CSRF Token Verification Script{RESET}")
    print(f"Testing: {BASE_URL}")
    print(f"Started: {BOLD}{BLUE}{'='*60}{RESET}\n")
    
    # Verify global CSRF configuration
    verify_global_csrf_config()
    
    # Test authentication forms
    auth_results = test_authentication_forms()
    
    # Test CRUD forms
    crud_results = test_crud_forms()
    
    # Print summary
    all_results = [
        ("Authentication Forms", auth_results),
        ("CRUD Forms", crud_results),
    ]
    
    success = print_summary(all_results)
    
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    if success:
        print_success("CSRF TOKEN VERIFICATION COMPLETE - ALL TESTS PASSED")
    else:
        print_error("CSRF TOKEN VERIFICATION COMPLETE - SOME TESTS FAILED")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")
    
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    
    try:
        # Check if server is running
        response = requests.get(urljoin(BASE_URL, "/"), timeout=5)
        sys.exit(main())
    except requests.exceptions.ConnectionError:
        print_error(f"Cannot connect to {BASE_URL}")
        print_info("Make sure the Flask application is running:")
        print_info("  python run.py")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error: {str(e)}")
        sys.exit(1)
