#!/usr/bin/env python3
"""
SecurityTrails API Multi-Page Scraper - Enhanced Version with Multi-Threading
Optimized for Termux with dynamic cookie loading, 100 threads support, and real-time output saving
Supports multiple keywords, auto page detection, domain extraction, and multi-threading
Now supports: subdomains, reverse IP, reverse MX, reverse email, reverse NS with search terms
CPU-optimized: Only saves TXT files, clears memory every 10 minutes, renews cookies every 10 minutes
Performance optimized for long-running sessions (1+ hours)
API-optimized: Gets page count from first page response (no separate API call)
Enhanced with: Session expiration handling and User-Agent rotation every 10 minutes
"""

import json
import requests
import sys
import time
import os
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import signal
import atexit
from datetime import datetime
import gc
import random

# Global variables for real-time saving (TXT only)
current_domains = set()  # Using set for faster lookups and less memory
saved_domains = set()  # Track what has been saved to avoid duplicates
results_lock = threading.Lock()
output_filename = "securitytrails_results"
save_interval = 30  # Save every 30 seconds
last_save_time = time.time()
worker_count = 1  # Default worker count

# Performance optimization variables
last_cookie_reload_time = time.time()
last_memory_clear_time = time.time()
last_user_agent_change_time = time.time()
cookie_reload_interval = 600  # Reload cookies every 10 minutes (600 seconds)
memory_clear_interval = 600   # Clear memory every 10 minutes (600 seconds)
user_agent_change_interval = 600  # Change User-Agent every 10 minutes (600 seconds)

# Current cookies and User-Agent (for session management)
current_cookies = None
current_user_agent = None

# Failed requests directory
failed_requests_dir = "securitytrailsfailedrequest"

# User-Agent lists for rotation
DESKTOP_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

MOBILE_USER_AGENTS = [
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-S908E) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
]

TERMUX_USER_AGENTS = [
    'Mozilla/5.0 (Linux; Android 10; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Termux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
]

def get_random_user_agent():
    """Get a random User-Agent with preference for Termux agents"""
    # 50% chance for Termux, 30% for mobile, 20% for desktop
    rand = random.random()
    if rand < 0.5:
        return random.choice(TERMUX_USER_AGENTS)
    elif rand < 0.8:
        return random.choice(MOBILE_USER_AGENTS)
    else:
        return random.choice(DESKTOP_USER_AGENTS)

def get_current_user_agent():
    """Get current User-Agent, rotating every 10 minutes"""
    global current_user_agent, last_user_agent_change_time
    
    current_time = time.time()
    
    # Change User-Agent if it's time or if we don't have one
    if not current_user_agent or (current_time - last_user_agent_change_time >= user_agent_change_interval):
        new_user_agent = get_random_user_agent()
        if new_user_agent != current_user_agent:
            current_user_agent = new_user_agent
            last_user_agent_change_time = current_time
            print(f"🔄 User-Agent rotated: {current_user_agent.split(' ')[-1]}")
    
    return current_user_agent

def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n⚠️  Interrupt received. Saving current results...")
    save_current_results()
    print("✅ Results saved. Exiting...")
    sys.exit(0)

def save_current_results():
    """Save current results to TXT file only (no JSON) - append mode, optimized for large files"""
    global current_domains, saved_domains, output_filename
    
    if not current_domains:
        return
    
    with results_lock:
        txt_filename = f"{output_filename}.txt"
        try:
            # Find only new domains that haven't been saved yet
            new_domains = current_domains - saved_domains
            
            if new_domains:
                # Append only new domains to the file
                with open(txt_filename, 'a', encoding='utf-8') as f:
                    for domain in new_domains:
                        f.write(f"{domain}\n")
                
                # Update saved_domains to track what we've saved
                saved_domains.update(new_domains)
                
                new_domains_count = len(new_domains)
                total_domains_count = len(saved_domains)
                print(f"💾 Real-time save: {new_domains_count} new domains added, {total_domains_count} total domains in {txt_filename}")
            else:
                print(f"💾 No new domains to save (all {len(current_domains)} domains already saved)")
                
        except Exception as e:
            print(f"❌ Error saving TXT: {e}")

def initialize_saved_domains():
    """Initialize saved_domains by reading existing file"""
    global saved_domains, output_filename
    
    txt_filename = f"{output_filename}.txt"
    if os.path.exists(txt_filename):
        try:
            with open(txt_filename, 'r', encoding='utf-8') as f:
                saved_domains = set(line.strip() for line in f if line.strip())
            print(f"📁 Loaded {len(saved_domains)} existing domains from {txt_filename}")
        except Exception as e:
            print(f"⚠️  Error reading existing domains: {e}")
            saved_domains = set()
    else:
        saved_domains = set()
        print(f"📁 Creating new output file: {txt_filename}")

def clear_memory():
    """Clear memory and cache to reduce CPU load (but keep accumulated domains)"""
    global last_memory_clear_time
    
    # Force garbage collection
    gc.collect()
    
    # Update last clear time
    last_memory_clear_time = time.time()
    
    print("🧹 Memory cleared (domains preserved)")

def check_performance_optimization():
    """Check if we need to reload cookies, clear memory, or change User-Agent based on time intervals"""
    global last_cookie_reload_time, last_memory_clear_time, last_user_agent_change_time
    global cookie_reload_interval, memory_clear_interval, user_agent_change_interval
    
    current_time = time.time()
    needs_cookie_reload = False
    needs_memory_clear = False
    needs_user_agent_change = False
    
    # Check if it's time to reload cookies (every 10 minutes)
    if current_time - last_cookie_reload_time >= cookie_reload_interval:
        needs_cookie_reload = True
        print(f"⏰ Cookie reload interval reached ({cookie_reload_interval/60:.0f} minutes)")
    
    # Check if it's time to clear memory (every 10 minutes)
    if current_time - last_memory_clear_time >= memory_clear_interval:
        needs_memory_clear = True
        print(f"⏰ Memory clear interval reached ({memory_clear_interval/60:.0f} minutes)")
    
    # Check if it's time to change User-Agent (every 10 minutes)
    if current_time - last_user_agent_change_time >= user_agent_change_interval:
        needs_user_agent_change = True
        print(f"⏰ User-Agent change interval reached ({user_agent_change_interval/60:.0f} minutes)")
    
    return needs_cookie_reload, needs_memory_clear, needs_user_agent_change

def create_failed_requests_dir():
    """Create directory for failed requests if it doesn't exist"""
    if not os.path.exists(failed_requests_dir):
        os.makedirs(failed_requests_dir)
        print(f"📁 Created failed requests directory: {failed_requests_dir}")

def save_failed_response(resource_type, resource_value, attempt, response_data, error_type="total_pages_detection"):
    """Save failed response data to file for debugging"""
    try:
        # Create resource directory (sanitize filename)
        safe_resource = "".join(c for c in resource_value if c.isalnum() or c in ('-', '.', '_')).rstrip()
        resource_dir = os.path.join(failed_requests_dir, safe_resource)
        
        if not os.path.exists(resource_dir):
            os.makedirs(resource_dir)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"retry_{attempt}_{error_type}_{timestamp}.json"
        filepath = os.path.join(resource_dir, filename)
        
        # Prepare data to save
        save_data = {
            "metadata": {
                "resource_type": resource_type,
                "resource_value": resource_value,
                "attempt": attempt,
                "timestamp": datetime.now().isoformat(),
                "error_type": error_type
            },
            "response_data": response_data
        }
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(save_data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Saved failed response to: {filepath}")
        return filepath
        
    except Exception as e:
        print(f"❌ Failed to save failed response: {e}")
        return None

def load_securitytrails_cookie(cookie_file='cookies.json'):
    """Load SecurityTrails cookie from JSON file with retry mechanism"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if not os.path.exists(cookie_file):
                print(f"❌ Cookie file '{cookie_file}' not found")
                return None
            
            with open(cookie_file, 'r') as f:
                cookies_data = json.load(f)
            
            # Find the SecurityTrails cookie
            for cookie in cookies_data:
                if cookie['name'] == 'SecurityTrails':
                    cookies_dict = {cookie['name']: cookie['value']}
                    print(f"✅ SecurityTrails cookie loaded successfully")
                    return cookies_dict
            
            print("❌ SecurityTrails cookie not found in file")
            return None
            
        except FileNotFoundError:
            print(f"❌ Error: Cookie file '{cookie_file}' not found")
            return None
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in cookie file '{cookie_file}'")
            return None
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"⚠️  Error loading cookies (attempt {attempt + 1}/{max_retries}): {e}")
                time.sleep(2)
                continue
            else:
                print(f"❌ Failed to load cookies after {max_retries} attempts: {e}")
                return None
    
    return None

def validate_session(cookies_dict):
    """Validate if the current session is still active"""
    test_url = "https://securitytrails.com/_next/data/0afcffcf/list/apex_domain/example.com.json"
    
    headers = {
        'User-Agent': get_current_user_agent(),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    try:
        response = requests.get(
            test_url,
            params={"page": 1, "domain": "example.com"},
            headers=headers,
            cookies=cookies_dict,
            timeout=10
        )
        
        # Check response for session expiration indicators
        if response.status_code == 401:
            return False
        
        try:
            data = response.json()
            if is_session_expired(data):
                return False
        except:
            pass
            
        return response.status_code == 200
    except:
        return False

def is_session_expired(data):
    """Check if response indicates session expiration"""
    if not data:
        return False
    
    # Check for 401 error in response data
    if 'pageProps' in data:
        page_props = data['pageProps']
        # Check apexDomainData
        if 'apexDomainData' in page_props:
            apex_data = page_props['apexDomainData']
            if apex_data.get('status') == 401 or apex_data.get('error') == 'session_expired':
                return True
        # Check dnsData
        if 'dnsData' in page_props:
            dns_data = page_props['dnsData']
            if dns_data.get('status') == 401 or dns_data.get('error') == 'session_expired':
                return True
    
    return False

def reload_cookies():
    """Reload cookies from cookies.json file with enhanced validation"""
    global last_cookie_reload_time, current_cookies
    
    print("🔄 Reloading cookies from cookies.json...")
    cookies = load_securitytrails_cookie()
    
    if cookies:
        # Validate the new cookies
        if validate_session(cookies):
            current_cookies = cookies
            last_cookie_reload_time = time.time()
            print("✅ Cookies reloaded and validated successfully")
            return cookies
        else:
            print("❌ New cookies are invalid, session still expired")
            return None
    else:
        print("❌ Failed to reload cookies")
        return None

def get_securitytrails_data(resource_type, resource_value, page, cookies_dict, search_term=None, max_retries=5):
    """Fetch data from SecurityTrails API for a specific page and resource type with enhanced session handling"""
    base_url = "https://securitytrails.com"
    
    # Define API paths for different resource types
    api_paths = {
        'subdomain': f"/_next/data/0afcffcf/list/apex_domain/{resource_value}.json",
        'reverse_ip': f"/_next/data/0afcffcf/list/ip/{resource_value}.json",
        'reverse_mx': f"/_next/data/0afcffcf/list/mx/{resource_value}.json",
        'reverse_email': f"/_next/data/0afcffcf/list/email/{resource_value}.json",
        'reverse_ns': f"/_next/data/0afcffcf/list/ns/{resource_value}.json",
        'keyword': f"/_next/data/0afcffcf/list/keyword/{resource_value}.json"
    }
    
    api_path = api_paths.get(resource_type)
    if not api_path:
        print(f"❌ Invalid resource type: {resource_type}")
        return None
    
    # Build parameters based on resource type
    params = {"page": page}
    
    if resource_type == 'subdomain':
        params["domain"] = resource_value
        if search_term:
            params["search"] = search_term
    elif resource_type == 'reverse_ip':
        params["ip"] = resource_value
        if search_term:
            params["search"] = search_term
    elif resource_type == 'reverse_mx':
        params["mx"] = resource_value
        if search_term:
            params["search"] = search_term
    elif resource_type == 'reverse_email':
        params["email"] = resource_value
        if search_term:
            params["search"] = search_term
    elif resource_type == 'reverse_ns':
        params["ns"] = resource_value
        if search_term:
            params["search"] = search_term
    elif resource_type == 'keyword':
        params["keyword"] = resource_value
        if search_term:
            params["search"] = search_term
    
    # Headers with rotating User-Agent
    headers = {
        'User-Agent': get_current_user_agent(),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Origin': base_url,
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    }
    
    # Set correct Referer based on resource type
    if resource_type == 'subdomain':
        headers['Referer'] = f'{base_url}/list/apex_domain/{resource_value}?page={page}'
    else:
        headers['Referer'] = f'{base_url}/list/{resource_type}/{resource_value}?page={page}'
    
    full_url = urljoin(base_url, api_path)
    
    # Retry logic for connection errors and session expiration
    for attempt in range(max_retries):
        try:
            # Make the request with SecurityTrails cookie
            response = requests.get(
                full_url,
                params=params,
                headers=headers,
                cookies=cookies_dict,
                timeout=30
            )
            
            # Check for 401 Unauthorized (session expiration)
            if response.status_code == 401:
                print(f"🔐 401 Unauthorized - Session expired, reloading cookies...")
                new_cookies = reload_cookies()
                if new_cookies:
                    cookies_dict = new_cookies
                    continue  # Retry with new cookies
                else:
                    print("❌ Failed to reload cookies after 401 error")
                    return None
            
            # Check if request was successful
            response.raise_for_status()
            
            data = response.json()
            
            # Check for session expiration in response content
            if is_session_expired(data):
                print(f"🔐 Session expired detected in response, reloading cookies...")
                new_cookies = reload_cookies()
                if new_cookies:
                    cookies_dict = new_cookies
                    continue  # Retry with new cookies
                else:
                    print("❌ Failed to reload cookies after session expiration")
                    return None
            
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print(f"🔐 HTTP 401 - Session expired")
                new_cookies = reload_cookies()
                if new_cookies:
                    cookies_dict = new_cookies
                    continue
                else:
                    print("❌ Failed to reload cookies after HTTP 401")
                    return None
            else:
                print(f"❌ HTTP error for page {page}: {e}")
                return None
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
            if attempt < max_retries - 1:
                print(f"⚠️  Connection error for page {page} (attempt {attempt + 1}/{max_retries}): {e}")
                time.sleep(2)  # Wait 2 seconds before retry
                continue
            else:
                print(f"❌ Failed to connect after {max_retries} attempts for page {page}: {e}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"❌ Error making request for page {page}: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ Error parsing JSON response for page {page}: {e}")
            return None
        except Exception as e:
            print(f"❌ Unexpected error for page {page}: {e}")
            return None
    
    return None

def extract_domains_from_data(data):
    """Extract domain records from API response (optimized for memory and speed)"""
    if not data or 'pageProps' not in data:
        return []
    
    page_props = data['pageProps']
    domains = []
    
    # Check for subdomain response structure (apexDomainData)
    if 'apexDomainData' in page_props and 'data' in page_props['apexDomainData']:
        apex_data = page_props['apexDomainData']['data']
        if 'records' in apex_data:
            for record in apex_data['records']:
                hostname = record.get('hostname', '')
                if hostname and hostname.strip():  # Enhanced validation
                    domains.append(hostname.strip())
    
    # Check for standard response structure (serverResponse)
    elif 'serverResponse' in page_props and 'data' in page_props['serverResponse']:
        server_data = page_props['serverResponse']['data']
        if 'records' in server_data:
            for record in server_data['records']:
                hostname = record.get('hostname', '')
                if hostname and hostname.strip():  # Enhanced validation
                    domains.append(hostname.strip())
    
    return domains

def get_total_pages_from_data(data, resource_type, resource_value):
    """Extract total pages from API response data"""
    if not data or 'pageProps' not in data:
        print(f"⚠️  Could not detect total pages for {resource_type}: {resource_value}, using default 100")
        return 100
    
    page_props = data.get('pageProps', {})
    
    # Check for subdomain response structure (apexDomainData)
    if 'apexDomainData' in page_props and 'data' in page_props['apexDomainData']:
        apex_data = page_props['apexDomainData']['data']
        if 'meta' in apex_data and 'total_pages' in apex_data['meta']:
            total_pages = apex_data['meta']['total_pages']
            # Check if this is a legitimate API limit (limit_reached = true) or actual failure
            if 'limit_reached' in apex_data['meta'] and apex_data['meta']['limit_reached']:
                print(f"✅ Found {total_pages} total pages for {resource_type}: {resource_value} (API limit reached)")
            else:
                print(f"✅ Found {total_pages} total pages for {resource_type}: {resource_value}")
            return total_pages
    
    # Check for standard response structure (serverResponse)
    if 'serverResponse' in page_props and 'data' in page_props['serverResponse']:
        server_data = page_props['serverResponse']['data']
        if 'meta' in server_data and 'total_pages' in server_data['meta']:
            total_pages = server_data['meta']['total_pages']
            # Check if this is a legitimate API limit (limit_reached = true) or actual failure
            if 'limit_reached' in server_data['meta'] and server_data['meta']['limit_reached']:
                print(f"✅ Found {total_pages} total pages for {resource_type}: {resource_value} (API limit reached)")
            else:
                print(f"✅ Found {total_pages} total pages for {resource_type}: {resource_value}")
            return total_pages
    
    print(f"⚠️  Could not detect total pages for {resource_type}: {resource_value}, using default 100")
    return 100

def is_legitimate_100_pages(data):
    """Check if 100 pages is a legitimate API limit or a detection failure"""
    if not data or 'pageProps' not in data:
        return False
    
    page_props = data.get('pageProps', {})
    
    # Check for subdomain response structure (apexDomainData)
    if 'apexDomainData' in page_props and 'data' in page_props['apexDomainData']:
        apex_data = page_props['apexDomainData']['data']
        if 'meta' in apex_data:
            meta = apex_data['meta']
            # If limit_reached is true, then 100 pages is legitimate (API limit)
            if 'limit_reached' in meta and meta['limit_reached']:
                return True
            # If we have records and proper meta data, it's legitimate
            if 'records' in apex_data and len(apex_data['records']) > 0:
                return True
    
    # Check for standard response structure (serverResponse)
    if 'serverResponse' in page_props and 'data' in page_props['serverResponse']:
        server_data = page_props['serverResponse']['data']
        if 'meta' in server_data:
            meta = server_data['meta']
            # If limit_reached is true, then 100 pages is legitimate (API limit)
            if 'limit_reached' in meta and meta['limit_reached']:
                return True
            # If we have records and proper meta data, it's legitimate
            if 'records' in server_data and len(server_data['records']) > 0:
                return True
    
    return False

def get_first_page_with_retry(resource_type, resource_value, cookies, search_term=None, max_retries=10):
    """Get first page data with enhanced session handling and retry mechanism"""
    for attempt in range(max_retries):
        print(f"🔄 Attempt {attempt + 1}/{max_retries} to get first page for {resource_type}: {resource_value}")
        
        # Validate session before making request
        if not validate_session(cookies):
            print("🔐 Session validation failed, reloading cookies...")
            new_cookies = reload_cookies()
            if new_cookies:
                cookies = new_cookies
            else:
                print("❌ Failed to reload cookies, retrying...")
                continue
        
        first_page_data = get_securitytrails_data(resource_type, resource_value, 1, cookies, search_term)
        
        if first_page_data:
            total_pages = get_total_pages_from_data(first_page_data, resource_type, resource_value)
            
            # Check if this is a legitimate 100 pages (API limit) or a detection failure
            if total_pages == 100:
                if is_legitimate_100_pages(first_page_data):
                    print(f"✅ Legitimate 100 pages found for {resource_type}: {resource_value} (API limit)")
                    return first_page_data, total_pages
                else:
                    print(f"⚠️  Got default total pages (100) for {resource_type}: {resource_value}, retrying...")
                    # Save failed response for debugging
                    save_failed_response(resource_type, resource_value, attempt + 1, first_page_data, "total_pages_detection_failed")
            else:
                # We got a non-100 total pages, so it's legitimate
                return first_page_data, total_pages
        else:
            print(f"⚠️  Failed to get first page data for {resource_type}: {resource_value}, retrying...")
            # Save failed response (None data) for debugging
            save_failed_response(resource_type, resource_value, attempt + 1, {"error": "no_data_received"}, "no_data_received")
        
        # Wait before retry (increasing wait time)
        wait_time = 2 * (attempt + 1)  # 2, 4, 6, 8, 10 seconds...
        print(f"⏳ Waiting {wait_time} seconds before retry...")
        time.sleep(wait_time)
    
    # If all retries failed, return None and default pages
    print(f"❌ All {max_retries} retry attempts failed for {resource_type}: {resource_value}")
    return None, 100

def load_resources_from_file(filename):
    """Load resources from a text file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            resources = [line.strip() for line in f if line.strip()]
        print(f"📁 Loaded {len(resources)} resources from {filename}")
        return resources
    except FileNotFoundError:
        print(f"❌ Error: Resources file '{filename}' not found")
        return []
    except Exception as e:
        print(f"❌ Error reading resources file: {e}")
        return []

def load_search_terms_from_file(filename):
    """Load search terms from a text file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            search_terms = [line.strip() for line in f if line.strip()]
        print(f"📁 Loaded {len(search_terms)} search terms from {filename}")
        return search_terms
    except FileNotFoundError:
        print(f"❌ Error: Search terms file '{filename}' not found")
        return []
    except Exception as e:
        print(f"❌ Error reading search terms file: {e}")
        return []

def validate_ip_or_cidr(ip_string):
    """Validate if string is a valid IP address or CIDR notation"""
    try:
        ipaddress.ip_network(ip_string, strict=False)
        return True
    except ValueError:
        return False

def distribute_resources_to_workers(resources, search_terms, worker_count):
    """Distribute resources and search terms among workers"""
    if not resources:
        return []
    
    # Create work items (resource + search_term combinations)
    work_items = []
    
    if search_terms:
        # If search terms exist, create combinations
        for resource in resources:
            for search_term in search_terms:
                work_items.append((resource, search_term))
    else:
        # If no search terms, just resources
        for resource in resources:
            work_items.append((resource, None))
    
    # Distribute work items among workers
    worker_tasks = [[] for _ in range(worker_count)]
    for i, work_item in enumerate(work_items):
        worker_tasks[i % worker_count].append(work_item)
    
    return worker_tasks

def worker_process(worker_id, tasks, resource_type, cookies, thread_count_per_worker):
    """Process tasks assigned to a specific worker with enhanced session handling"""
    global current_domains, last_save_time, current_cookies
    
    print(f"\n{'='*70}")
    print(f"👷 WORKER {worker_id + 1} STARTING - {len(tasks)} tasks assigned")
    print(f"{'='*70}")
    
    worker_domains = set()
    successful_tasks = 0
    failed_tasks = 0
    worker_start_time = time.time()
    
    for i, (resource, search_term) in enumerate(tasks, 1):
        print(f"\n{'='*50}")
        print(f"👷 WORKER {worker_id + 1} - TASK {i}/{len(tasks)}: {resource_type.upper()} - {resource}")
        if search_term:
            print(f"🔍 Search term: {search_term}")
        print(f"{'='*50}")
        
        # Check for performance optimization (cookies, memory, User-Agent)
        needs_cookie_reload, needs_memory_clear, needs_user_agent_change = check_performance_optimization()
        
        # Reload cookies if needed
        if needs_cookie_reload:
            new_cookies = reload_cookies()
            if new_cookies:
                cookies = new_cookies
                current_cookies = new_cookies
                print(f"🔄 Worker {worker_id + 1} using refreshed cookies")
        
        # Change User-Agent if needed
        if needs_user_agent_change:
            # This will automatically update when get_current_user_agent() is called
            print(f"🔄 Worker {worker_id + 1} User-Agent will be updated on next request")
        
        # Clear memory if needed
        if needs_memory_clear:
            clear_memory()
        
        # Always validate session before starting a new task
        if not validate_session(cookies):
            print("🔐 Session validation failed, reloading cookies...")
            new_cookies = reload_cookies()
            if new_cookies:
                cookies = new_cookies
                current_cookies = new_cookies
            else:
                print("❌ Critical: Cannot get valid session, skipping task")
                failed_tasks += 1
                continue
        
        # Get first page with enhanced retry mechanism
        print(f"🔍 Getting first page for {resource_type}: {resource}")
        first_page_data, total_pages = get_first_page_with_retry(resource_type, resource, cookies, search_term)
        
        if not first_page_data:
            print(f"❌ Failed to get first page for {resource_type}: {resource} after retries")
            failed_tasks += 1
            continue
        
        # Extract domains from first page
        first_page_domains = extract_domains_from_data(first_page_data)
        if first_page_domains:
            # Add to worker's local set
            worker_domains.update(first_page_domains)
            
            # Add to global set for real-time saving
            with results_lock:
                current_domains.update(first_page_domains)
            
            print(f"✅ First page: Found {len(first_page_domains)} domains")
            if first_page_domains:
                print(f"   First domain: {first_page_domains[0]}")
                if len(first_page_domains) > 1:
                    print(f"   ... and {len(first_page_domains) - 1} more")
        
        # Prepare arguments for remaining pages (skip page 1 since we already got it)
        page_args = [(resource_type, resource, page, total_pages, cookies, search_term) for page in range(2, total_pages + 1)]
        
        print(f"🚀 Worker {worker_id + 1} starting multi-threaded scraping with {thread_count_per_worker} threads...")
        
        # Use ThreadPoolExecutor for multi-threading
        with ThreadPoolExecutor(max_workers=thread_count_per_worker) as executor:
            # Submit all tasks
            future_to_page = {executor.submit(scrape_page, args): args[2] for args in page_args}
            
            # Collect results as they complete
            for future in as_completed(future_to_page):
                page, domains, success = future.result()
                if success:
                    # Add to worker's local set
                    worker_domains.update(domains)
                    
                    # Add to global set for real-time saving
                    with results_lock:
                        current_domains.update(domains)
                    
                    # Show first few domains from this page (simplified for speed)
                    if domains:
                        print(f"   Found domains: {domains[0]}")
                        if len(domains) > 1:
                            print(f"   ... and {len(domains) - 1} more")
                else:
                    failed_tasks += 1
                
                # Check if it's time to save results
                current_time = time.time()
                if current_time - last_save_time >= save_interval:
                    save_current_results()
                    last_save_time = current_time
        
        successful_tasks += 1
        
        # Note: Memory clearing is now done based on time intervals, not after each task
    
    # Calculate elapsed time
    elapsed_time = time.time() - worker_start_time
    
    # Summary for this worker
    print(f"\n📊 WORKER {worker_id + 1} SUMMARY:")
    print(f"✅ Successful tasks: {successful_tasks}")
    print(f"❌ Failed tasks: {failed_tasks}")
    print(f"🌐 Total domains collected: {len(worker_domains)}")
    print(f"⏱️  Total time: {elapsed_time:.1f} seconds")
    print(f"⚡ Threads used: {thread_count_per_worker}")
    
    return list(worker_domains)

def get_user_input():
    """Get resources, resource type, search terms, input method, thread count, and worker count from user"""
    print("🔍 SecurityTrails API - Enhanced Multi-Page Scraper with Multi-Threading")
    print("🚀 Optimized for Termux with 100 threads support and real-time saving")
    print("⚡ CPU-optimized: Only saves TXT files, clears memory every 10 minutes")
    print("👷 Worker system: Process resources one by one with distributed threads")
    print("🔄 Enhanced with: Session expiration handling and User-Agent rotation")
    print("=" * 70)
    
    # Ask for resource type
    print("📝 Choose resource type:")
    print("1. Subdomains (apex_domain)")
    print("2. Reverse IP")
    print("3. Reverse MX")
    print("4. Reverse Email")
    print("5. Reverse NS")
    print("6. Keyword search (original)")
    
    resource_types = {
        '1': 'subdomain',
        '2': 'reverse_ip',
        '3': 'reverse_mx',
        '4': 'reverse_email',
        '5': 'reverse_ns',
        '6': 'keyword'
    }
    
    while True:
        choice = input("Enter choice (1-6): ").strip()
        if choice in resource_types:
            resource_type = resource_types[choice]
            break
        print("❌ Please enter a number between 1 and 6.")
    
    # Ask for input method
    print("\n📝 Choose input method:")
    print("1. Manual input (type resources one by one)")
    print("2. Text file (load resources from file)")
    
    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice in ['1', '2']:
            break
        print("❌ Please enter 1 or 2.")
    
    resources = []
    
    if choice == '1':
        # Manual input
        print(f"\n🔎 Enter {resource_type} resources (one per line, press Enter twice to finish):")
        while True:
            resource = input(f"{resource_type.replace('_', ' ').title()}: ").strip()
            if not resource:
                if resources:
                    break
                else:
                    print("❌ Please enter at least one resource.")
                    continue
            
            # Validate IP/CIDR for reverse_ip
            if resource_type == 'reverse_ip' and not validate_ip_or_cidr(resource):
                print("❌ Invalid IP address or CIDR notation. Please enter a valid IP (e.g., 192.168.1.1) or CIDR (e.g., 192.168.1.0/24)")
                continue
            
            resources.append(resource)
    else:
        # File input
        while True:
            filename = input(f"📁 Enter {resource_type} resources file path (e.g., resources.txt): ").strip()
            if filename:
                resources = load_resources_from_file(filename)
                if resources:
                    # Validate IPs for reverse_ip
                    if resource_type == 'reverse_ip':
                        invalid_resources = [r for r in resources if not validate_ip_or_cidr(r)]
                        if invalid_resources:
                            print(f"❌ Invalid IP addresses found: {', '.join(invalid_resources)}")
                            print("Please fix the file and try again.")
                            continue
                    break
                else:
                    print("❌ No resources found in file. Please try again.")
            else:
                print("❌ Please enter a valid file path.")
    
    if not resources:
        print("❌ No resources provided. Exiting.")
        return [], [], 1, 1
    
    # Ask for search terms
    print("\n🔍 Search terms (optional):")
    print("1. No search terms")
    print("2. Manual input")
    print("3. Text file")
    
    while True:
        choice = input("Enter choice (1-3): ").strip()
        if choice in ['1', '2', '3']:
            break
        print("❌ Please enter 1, 2, or 3.")
    
    search_terms = []
    
    if choice == '2':
        # Manual search terms
        print("\n🔎 Enter search terms (one per line, press Enter twice to finish):")
        while True:
            term = input("Search term: ").strip()
            if not term:
                if search_terms:
                    break
                else:
                    print("❌ Please enter at least one search term.")
                    continue
            search_terms.append(term)
    elif choice == '3':
        # File search terms
        while True:
            filename = input("📁 Enter search terms file path (e.g., search_terms.txt): ").strip()
            if filename:
                search_terms = load_search_terms_from_file(filename)
                if search_terms:
                    break
                else:
                    print("❌ No search terms found in file. Please try again.")
            else:
                print("❌ Please enter a valid file path.")
    
    # Get worker count
    while True:
        try:
            worker_count = input(f"👷 Enter number of workers (1-50, default 10): ").strip()
            if not worker_count:
                worker_count = 10
            else:
                worker_count = int(worker_count)
            
            if 1 <= worker_count <= 50:
                break
            else:
                print("❌ Worker count must be between 1 and 50.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    # Get thread count per worker
    while True:
        try:
            thread_count = input(f"🧵 Enter number of threads per worker (1-50, default 5): ").strip()
            if not thread_count:
                thread_count = 5
            else:
                thread_count = int(thread_count)
            
            if 1 <= thread_count <= 50:
                break
            else:
                print("❌ Thread count must be between 1 and 50.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    # Get output filename
    output_filename = input("📄 Enter output filename (without extension, default: securitytrails_results): ").strip()
    if not output_filename:
        output_filename = "securitytrails_results"
    
    # Show summary
    print(f"\n📋 SCRAPING SUMMARY:")
    print(f"   Resource type: {resource_type}")
    print(f"   Resources: {', '.join(resources[:3])}{'...' if len(resources) > 3 else ''}")
    print(f"   Total resources: {len(resources)}")
    if search_terms:
        print(f"   Search terms: {', '.join(search_terms[:3])}{'...' if len(search_terms) > 3 else ''}")
        print(f"   Total search terms: {len(search_terms)}")
    else:
        print(f"   Search terms: None")
    print(f"   Workers: {worker_count}")
    print(f"   Threads per worker: {thread_count}")
    print(f"   Total threads: {worker_count * thread_count}")
    print(f"   Output file: {output_filename}.txt (TXT only for CPU optimization)")
    print(f"   Failed requests directory: {failed_requests_dir}/")
    print(f"   Mode: Auto-detect pages for each resource")
    print(f"   ⚡ Real-time saving enabled (TXT only)")
    print(f"   🧹 Memory clearing every 10 minutes (optimized)")
    print(f"   🔄 Dynamic cookie reloading every 10 minutes")
    print(f"   🔄 User-Agent rotation every 10 minutes")
    print(f"   🔐 Session expiration detection and auto-recovery")
    print(f"   👷 Worker system: Resources processed one by one")
    
    confirm = input(f"\n🚀 Start scraping? (y/n, default y): ").strip().lower()
    if confirm in ['n', 'no']:
        print("❌ Scraping cancelled.")
        return [], [], 1, 1
    
    return resources, search_terms, thread_count, resource_type, output_filename, worker_count

def parse_command_line_args():
    """Parse command line arguments"""
    if len(sys.argv) < 2:
        return None, None, 5, None, None, 1
    
    # Show help
    if sys.argv[1] in ['-h', '--help', 'help']:
        print("🔍 SecurityTrails API - Enhanced Multi-Page Scraper with Multi-Threading")
        print("🚀 Optimized for Termux with 100 threads support and real-time saving")
        print("⚡ CPU-optimized: Only saves TXT files, clears memory every 10 minutes")
        print("👷 Worker system: Process resources one by one with distributed threads")
        print("🔄 Enhanced with: Session expiration handling and User-Agent rotation")
        print("=" * 70)
        print("Usage:")
        print("  python securitytrails_multi_page_cli.py (interactive mode)")
        print("  python securitytrails_multi_page_cli.py --resources-file resources.txt --type subdomain")
        print("  python securitytrails_multi_page_cli.py --resources ip1,ip2,ip3 --type reverse_ip")
        print("  python securitytrails_multi_page_cli.py --resources-file resources.txt --search-terms-file terms.txt --type reverse_mx")
        print("\nResource types:")
        print("  subdomain, reverse_ip, reverse_mx, reverse_email, reverse_ns, keyword")
        print("\nExamples:")
        print("  python securitytrails_multi_page_cli.py")
        print("  python securitytrails_multi_page_cli.py --resources-file domains.txt --type subdomain")
        print("  python securitytrails_multi_page_cli.py --resources 192.168.1.1,10.0.0.1 --type reverse_ip --threads 50")
        print("\nFeatures:")
        print("  - Support for subdomains, reverse IP, reverse MX, reverse email, reverse NS")
        print("  - CIDR notation support for IP addresses")
        print("  - Optional search terms for filtering")
        print("  - Auto-detect total pages for each resource")
        print("  - Scrape all available pages")
        print("  - Save results to TXT files only (CPU optimized)")
        print("  - Save failed responses to securitytrailsfailedrequest/ directory")
        print("  - Support multiple resources")
        print("  - Multi-threading support (1-50 threads per worker)")
        print("  - Worker system (1-50 workers)")
        print("  - Dynamic cookie reloading from cookies.json")
        print("  - User-Agent rotation every 10 minutes")
        print("  - Session expiration detection and auto-recovery")
        print("  - Optimized for Termux and mobile devices")
        print("  - Memory clearing every 10 minutes (optimized)")
        return None, None, 5, None, None, 1
    
    # Parse arguments
    resources = []
    search_terms = []
    thread_count = 5  # default threads per worker
    resource_type = None
    output_filename = "securitytrails_results"
    worker_count = 1  # default worker count
    
    if '--resources-file' in sys.argv:
        idx = sys.argv.index('--resources-file')
        if idx + 1 < len(sys.argv):
            filename = sys.argv[idx + 1]
            resources = load_resources_from_file(filename)
    
    elif '--resources' in sys.argv:
        idx = sys.argv.index('--resources')
        if idx + 1 < len(sys.argv):
            resources_str = sys.argv[idx + 1]
            resources = [r.strip() for r in resources_str.split(',') if r.strip()]
    
    # Parse search terms
    if '--search-terms-file' in sys.argv:
        idx = sys.argv.index('--search-terms-file')
        if idx + 1 < len(sys.argv):
            filename = sys.argv[idx + 1]
            search_terms = load_search_terms_from_file(filename)
    
    elif '--search-terms' in sys.argv:
        idx = sys.argv.index('--search-terms')
        if idx + 1 < len(sys.argv):
            terms_str = sys.argv[idx + 1]
            search_terms = [t.strip() for t in terms_str.split(',') if t.strip()]
    
    # Parse resource type
    if '--type' in sys.argv:
        idx = sys.argv.index('--type')
        if idx + 1 < len(sys.argv):
            resource_type = sys.argv[idx + 1]
            valid_types = ['subdomain', 'reverse_ip', 'reverse_mx', 'reverse_email', 'reverse_ns', 'keyword']
            if resource_type not in valid_types:
                print(f"❌ Invalid resource type: {resource_type}")
                print(f"Valid types: {', '.join(valid_types)}")
                return None, None, 5, None, None, 1
    
    # Parse output filename
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_filename = sys.argv[idx + 1]
    
    # Parse worker count
    if '--workers' in sys.argv:
        idx = sys.argv.index('--workers')
        if idx + 1 < len(sys.argv):
            try:
                worker_count = int(sys.argv[idx + 1])
                if not (1 <= worker_count <= 50):
                    print("❌ Worker count must be between 1 and 50. Using default 1.")
                    worker_count = 1
            except ValueError:
                print("❌ Invalid worker count. Using default 1.")
                worker_count = 1
    
    # Parse thread count per worker
    if '--threads' in sys.argv:
        idx = sys.argv.index('--threads')
        if idx + 1 < len(sys.argv):
            try:
                thread_count = int(sys.argv[idx + 1])
                if not (1 <= thread_count <= 50):
                    print("❌ Thread count must be between 1 and 50. Using default 5.")
                    thread_count = 5
            except ValueError:
                print("❌ Invalid thread count. Using default 5.")
                thread_count = 5
    
    return resources, search_terms, thread_count, resource_type, output_filename, worker_count

def scrape_page(args):
    """Scrape a single page (for threading) - optimized for memory"""
    resource_type, resource_value, page, total_pages, cookies, search_term = args
    
    data = get_securitytrails_data(resource_type, resource_value, page, cookies, search_term)
    
    if data:
        domains = extract_domains_from_data(data)
        if domains:
            print(f"✅ Page {page}/{total_pages}: Found {len(domains)} domains")
            return page, domains, True
        else:
            print(f"⚠️  Page {page}/{total_pages}: No domains found")
            return page, [], False
    else:
        print(f"❌ Page {page}/{total_pages}: Failed to fetch data")
        return page, [], False

def main():
    global output_filename, current_cookies, current_user_agent
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)
    atexit.register(save_current_results)
    
    # Create failed requests directory
    create_failed_requests_dir()
    
    # Initialize User-Agent
    current_user_agent = get_random_user_agent()
    print(f"🔄 Initial User-Agent: {current_user_agent.split(' ')[-1]}")
    
    # Try to parse command line arguments first
    resources, search_terms, thread_count, resource_type, output_filename, worker_count = parse_command_line_args()
    
    # If no command line args or help requested, use interactive mode
    if not resources or not resource_type:
        resources, search_terms, thread_count, resource_type, output_filename, worker_count = get_user_input()
        if not resources:
            return
    
    # Initialize saved_domains by reading existing file
    initialize_saved_domains()
    
    print(f"\n✅ Using SecurityTrails cookie")
    print(f"👷 Worker system enabled with {worker_count} workers")
    print(f"🧵 {thread_count} threads per worker (total: {worker_count * thread_count} threads)")
    print(f"⚡ Real-time saving enabled (TXT only, every {save_interval} seconds)")
    print(f"🧹 Memory clearing every {memory_clear_interval/60:.0f} minutes (optimized)")
    print(f"🔄 Dynamic cookie reloading every {cookie_reload_interval/60:.0f} minutes")
    print(f"🔄 User-Agent rotation every {user_agent_change_interval/60:.0f} minutes")
    print(f"🔐 Session expiration detection and auto-recovery")
    print(f"🔄 Smart retry mechanism enabled (only retries on true failures)")
    print(f"💾 Failed responses saved to: {failed_requests_dir}/")
    print(f"⚡ Performance optimization: Reduced memory clearing frequency")
    
    # Load SecurityTrails cookie
    cookies = load_securitytrails_cookie()
    if not cookies:
        print("❌ Failed to load SecurityTrails cookie. Exiting.")
        sys.exit(1)
    
    current_cookies = cookies
    
    # Validate initial session
    if not validate_session(cookies):
        print("❌ Initial session validation failed. Please check your cookies.")
        sys.exit(1)
    
    # Distribute resources and search terms to workers
    worker_tasks = distribute_resources_to_workers(resources, search_terms, worker_count)
    
    if not worker_tasks or all(not tasks for tasks in worker_tasks):
        print("❌ No tasks to process. Exiting.")
        return
    
    # Show worker distribution
    print(f"\n📋 WORKER DISTRIBUTION:")
    for i, tasks in enumerate(worker_tasks):
        print(f"   Worker {i + 1}: {len(tasks)} tasks")
        for resource, search_term in tasks[:3]:  # Show first 3 tasks
            task_desc = f"{resource}"
            if search_term:
                task_desc += f" (search: {search_term})"
            print(f"     - {task_desc}")
        if len(tasks) > 3:
            print(f"     ... and {len(tasks) - 3} more tasks")
    
    # Create a list to hold results from all workers
    all_worker_domains = []
    successful_workers = 0
    failed_workers = 0
    total_start_time = time.time()
    
    # Process tasks using workers
    if worker_count == 1:
        # Single worker - process sequentially
        print(f"\n👷 PROCESSING WITH 1 WORKER")
        for worker_id, tasks in enumerate(worker_tasks):
            if tasks:
                worker_domains = worker_process(worker_id, tasks, resource_type, cookies, thread_count)
                all_worker_domains.extend(worker_domains)
                if worker_domains:
                    successful_workers += 1
                else:
                    failed_workers += 1
    else:
        # Multiple workers - process in parallel
        print(f"\n👷 PROCESSING WITH {worker_count} WORKERS IN PARALLEL")
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            # Submit all worker tasks
            future_to_worker = {executor.submit(worker_process, worker_id, tasks, resource_type, cookies, thread_count): worker_id for worker_id, tasks in enumerate(worker_tasks) if tasks}
            
            # Collect results as they complete
            for future in as_completed(future_to_worker):
                worker_id = future_to_worker[future]
                try:
                    worker_domains = future.result()
                    all_worker_domains.extend(worker_domains)
                    if worker_domains:
                        successful_workers += 1
                    else:
                        failed_workers += 1
                except Exception as e:
                    print(f"❌ Worker {worker_id + 1} failed: {e}")
                    failed_workers += 1
    
    # Final summary
    total_elapsed_time = time.time() - total_start_time
    
    print(f"\n{'='*70}")
    print("🎉 FINAL SCRAPING SUMMARY")
    print(f"{'='*70}")
    print(f"✅ Successful workers: {successful_workers}")
    print(f"❌ Failed workers: {failed_workers}")
    print(f"🌐 Total domains collected: {len(all_worker_domains)}")
    print(f"⏱️  Total time: {total_elapsed_time:.1f} seconds")
    print(f"👷 Workers used: {worker_count}")
    print(f"🧵 Threads per worker: {thread_count}")
    print(f"⚡ Total threads: {worker_count * thread_count}")
    print(f"⚡ Real-time saving enabled (TXT only)")
    print(f"🧹 Memory clearing every {memory_clear_interval/60:.0f} minutes (optimized)")
    print(f"🔄 Dynamic cookie reloading every {cookie_reload_interval/60:.0f} minutes")
    print(f"🔄 User-Agent rotation every {user_agent_change_interval/60:.0f} minutes")
    print(f"🔐 Session expiration detection and auto-recovery")
    print(f"🔄 Smart retry mechanism enabled (only retries on true failures)")
    print(f"💾 Failed responses saved to: {failed_requests_dir}/")
    
    if all_worker_domains:
        # Save final results
        save_current_results()
        
        print(f"\n💾 All data saved:")
        print(f"   - All domains TXT: {output_filename}.txt")
        print(f"   - Failed responses: {failed_requests_dir}/")
    else:
        print("❌ No domains were collected from any worker")
    
    # Final memory cleanup
    print("🧹 Final memory cleanup...")
    clear_memory()

if __name__ == "__main__":
    main()
