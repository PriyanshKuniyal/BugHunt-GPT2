import json
import re
import time
import requests
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional, Union
import hashlib
import difflib
import numpy as np
from sklearn.ensemble import IsolationForest
import tensorflow as tf
import argparse
import logging
from datetime import datetime
import socket
import dns.resolver
import ssl
import xml.etree.ElementTree as ET
import html
import zlib
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('burp_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AdvancedBurpScanner:
    def __init__(self, base_url: str, config: Dict = None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.start_time = time.time()
        
        # Default configuration with extensive options
        self.config = {
            'general': {
                'max_depth': 5,
                'threads': 15,
                'rate_limit': 0.3,  # seconds between requests
                'timeout': 15,  # request timeout in seconds
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'follow_redirects': True,
                'max_redirects': 5,
                'scan_speed': 'medium',  # slow/medium/fast
                'verify_ssl': False,
                'proxy': None,  # {'http': 'http://proxy:port', 'https': 'https://proxy:port'}
            },
            'scan_types': {
                'sqli': True,
                'xss': True,
                'rce': True,
                'idor': True,
                'ssrf': True,
                'xxe': True,
                'api': True,
                'csrf': True,
                'lfi': True,
                'ssti': True,
                'open_redirect': True,
                'cors': True,
                'jwt': True,
                'clickjacking': True,
                'header_security': True,
                'info_disclosure': True,
                'business_logic': True,
                'graphql': True,
                'websockets': True,
                'dns': True,
                'ssl_tls': True,
                'port_scan': False,
                'subdomain': False
            },
            'aggressiveness': {
                'level': 'medium',  # low/medium/high/extreme
                'fuzz_params': True,
                'fuzz_headers': True,
                'fuzz_cookies': True
            },
            'authentication': {
                'enabled': False,
                'type': 'basic',  # basic/bearer/form/cookie
                'credentials': None,
                'login_url': None,
                'logout_url': None,
                'csrf_token_loc': None
            },
            'reporting': {
                'format': 'json',  # json/html/markdown
                'output_file': 'scan_report.json',
                'verbose': True,
                'confidence_threshold': 0.8  # ML confidence threshold
            },
            'custom_payloads': {
                'enabled': False,
                'file_path': None
            },
            'advanced': {
                'ml_enabled': True,
                'anomaly_detection': True,
                'behavior_analysis': True,
                'fuzzing': True,
                'parallel_scanning': True
            }
        }
        
        # Merge user-provided config
        if config:
            self._deep_update(self.config, config)
        
        # Adjust settings based on scan speed
        self._adjust_for_scan_speed()
        
        # State tracking
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.graphql_endpoints: Set[str] = set()
        self.websocket_endpoints: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = self._init_session()
        self.fingerprints = set()
        self.executor = ThreadPoolExecutor(max_workers=self.config['general']['threads'])
        self.auth_state = {}  # Stores authentication state
        
        # Initialize ML models if enabled
        if self.config['advanced']['ml_enabled']:
            self._init_ml_models()
        
        # Load payloads
        self.payloads = self._load_advanced_payloads()
        
        # If authentication is enabled, authenticate
        if self.config['authentication']['enabled']:
            self._authenticate()
    
    def _deep_update(self, original, update):
        """Recursively update a nested dictionary"""
        for key, value in update.items():
            if isinstance(value, dict) and key in original:
                self._deep_update(original[key], value)
            else:
                original[key] = value
    
    def _adjust_for_scan_speed(self):
        """Adjust configuration based on scan speed setting"""
        speed = self.config['general']['scan_speed'].lower()
        if speed == 'slow':
            self.config['general']['rate_limit'] = 1.0
            self.config['general']['threads'] = 5
        elif speed == 'medium':
            self.config['general']['rate_limit'] = 0.3
            self.config['general']['threads'] = 15
        elif speed == 'fast':
            self.config['general']['rate_limit'] = 0.1
            self.config['general']['threads'] = 30
    
    def _init_session(self):
        """Configure HTTP session with advanced settings"""
        session = requests.Session()
        
        # Configure headers
        headers = {
            'User-Agent': self.config['general']['user_agent'],
            'X-Scanner': 'AdvancedBurpScanner/3.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        session.headers.update(headers)
        
        # Configure cookies
        session.cookies.set('scanner_session', hashlib.sha256(str(time.time()).encode()).hexdigest())
        
        # SSL verification
        session.verify = self.config['general']['verify_ssl']
        
        # Redirect configuration
        session.max_redirects = self.config['general']['max_redirects']
        
        # Proxy configuration
        if self.config['general']['proxy']:
            session.proxies.update(self.config['general']['proxy'])
        
        # Rate limiting
        original_request = session.request
        def rate_limited_request(*args, **kwargs):
            time.sleep(self.config['general']['rate_limit'])
            return original_request(*args, **kwargs)
        session.request = rate_limited_request
        
        return session
    
    def _init_ml_models(self):
        """Initialize machine learning models for vulnerability detection"""
        try:
            # Placeholder for actual model loading
            # In a real implementation, these would be pre-trained models
            self.xss_model = tf.keras.Sequential([tf.keras.layers.Dense(1)])
            self.sqli_model = tf.keras.Sequential([tf.keras.layers.Dense(1)])
            self.rce_model = tf.keras.Sequential([tf.keras.layers.Dense(1)])
            self.ssti_model = tf.keras.Sequential([tf.keras.layers.Dense(1)])
            
            logger.info("Machine learning models initialized")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {str(e)}")
            self.config['advanced']['ml_enabled'] = False
    
    def _load_advanced_payloads(self):
        """Load intelligent payloads from database or file"""
        payloads = {
            'sqli': [
                "' OR 1=1-- -",
                "' UNION SELECT null,username,password FROM users-- -",
                "1 AND EXTRACTVALUE(1,CONCAT(0x5c,USER()))",
                "1; WAITFOR DELAY '0:0:10'--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))--"
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "${alert(1)}",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>'
            ],
            'ssrf': [
                "http://169.254.169.254/latest/meta-data/",
                "http://internal.service",
                "http://localhost/admin",
                "http://127.0.0.1:8080"
            ],
            'idor': [
                "/api/user/12345/profile",
                "/admin/export?user_id=*",
                "/download?file=../../etc/passwd"
            ],
            'rce': [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                "{{7*7}}",
                "<%= 7*7 %>"
            ],
            'lfi': [
                "../../../../etc/passwd",
                "....//....//etc/passwd",
                "%2e%2e%2fetc%2fpasswd",
                "file:///etc/passwd"
            ],
            'ssti': [
                "{{7*'7'}}",
                "<%= 7*7 %>",
                "${7*7}",
                "#{7*7}",
                "${{7*7}}"
            ],
            'open_redirect': [
                "https://google.com",
                "http://evil.com",
                "//evil.com",
                "/\x0d\x0aLocation: http://evil.com"
            ],
            'csrf': [
                "<script>document.write('<form action=\"http://target.com/transfer\" method=\"POST\"><input type=\"hidden\" name=\"amount\" value=\"1000\"><input type=\"hidden\" name=\"to\" value=\"attacker\"></form>');document.forms[0].submit();</script>"
            ],
            'cors': [
                "Origin: https://evil.com",
                "Origin: null"
            ],
            'jwt': [
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            ],
            'graphql': [
                '{"query":"query { __schema { types { name fields { name } } } }"}',
                '{"query":"mutation { deleteUser(id: 1) { id } }"}'
            ],
            'websockets': [
                '{"type":"subscribe","channel":"private"}'
            ]
        }
        
        # Load custom payloads if enabled
        if self.config['custom_payloads']['enabled'] and self.config['custom_payloads']['file_path']:
            try:
                with open(self.config['custom_payloads']['file_path'], 'r') as f:
                    custom_payloads = json.load(f)
                    for vuln_type, vuln_payloads in custom_payloads.items():
                        if vuln_type in payloads:
                            payloads[vuln_type].extend(vuln_payloads)
                        else:
                            payloads[vuln_type] = vuln_payloads
                logger.info(f"Loaded custom payloads from {self.config['custom_payloads']['file_path']}")
            except Exception as e:
                logger.error(f"Failed to load custom payloads: {str(e)}")
        
        return payloads
    
    def _authenticate(self):
        """Handle authentication based on configuration"""
        auth_type = self.config['authentication']['type'].lower()
        credentials = self.config['authentication']['credentials']
        
        if not credentials:
            logger.error("Authentication enabled but no credentials provided")
            return
        
        try:
            if auth_type == 'basic':
                # Basic auth
                self.session.auth = (credentials.get('username'), credentials.get('password'))
                logger.info("Basic authentication configured")
            
            elif auth_type == 'bearer':
                # Bearer token
                self.session.headers['Authorization'] = f"Bearer {credentials.get('token')}"
                logger.info("Bearer token authentication configured")
            
            elif auth_type == 'form':
                # Form-based auth
                login_url = self.config['authentication']['login_url']
                if not login_url:
                    logger.error("Form authentication requires login_url")
                    return
                
                login_data = {
                    credentials.get('username_field', 'username'): credentials.get('username'),
                    credentials.get('password_field', 'password'): credentials.get('password')
                }
                
                # Handle CSRF token if needed
                if self.config['authentication']['csrf_token_loc']:
                    csrf_loc = self.config['authentication']['csrf_token_loc']
                    login_page = self.session.get(login_url)
                    
                    if csrf_loc.startswith('name='):
                        csrf_name = csrf_loc[5:]
                        soup = BeautifulSoup(login_page.text, 'html.parser')
                        csrf_token = soup.find('input', {'name': csrf_name}).get('value', '')
                    elif csrf_loc.startswith('header='):
                        csrf_header = csrf_loc[7:]
                        csrf_token = login_page.headers.get(csrf_header, '')
                    
                    login_data[csrf_name] = csrf_token
                
                # Perform login
                response = self.session.post(login_url, data=login_data)
                if response.status_code == 200:
                    logger.info("Form authentication successful")
                    self.auth_state['authenticated'] = True
                else:
                    logger.error(f"Form authentication failed with status {response.status_code}")
            
            elif auth_type == 'cookie':
                # Cookie-based auth
                for cookie_name, cookie_value in credentials.items():
                    self.session.cookies.set(cookie_name, cookie_value)
                logger.info("Cookie authentication configured")
            
            else:
                logger.error(f"Unsupported authentication type: {auth_type}")
        
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
    
    def crawl(self, url: str, depth: int = 0) -> None:
        """Advanced recursive crawler with AJAX/API discovery"""
        if depth > self.config['general']['max_depth'] or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        logger.info(f"Crawling ({depth}): {url}")
        
        try:
            # Fetch page with error handling
            response = self._safe_request('GET', url)
            if not response:
                return
            
            # Skip binary content
            if response.headers.get('Content-Type', '').startswith(('image/', 'video/', 'audio/', 'application/octet-stream')):
                return
            
            # Check for compressed content
            content = self._decompress_content(response)
            
            # Content hash for duplicate detection
            content_hash = hashlib.sha256(content).hexdigest()
            if content_hash in self.fingerprints:
                return
            self.fingerprints.add(content_hash)
            
            # Passive analysis
            self._passive_scan(url, response)
            
            # Parse content
            soup = BeautifulSoup(content, 'html.parser')
            
            # Discover traditional links
            for link in soup.find_all(['a', 'link'], href=True):
                self._process_link(url, link['href'])
                
            # Discover JavaScript/AJAX endpoints
            for script in soup.find_all('script'):
                self._find_js_endpoints(script.text, url)
                
            # Discover forms
            for form in soup.find_all('form'):
                self._process_form(form, url)
                
            # Discover API endpoints
            self._find_api_endpoints(content.decode('utf-8', errors='ignore'), url)
            
            # Discover GraphQL endpoints
            self._find_graphql_endpoints(content.decode('utf-8', errors='ignore'), url)
            
            # Discover WebSocket endpoints
            self._find_websocket_endpoints(content.decode('utf-8', errors='ignore'), url)
            
            # Discover comments and metadata
            self._find_info_disclosure(soup, url)
            
            # DNS and subdomain discovery if enabled
            if self.config['scan_types']['dns']:
                self._dns_scan(url)
            
            if self.config['scan_types']['subdomain']:
                self._subdomain_scan()
            
            # SSL/TLS scan if enabled
            if self.config['scan_types']['ssl_tls']:
                self._ssl_scan(url)
            
        except Exception as e:
            logger.error(f"Crawl error on {url}: {str(e)}")
    
    def _safe_request(self, method: str, url: str, **kwargs):
        """Make HTTP request with error handling"""
        try:
            kwargs.setdefault('timeout', self.config['general']['timeout'])
            response = self.session.request(method, url, **kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 10))
                logger.warning(f"Rate limited, waiting {retry_after} seconds")
                time.sleep(retry_after)
                return self._safe_request(method, url, **kwargs)
            
            return response
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {url}: {str(e)}")
            return None
    
    def _decompress_content(self, response):
        """Handle compressed content"""
        if response.headers.get('Content-Encoding') == 'gzip':
            return zlib.decompress(response.content, 16 + zlib.MAX_WBITS)
        elif response.headers.get('Content-Encoding') == 'deflate':
            return zlib.decompress(response.content)
        return response.content
    
    def _process_link(self, base_url: str, href: str):
        """Process discovered links"""
        absolute_url = urljoin(base_url, href)
        if self.domain in urlparse(absolute_url).netloc and not absolute_url.startswith(('mailto:', 'tel:', 'javascript:')):
            self.discovered_endpoints.add(absolute_url)
            self.executor.submit(self.crawl, absolute_url, depth + 1)
    
    def _find_js_endpoints(self, js_code: str, base_url: str):
        """Find AJAX/API endpoints in JavaScript"""
        patterns = [
            r'fetch\("([^"]+)"\)',
            r'\.get\("([^"]+)"\)',
            r'\.post\("([^"]+)"\)',
            r'api\.([a-z]+)\("([^"]+)"\)',
            r'url:\s*["\']([^"\']+)["\']',
            r'ajax\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, js_code):
                endpoint = urljoin(base_url, match.group(1))
                if self.domain in urlparse(endpoint).netloc:
                    self.api_endpoints.add(endpoint)
                    self._test_api_endpoint(endpoint)
    
    def _process_form(self, form, base_url: str):
        """Analyze and test HTML forms"""
        form_details = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': [],
            'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
            'attributes': dict(form.attrs)
        }
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            form_details['inputs'].append({
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name', ''),
                'value': input_tag.get('value', ''),
                'attributes': dict(input_tag.attrs)
            })
        
        # Test for CSRF vulnerabilities
        if self.config['scan_types']['csrf']:
            self._test_csrf(form_details)
        
        # Test the form for all enabled vulnerability types
        self._test_form(form_details)
    
    def _find_api_endpoints(self, text: str, base_url: str):
        """Discover API endpoints in JSON/JS content"""
        patterns = [
            r'"endpoint"\s*:\s*"([^"]+)"',
            r'"url"\s*:\s*"([^"]+)"',
            r'/api/v\d+/\w+',
            r'https?://[^"]+\.json',
            r'https?://[^"]+/rest/\w+',
            r'https?://[^"]+/graphql'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                endpoint = urljoin(base_url, match.group(1 if match.groups() else 0))
                if self.domain in urlparse(endpoint).netloc:
                    self.api_endpoints.add(endpoint)
                    self._test_api_endpoint(endpoint)
    
    def _find_graphql_endpoints(self, text: str, base_url: str):
        """Discover GraphQL endpoints"""
        if not self.config['scan_types']['graphql']:
            return
        
        patterns = [
            r'/graphql',
            r'/graphiql',
            r'/playground',
            r'GraphQLURL\s*:\s*["\']([^"\']+)["\']',
            r'graphqlEndpoint\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                endpoint = urljoin(base_url, match.group(1 if match.groups() else 0))
                if self.domain in urlparse(endpoint).netloc:
                    self.graphql_endpoints.add(endpoint)
                    self._test_graphql_endpoint(endpoint)
    
    def _find_websocket_endpoints(self, text: str, base_url: str):
        """Discover WebSocket endpoints"""
        if not self.config['scan_types']['websockets']:
            return
        
        patterns = [
            r'ws[s]?://[^"\'\s]+',
            r'new WebSocket\("([^"]+)"\)',
            r'WebSocketURL\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                endpoint = urljoin(base_url, match.group(1 if match.groups() else 0))
                if self.domain in urlparse(endpoint).netloc:
                    self.websocket_endpoints.add(endpoint)
                    self._test_websocket_endpoint(endpoint)
    
    def _find_info_disclosure(self, soup, url: str):
        """Find information disclosure in comments and metadata"""
        if not self.config['scan_types']['info_disclosure']:
            return
        
        # Check HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--')):
            sensitive_keywords = [
                'password', 'secret', 'key', 'api', 'token',
                'internal', 'test', 'debug', 'backup', 'admin'
            ]
            
            for keyword in sensitive_keywords:
                if keyword in comment.lower():
                    self._log_vulnerability(
                        url=url,
                        type="Information Disclosure",
                        severity="Medium",
                        description=f"Sensitive keyword '{keyword}' found in HTML comment",
                        evidence=comment.strip()[:100] + "..." if len(comment) > 100 else comment.strip()
                    )
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            
            if name in ('generator', 'author', 'copyright'):
                self._log_vulnerability(
                    url=url,
                    type="Information Disclosure",
                    severity="Low",
                    description=f"Potential information disclosure in meta tag: {name}",
                    evidence=content[:200]
                )
    
    def _dns_scan(self, url: str):
        """Perform basic DNS reconnaissance"""
        try:
            domain = urlparse(url).netloc
            if ':' in domain:  # Remove port if present
                domain = domain.split(':')[0]
            
            # Check for DNS zone transfers
            try:
                answers = dns.resolver.resolve(domain, 'AXFR')
                if answers:
                    self._log_vulnerability(
                        url=url,
                        type="DNS Zone Transfer",
                        severity="High",
                        description="DNS zone transfer possible (AXFR)",
                        evidence=str(answers)
                    )
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.exception.DNSException:
                pass
            
            # Check for common DNS misconfigurations
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for answer in answers:
                    if 'localhost' in str(answer.exchange).lower():
                        self._log_vulnerability(
                            url=url,
                            type="DNS Misconfiguration",
                            severity="Medium",
                            description="Localhost MX record found",
                            evidence=str(answer)
                        )
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.exception.DNSException:
                pass
            
        except Exception as e:
            logger.warning(f"DNS scan failed for {url}: {str(e)}")
    
    def _subdomain_scan(self):
        """Perform basic subdomain enumeration"""
        if not self.domain:
            return
            
        domain_parts = self.domain.split('.')
        if len(domain_parts) < 2:
            return
            
        base_domain = '.'.join(domain_parts[-2:])
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'server', 'ns', 'ns1', 
            'ns2', 'smtp', 'secure', 'vpn', 'm', 'mobile', 'dev', 'test'
        ]
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{base_domain}"
            try:
                socket.gethostbyname(subdomain)
                self._log_vulnerability(
                    url=f"http://{subdomain}",
                    type="Subdomain Found",
                    severity="Info",
                    description=f"Subdomain discovered: {subdomain}",
                    evidence="DNS resolution successful"
                )
            except socket.gaierror:
                continue
            except Exception as e:
                logger.warning(f"Subdomain scan failed for {subdomain}: {str(e)}")
    
    def _ssl_scan(self, url: str):
        """Perform basic SSL/TLS checks"""
        try:
            hostname = urlparse(url).netloc
            if ':' in hostname:
                hostname, port = hostname.split(':')
                port = int(port)
            else:
                port = 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Test SSL connection
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    # Check certificate expiry
                    not_after = x509_cert.not_valid_after
                    days_remaining = (not_after - datetime.utcnow()).days
                    
                    if days_remaining < 30:
                        self._log_vulnerability(
                            url=url,
                            type="SSL Certificate Expiry",
                            severity="Medium",
                            description=f"SSL certificate expires in {days_remaining} days",
                            evidence=f"Expiry date: {not_after}"
                        )
                    
                    # Check weak algorithms
                    signature_algorithm = x509_cert.signature_algorithm_oid._name
                    weak_algorithms = ['md5', 'sha1']
                    if any(algo in signature_algorithm.lower() for algo in weak_algorithms):
                        self._log_vulnerability(
                            url=url,
                            type="Weak SSL Algorithm",
                            severity="High",
                            description=f"Weak SSL signature algorithm: {signature_algorithm}",
                            evidence="Consider upgrading to SHA-256 or stronger"
                        )
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                        self._log_vulnerability(
                            url=url,
                            type="Deprecated TLS Version",
                            severity="High",
                            description=f"Deprecated TLS version: {tls_version}",
                            evidence="Upgrade to TLSv1.2 or higher"
                        )
        
        except Exception as e:
            logger.warning(f"SSL scan failed for {url}: {str(e)}")
    
    def _test_form(self, form: Dict):
        """Test forms for all vulnerability types"""
        if self.config['scan_types']['sqli']:
            self._test_sqli(form)
            
        if self.config['scan_types']['xss']:
            self._test_xss(form)
            
        if self.config['scan_types']['xxe']:
            self._test_xxe(form)
            
        if self.config['scan_types']['rce']:
            self._test_rce(form)
            
        if self.config['scan_types']['lfi']:
            self._test_lfi(form)
            
        if self.config['scan_types']['ssti']:
            self._test_ssti(form)
            
        if self.config['scan_types']['open_redirect']:
            self._test_open_redirect(form)
    
    def _test_api_endpoint(self, endpoint: str):
        """Advanced API security testing"""
        # Test for IDOR
        if self.config['scan_types']['idor']:
            self._test_idor(endpoint)
            
        # Test for SSRF
        if self.config['scan_types']['ssrf']:
            self._test_ssrf(endpoint)
            
        # Test for CORS
        if self.config['scan_types']['cors']:
            self._test_cors(endpoint)
            
        # Test for JWT issues
        if self.config['scan_types']['jwt']:
            self._test_jwt(endpoint)
            
        # Test for business logic flaws
        if self.config['scan_types']['business_logic']:
            self._test_business_logic(endpoint)
    
    def _test_graphql_endpoint(self, endpoint: str):
        """Test GraphQL endpoints for vulnerabilities"""
        if not self.config['scan_types']['graphql']:
            return
        
        # Test for introspection
        introspection_query = '{"query":"query { __schema { types { name fields { name } } } }"}'
        try:
            response = self._safe_request('POST', endpoint, data=introspection_query, headers={'Content-Type': 'application/json'})
            if response and response.status_code == 200:
                if '__schema' in response.text:
                    self._log_vulnerability(
                        url=endpoint,
                        type="GraphQL Introspection",
                        severity="Medium",
                        description="GraphQL introspection enabled",
                        evidence="Schema information exposed"
                    )
        except Exception as e:
            logger.warning(f"GraphQL test failed for {endpoint}: {str(e)}")
        
        # Test for mutations if found
        if 'mutation' in self.payloads['graphql'][1]:
            try:
                response = self._safe_request('POST', endpoint, data=self.payloads['graphql'][1], headers={'Content-Type': 'application/json'})
                if response and response.status_code == 200:
                    if 'deleteUser' in response.text:
                        self._log_vulnerability(
                            url=endpoint,
                            type="GraphQL Mutation",
                            severity="High",
                            description="GraphQL mutation operation allowed",
                            evidence="Potential data modification possible"
                        )
            except Exception as e:
                logger.warning(f"GraphQL mutation test failed for {endpoint}: {str(e)}")
    
    def _test_websocket_endpoint(self, endpoint: str):
        """Test WebSocket endpoints for vulnerabilities"""
        if not self.config['scan_types']['websockets']:
            return
        
        # Placeholder for WebSocket testing
        # In a real implementation, we would use a WebSocket client to test
        self._log_vulnerability(
            url=endpoint,
            type="WebSocket Endpoint",
            severity="Info",
            description="WebSocket endpoint discovered",
            evidence="Manual testing recommended"
        )
    
    def _test_csrf(self, form: Dict):
        """Test for CSRF vulnerabilities"""
        csrf_protected = False
        
        # Check for CSRF token in form
        for field in form['inputs']:
            if field['name'].lower() in ('csrf', 'csrf_token', 'authenticity_token'):
                csrf_protected = True
                break
        
        # Check for SameSite cookie attribute
        cookies = self.session.cookies.get_dict()
        for cookie in cookies:
            if 'samesite' in self.session.cookies.get(cookie).lower():
                csrf_protected = True
                break
        
        if not csrf_protected:
            self._log_vulnerability(
                url=form['action'],
                type="CSRF Vulnerability",
                severity="Medium",
                description="Potential CSRF vulnerability - no CSRF protection detected",
                evidence="Missing CSRF token or SameSite cookie attribute"
            )
    
    def _test_sqli(self, form: Dict):
        """Advanced SQLi detection with ML and timing-based checks"""
        for payload in self.payloads['sqli']:
            data = {}
            for field in form['inputs']:
                if field['name']:
                    data[field['name']] = payload
                    
            try:
                start_time = time.time()
                
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                if not response:
                    continue
                
                # Time-based detection
                elapsed = time.time() - start_time
                if 'SLEEP(' in payload or 'WAITFOR' in payload:
                    if elapsed > 5:  # If the request took significantly longer
                        self._log_vulnerability(
                            url=form['action'],
                            type="SQL Injection (Time-Based)",
                            severity="Critical",
                            description="Potential time-based SQL injection",
                            payload=payload,
                            evidence=f"Response delayed by {elapsed:.2f} seconds"
                        )
                        continue
                
                # Traditional detection
                if self._check_sqli(response.text):
                    self._log_vulnerability(
                        url=form['action'],
                        type="SQL Injection",
                        severity="Critical",
                        description="Traditional SQLi detected",
                        payload=payload,
                        evidence="Error message or behavior indicative of SQLi"
                    )
                
                # ML-based detection
                if self.config['advanced']['ml_enabled']:
                    try:
                        ml_prediction = self.sqli_model.predict([response.text])[0]
                        if ml_prediction > self.config['reporting']['confidence_threshold']:
                            self._log_vulnerability(
                                url=form['action'],
                                type="SQL Injection (ML Detected)",
                                severity="Critical",
                                description="ML model detected potential SQLi",
                                payload=payload,
                                evidence=f"ML confidence: {ml_prediction:.2f}"
                            )
                    except Exception as e:
                        logger.warning(f"SQLi ML prediction failed: {str(e)}")
                        
            except Exception as e:
                logger.warning(f"SQLi test failed for {form['action']}: {str(e)}")
                continue
    
    def _check_sqli(self, response_text: str) -> bool:
        """Check response for SQLi indicators"""
        indicators = [
            'SQL syntax',
            'MySQL server',
            'ORA-',
            'syntax error',
            'unclosed quotation mark',
            'PG::',
            'Microsoft OLE DB Provider',
            'ODBC Driver'
        ]
        
        return any(indicator.lower() in response_text.lower() for indicator in indicators)
    
    def _test_xss(self, form: Dict):
        """Advanced XSS detection with DOM analysis and ML"""
        for payload in self.payloads['xss']:
            data = {}
            for field in form['inputs']:
                if field['name']:
                    data[field['name']] = payload
                    
            try:
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                if not response:
                    continue
                
                # Traditional reflection check
                decoded_payload = html.unescape(payload)
                if decoded_payload in response.text:
                    self._log_vulnerability(
                        url=form['action'],
                        type="Reflected XSS",
                        severity="High",
                        description="XSS payload reflected in response",
                        payload=payload,
                        evidence="Payload reflected unencoded"
                    )
                
                # Check for DOM-based XSS patterns
                dom_patterns = [
                    f'document.write({payload})',
                    f'eval({payload})',
                    f'innerHTML={payload}'
                ]
                
                if any(pattern in response.text for pattern in dom_patterns):
                    self._log_vulnerability(
                        url=form['action'],
                        type="DOM-based XSS",
                        severity="High",
                        description="Potential DOM-based XSS detected",
                        payload=payload,
                        evidence="DOM manipulation pattern found"
                    )
                
                # ML-based detection
                if self.config['advanced']['ml_enabled']:
                    try:
                        ml_prediction = self.xss_model.predict([response.text])[0]
                        if ml_prediction > self.config['reporting']['confidence_threshold']:
                            self._log_vulnerability(
                                url=form['action'],
                                type="XSS (ML Detected)",
                                severity="High",
                                description="ML model detected potential XSS",
                                payload=payload,
                                evidence=f"ML confidence: {ml_prediction:.2f}"
                            )
                    except Exception as e:
                        logger.warning(f"XSS ML prediction failed: {str(e)}")
                        
            except Exception as e:
                logger.warning(f"XSS test failed for {form['action']}: {str(e)}")
                continue
    
    def _test_xxe(self, form: Dict):
        """XXE injection testing with advanced detection"""
        if 'xml' not in form['enctype'].lower():
            return
            
        for payload in self.payloads['xxe']:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self._safe_request('POST', form['action'], data=payload, headers=headers)
                
                if not response:
                    continue
                
                # Check for common XXE indicators
                indicators = [
                    'root:x:',
                    '<?xml',
                    '<!DOCTYPE',
                    'file not found',
                    'permission denied'
                ]
                
                if any(indicator.lower() in response.text.lower() for indicator in indicators):
                    self._log_vulnerability(
                        url=form['action'],
                        type="XXE Injection",
                        severity="Critical",
                        description="Potential XXE vulnerability detected",
                        payload=payload[:100] + "..." if len(payload) > 100 else payload,
                        evidence="Response contains file content or XML errors"
                    )
                    
            except Exception as e:
                logger.warning(f"XXE test failed for {form['action']}: {str(e)}")
                continue
    
    def _test_idor(self, endpoint: str):
        """IDOR testing with parameter fuzzing and state analysis"""
        # Check if endpoint has ID-like parameters
        id_params = ['id', 'user', 'account', 'doc', 'file', 'uid']
        
        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        
        # Find parameters that look like IDs
        test_params = {}
        for param in query_params:
            if any(id_param in param.lower() for id_param in id_params):
                test_params[param] = query_params[param][0]
        
        # If no obvious ID params, try common patterns
        if not test_params and any(part.isdigit() for part in parsed.path.split('/')):
            # Try replacing numbers in path
            parts = parsed.path.split('/')
            for i, part in enumerate(parts):
                if part.isdigit():
                    new_path = '/'.join(parts[:i] + ['12345'] + parts[i+1:])
                    test_url = parsed._replace(path=new_path).geturl()
                    self._test_idor_comparison(endpoint, test_url)
        else:
            # Test each ID parameter
            for param, value in test_params.items():
                # Create test URL with modified ID
                new_params = query_params.copy()
                new_params[param] = ['54321']
                test_url = parsed._replace(query='&'.join(f"{k}={v[0]}" for k, v in new_params.items())).geturl()
                self._test_idor_comparison(endpoint, test_url)
    
    def _test_idor_comparison(self, original_url: str, test_url: str):
        """Compare responses for IDOR testing"""
        try:
            response1 = self._safe_request('GET', original_url)
            response2 = self._safe_request('GET', test_url)
            
            if not response1 or not response2:
                return
                
            # Check status codes
            if response1.status_code == 200 and response2.status_code == 200:
                # Content-based comparison
                similarity = difflib.SequenceMatcher(
                    None, 
                    response1.text, 
                    response2.text
                ).ratio()
                
                if similarity < 0.7:  # Different responses
                    self._log_vulnerability(
                        url=original_url,
                        type="IDOR",
                        severity="Medium",
                        description="Insecure Direct Object Reference possible",
                        payload=f"Modified parameter in {test_url}",
                        evidence=f"Response similarity: {similarity:.2f}"
                    )
            
            # Check if we got access to someone else's data
            elif response1.status_code == 403 and response2.status_code == 200:
                self._log_vulnerability(
                    url=original_url,
                    type="IDOR",
                    severity="High",
                    description="Insecure Direct Object Reference confirmed",
                    payload=f"Modified parameter in {test_url}",
                    evidence="Got access to unauthorized resource"
                )
                
        except Exception as e:
            logger.warning(f"IDOR test failed for {original_url}: {str(e)}")
    
    def _test_ssrf(self, endpoint: str):
        """SSRF testing with internal IPs and advanced detection"""
        for payload in self.payloads['ssrf']:
            try:
                # Test in different parts of the request
                test_locations = [
                    ('url', f"{endpoint}?url={payload}"),
                    ('path', endpoint.replace('{url}', payload)),
                    ('header', endpoint, {'X-Forwarded-For': '127.0.0.1'})
                ]
                
                for location_type, test_url, *headers in test_locations:
                    if headers:
                        headers = headers[0]
                    else:
                        headers = {}
                    
                    response = self._safe_request('GET', test_url, headers=headers, timeout=5)
                    if not response:
                        continue
                    
                    # Check response for SSRF indicators
                    indicators = [
                        'EC2', 'Metadata', 'Internal', 'localhost',
                        '169.254.169.254', '127.0.0.1', 'file://'
                    ]
                    
                    if any(indicator in response.text for indicator in indicators):
                        self._log_vulnerability(
                            url=endpoint,
                            type="SSRF",
                            severity="High",
                            description=f"Potential SSRF in {location_type} parameter",
                            payload=payload,
                            evidence="Response contains internal system information"
                        )
                        break
                        
            except Exception as e:
                logger.warning(f"SSRF test failed for {endpoint}: {str(e)}")
                continue
    
    def _test_rce(self, form: Dict):
        """Remote Code Execution testing"""
        for payload in self.payloads['rce']:
            data = {}
            for field in form['inputs']:
                if field['name']:
                    data[field['name']] = payload
                    
            try:
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                if not response:
                    continue
                
                # Check for command execution patterns
                patterns = [
                    'uid=', 'gid=', 'groups=',
                    'Microsoft Windows', 'Linux',
                    'cannot execute', 'command not found'
                ]
                
                if any(pattern in response.text for pattern in patterns):
                    self._log_vulnerability(
                        url=form['action'],
                        type="Potential RCE",
                        severity="Critical",
                        description="Potential remote code execution",
                        payload=payload,
                        evidence="Command execution response detected"
                    )
                    
            except Exception as e:
                logger.warning(f"RCE test failed for {form['action']}: {str(e)}")
                continue
    
    def _test_lfi(self, form: Dict):
        """Local File Inclusion testing"""
        for payload in self.payloads['lfi']:
            data = {}
            for field in form['inputs']:
                if field['name']:
                    data[field['name']] = payload
                    
            try:
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                if not response:
                    continue
                
                # Check for common LFI indicators
                indicators = [
                    'root:x:', 'daemon:x:', 'bin:x:',
                    'DB_PASSWORD', 'SECRET_KEY',
                    '<?php', '<%', 'jsp:'
                ]
                
                if any(indicator in response.text for indicator in indicators):
                    self._log_vulnerability(
                        url=form['action'],
                        type="LFI/RFI",
                        severity="High",
                        description="Potential local/remote file inclusion",
                        payload=payload,
                        evidence="File contents or script tags in response"
                    )
                    
            except Exception as e:
                logger.warning(f"LFI test failed for {form['action']}: {str(e)}")
                continue
    
    def _test_ssti(self, form: Dict):
        """Server-Side Template Injection testing"""
        for payload in self.payloads['ssti']:
            data = {}
            for field in form['inputs']:
                if field['name']:
                    data[field['name']] = payload
                    
            try:
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                if not response:
                    continue
                
                # Check for template evaluation
                if '49' in response.text:  # 7*7=49
                    self._log_vulnerability(
                        url=form['action'],
                        type="SSTI",
                        severity="High",
                        description="Potential server-side template injection",
                        payload=payload,
                        evidence="Template expression evaluated"
                    )
                    
            except Exception as e:
                logger.warning(f"SSTI test failed for {form['action']}: {str(e)}")
                continue
    
    def _test_open_redirect(self, form: Dict):
        """Open Redirect testing"""
        for payload in self.payloads['open_redirect']:
            data = {}
            for field in form['inputs']:
                if field['name'] and 'url' in field['name'].lower():
                    data[field['name']] = payload
                    
            if not data:  # No URL parameters found
                return
                
            try:
                # Don't follow redirects for this test
                original_follow = self.session.max_redirects
                self.session.max_redirects = 0
                
                if form['method'] == 'get':
                    response = self._safe_request('GET', form['action'], params=data)
                else:
                    response = self._safe_request(form['method'], form['action'], data=data)
                
                # Restore redirect setting
                self.session.max_redirects = original_follow
                
                if not response:
                    continue
                
                # Check for redirect to our payload
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', '')
                    if payload in location or urlparse(location).netloc in payload:
                        self._log_vulnerability(
                            url=form['action'],
                            type="Open Redirect",
                            severity="Medium",
                            description="Open redirect vulnerability",
                            payload=payload,
                            evidence=f"Redirects to: {location}"
                        )
                        
            except Exception as e:
                logger.warning(f"Open redirect test failed for {form['action']}: {str(e)}")
                continue
            finally:
                    self.session.max_redirects = original_follow
    
    def _test_cors(self, endpoint: str):
        """CORS misconfiguration testing"""
        if not self.config['scan_types']['cors']:
            return
            
        try:
            # Test with simple Origin header
            headers = {'Origin': 'https://evil.com'}
            response = self._safe_request('OPTIONS', endpoint, headers=headers)
            
            if not response:
                return
                
            # Check CORS headers
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'
            
            if acao == '*' and acac:
                self._log_vulnerability(
                    url=endpoint,
                    type="CORS Misconfiguration",
                    severity="High",
                    description="Insecure CORS configuration - allows any origin with credentials",
                    evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
                )
            elif acao == '*' and not acac:
                self._log_vulnerability(
                    url=endpoint,
                    type="CORS Misconfiguration",
                    severity="Medium",
                    description="CORS allows any origin",
                    evidence="Access-Control-Allow-Origin: *"
                )
            elif 'evil.com' in acao:
                self._log_vulnerability(
                    url=endpoint,
                    type="CORS Misconfiguration",
                    severity="High",
                    description="CORS reflects arbitrary origin",
                    evidence=f"Access-Control-Allow-Origin: {acao}"
                )
                
        except Exception as e:
            logger.warning(f"CORS test failed for {endpoint}: {str(e)}")
    
    def _test_jwt(self, endpoint: str):
        """JWT testing (placeholder - would test for alg:none, weak secrets, etc.)"""
        if not self.config['scan_types']['jwt']:
            return
            
        # Check if endpoint uses JWT
        try:
            response = self._safe_request('GET', endpoint)
            if not response:
                return
                
            auth_header = response.request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                parts = token.split('.')
                
                if len(parts) == 3:  # Looks like JWT
                    # Test for alg:none vulnerability
                    try:
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
                        if header.get('alg', '').lower() == 'none':
                            self._log_vulnerability(
                                url=endpoint,
                                type="JWT alg:none",
                                severity="High",
                                description="JWT accepts 'none' algorithm",
                                evidence="Token header allows alg:none"
                            )
                    except:
                        pass
                        
                    self._log_vulnerability(
                        url=endpoint,
                        type="JWT Found",
                        severity="Info",
                        description="JWT token in use",
                        evidence="Manual testing recommended"
                    )
                    
        except Exception as e:
            logger.warning(f"JWT test failed for {endpoint}: {str(e)}")
    
    def _test_business_logic(self, endpoint: str):
        """Basic business logic testing (placeholder for more advanced checks)"""
        if not self.config['scan_types']['business_logic']:
            return
            
        # Example: Test for price manipulation
        if 'cart' in endpoint.lower() or 'checkout' in endpoint.lower():
            try:
                # First get the normal response
                normal_response = self._safe_request('GET', endpoint)
                if not normal_response:
                    return
                    
                # Try to modify price parameter
                parsed = urlparse(endpoint)
                query_params = parse_qs(parsed.query)
                
                if 'price' in query_params or 'amount' in query_params:
                    modified_params = query_params.copy()
                    if 'price' in modified_params:
                        modified_params['price'] = ['0.01']
                    if 'amount' in modified_params:
                        modified_params['amount'] = ['0.01']
                        
                    test_url = parsed._replace(query='&'.join(f"{k}={v[0]}" for k, v in modified_params.items())).geturl()
                    modified_response = self._safe_request('GET', test_url)
                    
                    if modified_response and modified_response.status_code == 200:
                        self._log_vulnerability(
                            url=endpoint,
                            type="Business Logic Flaw",
                            severity="High",
                            description="Potential price manipulation vulnerability",
                            evidence="Price parameter accepted modified value"
                        )
                        
            except Exception as e:
                logger.warning(f"Business logic test failed for {endpoint}: {str(e)}")
    
    def _passive_scan(self, url: str, response: requests.Response):
        """Comprehensive passive checks"""
        # Header security checks
        if self.config['scan_types']['header_security']:
            self._check_headers(url, response.headers)
        
        # Clickjacking check
        if self.config['scan_types']['clickjacking']:
            self._check_clickjacking(url, response.headers)
        
        # Information disclosure checks
        if self.config['scan_types']['info_disclosure']:
            self._check_info_disclosure(url, response)
    
    def _check_headers(self, url: str, headers: Dict):
        """Check for security-related HTTP headers"""
        security_headers = {
            'X-XSS-Protection': {'expected': '1; mode=block', 'severity': 'Medium'},
            'Content-Security-Policy': {'expected': None, 'severity': 'Medium'},
            'X-Content-Type-Options': {'expected': 'nosniff', 'severity': 'Medium'},
            'X-Frame-Options': {'expected': 'DENY', 'severity': 'Medium'},
            'Strict-Transport-Security': {'expected': 'max-age=31536000', 'severity': 'High'},
            'Referrer-Policy': {'expected': 'no-referrer', 'severity': 'Low'},
            'Feature-Policy': {'expected': None, 'severity': 'Low'}
        }
        
        for header, config in security_headers.items():
            if header not in headers:
                self._log_vulnerability(
                    url=url,
                    type=f"Missing Security Header - {header}",
                    severity=config['severity'],
                    description=f"Missing recommended security header: {header}",
                    evidence=f"Expected: {config['expected']}" if config['expected'] else "Header missing"
                )
            elif config['expected'] and headers[header] != config['expected']:
                self._log_vulnerability(
                    url=url,
                    type=f"Insecure Security Header - {header}",
                    severity=config['severity'],
                    description=f"Insecure value for security header: {header}",
                    evidence=f"Current: {headers[header]}, Expected: {config['expected']}"
                )
    
    def _check_clickjacking(self, url: str, headers: Dict):
        """Check for clickjacking protection"""
        xfo = headers.get('X-Frame-Options', '').lower()
        csp = headers.get('Content-Security-Policy', '').lower()
        
        if not xfo and 'frame-ancestors' not in csp:
            self._log_vulnerability(
                url=url,
                type="Clickjacking Vulnerability",
                severity="Medium",
                description="Missing clickjacking protection headers",
                evidence="No X-Frame-Options or CSP frame-ancestors directive"
            )
    
    def _check_info_disclosure(self, url: str, response: requests.Response):
        """Check for information disclosure in response"""
        # Check for sensitive info in response
        sensitive_patterns = [
            ('password', 'Potential password exposure'),
            ('api_key', 'API key exposure'),
            ('secret', 'Secret key exposure'),
            ('aws_key', 'AWS key exposure'),
            ('database_password', 'Database password exposure'),
            ('<error>', 'Verbose error messages'),
            ('stack trace', 'Stack trace exposure'),
            ('DEBUG', 'Debug mode enabled')
        ]
        
        for pattern, desc in sensitive_patterns:
            if pattern.lower() in response.text.lower():
                self._log_vulnerability(
                    url=url,
                    type="Information Disclosure",
                    severity="Medium",
                    description=desc,
                    evidence=f"Found '{pattern}' in response"
                )
        
        # Check for server/tech info in headers
        server = response.headers.get('Server', '')
        if server:
            self._log_vulnerability(
                url=url,
                type="Server Information Disclosure",
                severity="Low",
                description="Server header reveals technology information",
                evidence=f"Server: {server}"
            )
        
        xpowered = response.headers.get('X-Powered-By', '')
        if xpowered:
            self._log_vulnerability(
                url=url,
                type="Technology Information Disclosure",
                severity="Low",
                description="X-Powered-By header reveals technology information",
                evidence=f"X-Powered-By: {xpowered}"
            )
    
    def _log_vulnerability(self, **kwargs):
        """Standardized vulnerability logging"""
        vuln = {
            'timestamp': datetime.now().isoformat(),
            'confirmed': False,
            'confidence': 'medium',
            **kwargs
        }
        
        # Set confidence based on detection method
        if 'ML Detected' in vuln.get('type', ''):
            vuln['confidence'] = 'high'
        elif 'Potential' in vuln.get('type', '') or 'Possible' in vuln.get('type', ''):
            vuln['confidence'] = 'low'
        
        self.vulnerabilities.append(vuln)
        logger.warning(f"Vulnerability found: {vuln['type']} at {vuln['url']}")
    
    def run_scan(self):
        """Execute complete scan workflow"""
        logger.info(f"Starting advanced scan of {self.base_url}")
        self.start_time = time.time()
        
        # Initial crawl
        self.crawl(self.base_url)
        
        # API-specific tests
        if self.config['scan_types']['api']:
            logger.info("Testing discovered API endpoints")
            for endpoint in list(self.api_endpoints):
                self._test_api_endpoint(endpoint)
        
        # GraphQL tests
        if self.config['scan_types']['graphql'] and self.graphql_endpoints:
            logger.info("Testing discovered GraphQL endpoints")
            for endpoint in list(self.graphql_endpoints):
                self._test_graphql_endpoint(endpoint)
        
        # WebSocket tests
        if self.config['scan_types']['websockets'] and self.websocket_endpoints:
            logger.info("Testing discovered WebSocket endpoints")
            for endpoint in list(self.websocket_endpoints):
                self._test_websocket_endpoint(endpoint)
        
        # Port scanning if enabled
        if self.config['scan_types']['port_scan']:
            logger.info("Performing basic port scan")
            self._port_scan()
        
        # Wait for completion
        self.executor.shutdown(wait=True)
        
        # Final analysis
        if self.config['advanced']['anomaly_detection']:
            self._analyze_results()
        
        # Generate report
        report = self.generate_report()
        
        # Save report
        self._save_report(report)
        
        return report
    
    def _port_scan(self):
        """Basic port scanning functionality"""
        try:
            domain = urlparse(self.base_url).netloc
            if ':' in domain:
                domain = domain.split(':')[0]
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        self._log_vulnerability(
                            url=f"{domain}:{port}",
                            type="Open Port",
                            severity="Info",
                            description=f"Port {port} is open",
                            evidence="Port scan detected open port"
                        )
                    sock.close()
                except:
                    continue
        except Exception as e:
            logger.warning(f"Port scan failed: {str(e)}")
    
    def _analyze_results(self):
        """Post-scan analysis with anomaly detection and clustering"""
        if not self.vulnerabilities:
            return
            
        try:
            # Cluster similar vulnerabilities
            vuln_texts = [f"{v['type']} {v['description']}" for v in self.vulnerabilities]
            vectors = np.array([hashlib.md5(t.encode()).hexdigest()[:16] for t in vuln_texts])
            
            # Anomaly detection
            clf = IsolationForest(contamination=0.1)
            anomalies = clf.fit_predict(vectors.reshape(-1, 1))
            
            for i, is_anomaly in enumerate(anomalies):
                if is_anomaly == -1:
                    self.vulnerabilities[i]['tags'] = ['anomaly']
                    self.vulnerabilities[i]['confidence'] = 'high'
        
        except Exception as e:
            logger.warning(f"Anomaly detection failed: {str(e)}")
    
    def generate_report(self):
        """Generate professional report with remediation"""
        report = {
            'metadata': {
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'base_url': self.base_url,
                'duration': f"{(time.time() - self.start_time):.2f} seconds",
                'pages_crawled': len(self.visited_urls),
                'endpoints_found': len(self.discovered_endpoints),
                'api_endpoints': len(self.api_endpoints),
                'graphql_endpoints': len(self.graphql_endpoints),
                'websocket_endpoints': len(self.websocket_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'config': self.config
            },
            'vulnerabilities': sorted(
                self.vulnerabilities,
                key=lambda x: (
                    ['Critical', 'High', 'Medium', 'Low', 'Info'].index(x['severity']),
                    -1 * x.get('confidence', 0)  # Sort by confidence if available
                )
            ),
            'sitemap': {
                'web_pages': list(self.visited_urls),
                'api_endpoints': list(self.api_endpoints),
                'graphql_endpoints': list(self.graphql_endpoints),
                'websocket_endpoints': list(self.websocket_endpoints)
            },
            'recommendations': self._generate_recommendations(),
            'stats': {
                'vulnerability_distribution': self._get_vuln_distribution(),
                'severity_distribution': self._get_severity_distribution()
            }
        }
        
        return report
    
    def _save_report(self, report):
        """Save report in configured format"""
        output_file = self.config['reporting']['output_file']
        report_format = self.config['reporting']['format'].lower()
        
        try:
            if report_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            elif report_format == 'html':
                self._generate_html_report(report, output_file)
            elif report_format == 'markdown':
                self._generate_markdown_report(report, output_file)
            else:
                logger.error(f"Unsupported report format: {report_format}")
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            
            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
    
    def _generate_html_report(self, report, output_file):
        """Generate HTML version of the report"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {report['metadata']['base_url']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .info {{ border-left: 5px solid #17a2b8; }}
                .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .severity-count {{ display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }}
                .severity-critical {{ background: #dc3545; }}
                .severity-high {{ background: #fd7e14; }}
                .severity-medium {{ background: #ffc107; }}
                .severity-low {{ background: #28a745; }}
                .severity-info {{ background: #17a2b8; }}
                pre {{ background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>Security Scan Report</h1>
            <div class="metadata">
                <h2>Scan Metadata</h2>
                <p><strong>Target URL:</strong> {report['metadata']['base_url']}</p>
                <p><strong>Scan Date:</strong> {report['metadata']['scan_date']}</p>
                <p><strong>Duration:</strong> {report['metadata']['duration']}</p>
                <p><strong>Pages Crawled:</strong> {report['metadata']['pages_crawled']}</p>
                <p><strong>Endpoints Found:</strong> {report['metadata']['endpoints_found']}</p>
                <p><strong>Vulnerabilities Found:</strong> 
                    <span class="severity-count severity-critical">{report['stats']['severity_distribution'].get('Critical', 0)} Critical</span>
                    <span class="severity-count severity-high">{report['stats']['severity_distribution'].get('High', 0)} High</span>
                    <span class="severity-count severity-medium">{report['stats']['severity_distribution'].get('Medium', 0)} Medium</span>
                    <span class="severity-count severity-low">{report['stats']['severity_distribution'].get('Low', 0)} Low</span>
                    <span class="severity-count severity-info">{report['stats']['severity_distribution'].get('Info', 0)} Info</span>
                </p>
            </div>
            
            <h2>Vulnerabilities</h2>
            {"".join(self._format_vuln_html(vuln) for vuln in report['vulnerabilities'])}
            
            <h2>Recommendations</h2>
            <ul>
                {"".join(f"<li><strong>{rec['issue']}:</strong> {rec['fix']}</li>" for rec in report['recommendations'])}
            </ul>
            
            <h2>Scan Statistics</h2>
            <h3>Vulnerability Distribution</h3>
            <ul>
                {"".join(f"<li>{vuln_type}: {count}</li>" for vuln_type, count in report['stats']['vulnerability_distribution'].items())}
            </ul>
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html_template)
    
    def _format_vuln_html(self, vuln):
        """Format a single vulnerability for HTML report"""
        try:
            severity_class = vuln.get('severity', 'info').lower()
            
            # Safely escape all content with proper fallbacks
            vuln_type = html.escape(str(vuln.get('type', 'Unknown Vulnerability')))
            url = html.escape(str(vuln.get('url', 'No URL')))
            description = html.escape(str(vuln.get('description', 'No description available')))
            
            # Handle timestamp with multiple fallbacks
            timestamp = ''
            if 'timestamp' in vuln:
                if isinstance(vuln['timestamp'], (str, int, float)):
                    timestamp = html.escape(str(vuln['timestamp']))
                elif hasattr(vuln['timestamp'], 'isoformat'):
                    timestamp = html.escape(vuln['timestamp'].isoformat())
                else:
                    timestamp = html.escape(str(vuln['timestamp']))
            else:
                timestamp = html.escape(time.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Handle optional fields
            payload = ''
            if vuln.get('payload'):
                payload = f"<p><strong>Payload:</strong> <code>{html.escape(str(vuln['payload']))}</code></p>"
            
            evidence = ''
            if vuln.get('evidence'):
                evidence = f"<p><strong>Evidence:</strong> <pre>{html.escape(str(vuln['evidence']))}</pre></p>"
            
            return f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln_type} <span class="severity-count severity-{severity_class}">{vuln.get('severity', 'Info')}</span></h3>
                <p><strong>URL:</strong> {url}</p>
                <p><strong>Description:</strong> {description}</p>
                {payload}
                {evidence}
                <p><strong>Timestamp:</strong> {timestamp}</p>
            </div>
            """
        except Exception as e:
            logger.error(f"Error formatting vulnerability for HTML: {str(e)}")
            return """
            <div class="vulnerability error">
                <h3>Error Displaying Vulnerability</h3>
                <p>Could not properly format this vulnerability for display.</p>
            </div>
            """
    
    def _generate_markdown_report(self, report, output_file):
        """Generate Markdown version of the report"""
        try:
            # Create markdown content
            markdown_lines = [
                "# Security Scan Report",
                "",
                "## Scan Metadata",
                f"- **Target URL**: {report['metadata']['base_url']}",
                f"- **Scan Date**: {report['metadata']['scan_date']}",
                f"- **Duration**: {report['metadata']['duration']}",
                f"- **Pages Crawled**: {report['metadata']['pages_crawled']}",
                f"- **Endpoints Found**: {report['metadata']['endpoints_found']}",
                f"- **Vulnerabilities Found**:",
                f"  - Critical: {report['stats']['severity_distribution'].get('Critical', 0)}",
                f"  - High: {report['stats']['severity_distribution'].get('High', 0)}",
                f"  - Medium: {report['stats']['severity_distribution'].get('Medium', 0)}",
                f"  - Low: {report['stats']['severity_distribution'].get('Low', 0)}",
                f"  - Info: {report['stats']['severity_distribution'].get('Info', 0)}",
                "",
                "## Vulnerabilities"
            ]
    
            # Add vulnerabilities
            for vuln in report['vulnerabilities']:
                markdown_lines.extend([
                    "",
                    f"### {vuln['type']} ({vuln['severity']})",
                    f"- **URL**: {vuln['url']}",
                    f"- **Description**: {vuln['description']}"
                ])
                if vuln.get('payload'):
                    markdown_lines.append(f"- **Payload**: `{vuln['payload']}`")
                if vuln.get('evidence'):
                    markdown_lines.append(f"- **Evidence**: \n```\n{vuln['evidence']}\n```")
                markdown_lines.append(f"- **Timestamp**: {vuln['timestamp']}")
    
            # Add recommendations and stats
            markdown_lines.extend([
                "",
                "## Recommendations"
            ])
            for rec in report['recommendations']:
                markdown_lines.append(f"- **{rec['issue']}**: {rec['fix']}")
    
            markdown_lines.extend([
                "",
                "## Scan Statistics",
                "",
                "### Vulnerability Distribution"
            ])
            for vuln_type, count in report['stats']['vulnerability_distribution'].items():
                markdown_lines.append(f"- {vuln_type}: {count}")
    
            # Write to file
            with open(output_file, 'w') as f:
                f.write('\n'.join(markdown_lines))
                
        except Exception as e:
            logger.error(f"Error generating Markdown report: {str(e)}")
            raise
    def _get_vuln_distribution(self):
        """Get count of each vulnerability type"""
        dist = {}
        for vuln in self.vulnerabilities:
            dist[vuln['type']] = dist.get(vuln['type'], 0) + 1
        return dict(sorted(dist.items(), key=lambda item: item[1], reverse=True))
    
    def _get_severity_distribution(self):
        """Get count of each severity level"""
        dist = {}
        for vuln in self.vulnerabilities:
            dist[vuln['severity']] = dist.get(vuln['severity'], 0) + 1
        return dist
    
    def _generate_recommendations(self):
        """Generate actionable security recommendations"""
        recs = []
        vuln_types = {v['type'] for v in self.vulnerabilities}
        
        if any('SQL Injection' in t for t in vuln_types):
            recs.append({
                'issue': 'SQL Injection',
                'fix': 'Use parameterized queries/prepared statements. Validate and sanitize all user input.',
                'resources': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                    'https://owasp.org/www-community/attacks/SQL_Injection'
                ]
            })
        
        if any('XSS' in t for t in vuln_types):
            recs.append({
                'issue': 'Cross-Site Scripting',
                'fix': 'Implement Content Security Policy (CSP) and output encoding. Use XSS filters.',
                'resources': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
                    'https://owasp.org/www-community/attacks/xss/'
                ]
            })
        
        if any('IDOR' in t for t in vuln_types):
            recs.append({
                'issue': 'Insecure Direct Object Reference',
                'fix': 'Implement proper access controls. Use indirect object references.',
                'resources': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html',
                    'https://owasp.org/www-community/attacks/idor'
                ]
            })
        
        if any('SSRF' in t for t in vuln_types):
            recs.append({
                'issue': 'Server-Side Request Forgery',
                'fix': 'Validate and sanitize all user-supplied URLs. Use allowlists for internal resources.',
                'resources': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
                    'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
                ]
            })
        
        if any('XXE' in t for t in vuln_types):
            recs.append({
                'issue': 'XML External Entity',
                'fix': 'Disable XML external entity processing. Use simpler data formats like JSON.',
                'resources': [
                    'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
                    'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'
                ]
            })
        
        if any('Missing Security Header' in t for t in vuln_types):
            recs.append({
                'issue': 'Missing Security Headers',
                'fix': 'Implement security headers like CSP, X-Frame-Options, X-Content-Type-Options, etc.',
                'resources': [
                    'https://owasp.org/www-project-secure-headers/',
                    'https://securityheaders.com/'
                ]
            })
        
        if any('Information Disclosure' in t for t in vuln_types):
            recs.append({
                'issue': 'Information Disclosure',
                'fix': 'Remove sensitive information from responses. Disable debug modes in production.',
                'resources': [
                    'https://owasp.org/www-community/vulnerabilities/Information_exposure',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure_Cheat_Sheet.html'
                ]
            })
        
        return recs

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Advanced Burp-like Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-c', '--config', help='Path to config file (JSON)')
    parser.add_argument('-o', '--output', help='Output file path', default='scan_report.json')
    parser.add_argument('-f', '--format', help='Report format (json/html/markdown)', default='json')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    return parser.parse_args()

def load_config(config_path):
    """Load configuration from file"""
    if not config_path:
        return None
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config file: {str(e)}")
        return None

if __name__ == "__main__":
    args = parse_args()
    
    # Set up logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load config
    config = load_config(args.config) or {}
    
    # Override output settings from command line
    if 'reporting' not in config:
        config['reporting'] = {}
    config['reporting']['output_file'] = args.output
    config['reporting']['format'] = args.format
    
    # Run scanner
    scanner = AdvancedBurpScanner(args.url, config)
    report = scanner.run_scan()
    
    print(f"\n[+] Scan complete. Found {len(report['vulnerabilities'])} vulnerabilities.")
    print(f"    Report saved to {config['reporting']['output_file']}")
