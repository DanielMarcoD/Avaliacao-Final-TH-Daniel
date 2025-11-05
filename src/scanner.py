#!/usr/bin/env python3
"""
Advanced Web Security Scanner - Conceito A
Enhanced with heuristic analysis, risk scoring, and advanced vulnerability detection
"""

import requests
import argparse
import time
import json
import re
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import socket
from typing import Dict, List, Tuple, Any
import warnings

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)
requests.packages.urllib3.disable_warnings()

# Initialize colorama
init(autoreset=True)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print(f"{Fore.YELLOW}⚠️ Nmap não disponível. Algumas funcionalidades serão limitadas.")

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    print(f"{Fore.YELLOW}⚠️ ZAP API não disponível. Instale com: pip install python-owasp-zap-v2.4")

try:
    import subprocess
    # Verificar se nikto está realmente instalado
    result = subprocess.run(['which', 'nikto'], capture_output=True, timeout=2)
    NIKTO_AVAILABLE = (result.returncode == 0)
    if not NIKTO_AVAILABLE:
        print(f"{Fore.YELLOW}⚠️ Nikto não encontrado no sistema")
except Exception:
    NIKTO_AVAILABLE = False

from utils.helpers import (
    XSS_PAYLOADS_ADVANCED, SQL_PAYLOADS_ADVANCED, DIRECTORY_TRAVERSAL_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS, INFO_DISCLOSURE_PATHS, AUTH_BYPASS_PAYLOADS
)
from report_generator import AdvancedReportGeneratorA

class VulnerabilityRisk:
    """Class for vulnerability risk scoring and categorization"""
    
    SEVERITY_WEIGHTS = {
        'CRITICAL': 10,
        'HIGH': 8, 
        'MEDIUM': 5,
        'LOW': 2,
        'INFO': 1
    }
    
    VULNERABILITY_SCORES = {
        'SQL Injection': ('CRITICAL', 9.8),
        'XSS': ('HIGH', 8.5),
        'Command Injection': ('CRITICAL', 9.5),
        'Directory Traversal': ('HIGH', 7.5),
        'Information Disclosure': ('MEDIUM', 5.5),
        'Broken Authentication': ('HIGH', 8.0),
        'Insecure Direct Object Reference': ('HIGH', 7.8),
        'Security Misconfiguration': ('MEDIUM', 6.0),
        'Cross-Site Request Forgery': ('MEDIUM', 6.8),
        'Insecure Cryptographic Storage': ('HIGH', 7.9)
    }
    
    @staticmethod
    def calculate_risk_score(vuln_type: str, context: Dict[str, Any]) -> float:
        """Calculate CVSS-like risk score for vulnerability"""
        base_score = VulnerabilityRisk.VULNERABILITY_SCORES.get(vuln_type, ('MEDIUM', 5.0))[1]
        
        # Context-based adjustments (smaller multipliers to avoid hitting ceiling)
        if context.get('authentication_required', False):
            base_score *= 0.7  # Reduce significantly if auth required
        
        if context.get('public_facing', True):
            base_score *= 1.05  # Small increase if publicly accessible
            
        if context.get('sensitive_data', False):
            base_score *= 1.1  # Moderate increase if sensitive data involved
            
        return min(base_score, 10.0)
    
    @staticmethod
    def get_severity_level(score: float) -> str:
        """Get severity level based on score"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score >= 1.0:
            return 'LOW'
        else:
            return 'INFO'

class HeuristicAnalyzer:
    """Advanced heuristic analysis for vulnerability patterns"""
    
    def __init__(self):
        self.behavioral_patterns = {
            'sql_error_patterns': [
                r'mysql_fetch_array\(\)',
                r'ORA-\d{5}',
                r'Microsoft.*ODBC.*SQL Server',
                r'PostgreSQL.*ERROR',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'MySqlClient\.',
                r'SQLServer JDBC Driver'
            ],
            'xss_reflection_patterns': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'on\w+\s*=',
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>'
            ],
            'path_traversal_patterns': [
                r'\.\.[\\/]',
                r'%2e%2e%2f',
                r'%252e%252e%252f',
                r'\.\.\\',
                r'%2e%2e%5c'
            ]
        }
        
    def analyze_response_behavior(self, response: requests.Response, payload: str) -> Dict[str, Any]:
        """Analyze response behavior for heuristic detection"""
        analysis = {
            'response_time_anomaly': False,
            'content_length_anomaly': False,
            'status_code_anomaly': False,
            'header_anomalies': [],
            'content_patterns': [],
            'confidence_score': 0.0
        }
        
        # Response time analysis
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 10:
            analysis['response_time_anomaly'] = True
            analysis['confidence_score'] += 0.3
            
        # Content length analysis
        if 'content-length' in response.headers:
            try:
                length = int(response.headers['content-length'])
                if length > 100000:  # Unusually large response
                    analysis['content_length_anomaly'] = True
                    analysis['confidence_score'] += 0.2
            except ValueError:
                pass
                
        # Status code analysis
        if response.status_code in [500, 501, 502, 503]:
            analysis['status_code_anomaly'] = True
            analysis['confidence_score'] += 0.4
            
        # Content pattern analysis
        content = response.text.lower()
        for pattern_type, patterns in self.behavioral_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis['content_patterns'].append({
                        'type': pattern_type,
                        'pattern': pattern,
                        'payload': payload
                    })
                    analysis['confidence_score'] += 0.3
                    
        return analysis

class EnhancedWebSecurityScanner:
    """Enhanced Web Security Scanner with advanced analysis and risk scoring"""
    
    def __init__(self, url: str, timeout: int = 30, max_paths: int = 50, max_scan_time: int = None):
        """
        Initialize scanner with configuration
        
        Args:
            url: Target URL to scan
            timeout: Request timeout in seconds (default: 30)
            max_paths: Maximum number of paths to scan (0 or -1 for unlimited)
            max_scan_time: Maximum total scan time in seconds (None for unlimited)
        """
        self.url = url
        self.timeout = timeout
        # If max_paths is 0 or -1, it means unlimited
        self.max_paths = max_paths if max_paths > 0 else 999999
        self.is_unlimited = (max_paths == 0 or max_paths == -1)
        self.max_scan_time = max_scan_time  # NEW: Global scan timeout
        self.scan_start_time = None  # NEW: Track when scan started
        self.scan_interrupted = False  # NEW: Flag if scan was interrupted by timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.scan_metadata = {
            'start_time': datetime.now(),
            'target_url': url,
            'scan_id': hashlib.md5(f"{url}{time.time()}".encode(), usedforsecurity=False).hexdigest()[:8],
            'scanner_version': 'v3.0-ConceptA',
            'total_requests': 0,
            'max_paths': 'unlimited' if self.is_unlimited else max_paths,
            'max_scan_time': max_scan_time,
            'vulnerabilities_by_type': {},
            'risk_metrics': {}
        }
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.discovered_paths = set()  # Track discovered paths
        
    def _make_request(self, url: str, method: str = 'GET', data: dict = None, 
                     headers: dict = None) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            self.scan_metadata['total_requests'] += 1
            
            if method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout, 
                                           verify=False, headers=headers or {})
            else:
                response = self.session.get(url, timeout=self.timeout, 
                                          verify=False, headers=headers or {})
            return response
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}❌ Erro na requisição: {e}")
            return None
            
    def _add_vulnerability(self, vuln_type: str, url: str, payload: str, 
                          description: str, evidence: str = "", context: dict = None):
        """Add vulnerability with enhanced metadata and risk scoring"""
        context = context or {}
        
        # Calculate risk score
        risk_score = VulnerabilityRisk.calculate_risk_score(vuln_type, context)
        severity = VulnerabilityRisk.get_severity_level(risk_score)
        
        vulnerability = {
            'id': len(self.vulnerabilities) + 1,
            'type': vuln_type,
            'severity': severity,
            'risk_score': risk_score,
            'url': url,
            'payload': payload,
            'description': description,
            'evidence': evidence,
            'context': context,
            'timestamp': datetime.now().isoformat(),
            'scan_id': self.scan_metadata['scan_id']
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # Update scan metadata
        if vuln_type not in self.scan_metadata['vulnerabilities_by_type']:
            self.scan_metadata['vulnerabilities_by_type'][vuln_type] = 0
        self.scan_metadata['vulnerabilities_by_type'][vuln_type] += 1
        
    def discover_paths(self):
        """Discover paths/endpoints from the target website"""
        display_limit = 'UNLIMITED' if self.is_unlimited else self.max_paths
        print(f"{Fore.CYAN}🔍 Discovering paths from website (max: {display_limit})...")
        
        try:
            response = self._make_request(self.url)
            if not response:
                return [self.url]
            
            soup = BeautifulSoup(response.text, 'html.parser')
            base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
            
            # Add base URL
            self.discovered_paths.add(self.url)
            
            # Find all links
            for link in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                href = link.get('href') or link.get('src') or link.get('action')
                if href:
                    # Build absolute URL
                    if href.startswith('/'):
                        full_url = base_url + href
                    elif href.startswith('http'):
                        # Only include if same domain
                        if urlparse(href).netloc == urlparse(self.url).netloc:
                            full_url = href
                        else:
                            continue
                    elif not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(self.url, href)
                    else:
                        continue
                    
                    # Remove fragments
                    full_url = full_url.split('#')[0]
                    
                    if full_url and full_url not in self.discovered_paths:
                        self.discovered_paths.add(full_url)
                        
                        # Only check limit if not unlimited
                        if not self.is_unlimited and len(self.discovered_paths) >= self.max_paths:
                            break
                
                # Only check limit if not unlimited
                if not self.is_unlimited and len(self.discovered_paths) >= self.max_paths:
                    break
            
            # Convert to list
            paths_list = list(self.discovered_paths)
            if not self.is_unlimited:
                paths_list = paths_list[:self.max_paths]
                
            print(f"{Fore.GREEN}✅ Discovered {len(paths_list)} paths to scan")
            
            return paths_list
            
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Path discovery error: {e}")
            return [self.url]  # Fallback to base URL only
    
    def scan_ssl_configuration(self):
        """Advanced SSL/TLS configuration analysis"""
        print(f"{Fore.CYAN}🔐 Iniciando análise avançada de SSL/TLS...")
        
        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            if parsed_url.scheme != 'https':
                self._add_vulnerability(
                    "Security Misconfiguration",
                    self.url,
                    "HTTP_ONLY",
                    "Site não utiliza HTTPS",
                    "Conexão não criptografada detectada",
                    {'public_facing': True, 'sensitive_data': True}
                )
                return
                
            # SSL Context analysis
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
                    if cipher and any(weak in str(cipher) for weak in weak_ciphers):
                        self._add_vulnerability(
                            "Insecure Cryptographic Storage",
                            self.url,
                            f"WEAK_CIPHER:{cipher[0]}",
                            "Cifra SSL/TLS fraca detectada",
                            f"Cifra utilizada: {cipher[0]}",
                            {'public_facing': True}
                        )
                        
                    # Check SSL version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._add_vulnerability(
                            "Security Misconfiguration", 
                            self.url,
                            f"WEAK_TLS:{version}",
                            "Versão SSL/TLS insegura",
                            f"Versão detectada: {version}",
                            {'public_facing': True}
                        )
                        
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Análise SSL falhou: {e}")
            
    def scan_advanced_xss(self):
        """Advanced XSS scanning with heuristic analysis"""
        print(f"{Fore.CYAN}🕷️ Iniciando scan avançado de XSS com análise heurística...")
        
        xss_found = 0
        
        # Use discovered paths or fallback to main URL
        paths_to_test = list(self.discovered_paths) if self.discovered_paths else [self.url]
        print(f"{Fore.CYAN}   Testando XSS em {len(paths_to_test)} paths...")
        
        for current_url in paths_to_test:
            # Check scan timeout
            if self._check_scan_timeout():
                return
            
            print(f"{Fore.CYAN}   📄 Analisando: {current_url}")
            
            # Get page forms and parameters
            response = self._make_request(current_url)
            if not response:
                print(f"{Fore.YELLOW}      ⚠️ Sem resposta, pulando...")
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test URL parameters
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            if params:
                print(f"{Fore.CYAN}      🔍 {len(params)} parâmetros GET encontrados")
            
            for param in params:
                # Check timeout before testing each parameter
                if self._check_scan_timeout():
                    return
                
                print(f"{Fore.CYAN}   Testando parâmetro: {param} em {current_url}")
                for payload in XSS_PAYLOADS_ADVANCED[:30]:  # Enhanced payload testing (aumentado de 15 para 30)
                    # Check timeout in payload loop
                    if self._check_scan_timeout():
                        return
                    
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                    

                    time.sleep(0.5)  # Delay realista para evitar rate limiting (aumentado de 0.1 para 0.5)
                    test_response = self._make_request(test_url)
                    if test_response:
                        # Heuristic analysis
                        analysis = self.heuristic_analyzer.analyze_response_behavior(test_response, payload)
                        
                        if payload in test_response.text or analysis['confidence_score'] > 0.5:
                            context = {
                                'parameter': param,
                                'heuristic_confidence': analysis['confidence_score'],
                                'public_facing': True,
                                'authentication_required': False
                            }
                            
                            self._add_vulnerability(
                                "XSS",
                                test_url,
                                payload,
                                f"Cross-Site Scripting no parâmetro '{param}'",
                                f"Payload refletido na resposta. Confiança: {analysis['confidence_score']:.2f}",
                                context
                            )
                            xss_found += 1
                        
            # Test forms
            forms = soup.find_all('form')
            if forms:
                print(f"{Fore.CYAN}      📋 {len(forms)} formulários encontrados, testando até 5")
            
            for form_idx, form in enumerate(forms[:5], 1):  # Aumentado de 3 para 5 formulários por página
                # Check timeout before testing each form
                if self._check_scan_timeout():
                    return
                
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    form_url = urljoin(current_url, action)
                else:
                    form_url = current_url
                
                print(f"{Fore.CYAN}         Form {form_idx}/{min(len(forms), 5)}: {method} {action or '(same page)'}")
                    
                inputs = form.find_all(['input', 'textarea', 'select'])
                testable_inputs = [inp for inp in inputs if inp.get('name') and inp.get('type') not in ['submit', 'button', 'reset']]
                
                if not testable_inputs:
                    print(f"{Fore.YELLOW}            ⚠️ Sem inputs testáveis, pulando...")
                    continue
                
                print(f"{Fore.CYAN}            🎯 {len(testable_inputs)} campos testáveis encontrados")
                print(f"{Fore.CYAN}            🎯 {len(testable_inputs)} campos testáveis encontrados")
                
                for payload in XSS_PAYLOADS_ADVANCED[:25]:  # Aumentado de 10 para 25
                    # Check timeout in payload loop
                    if self._check_scan_timeout():
                        return
                    
                    form_data = {}
                    for inp in testable_inputs:
                        name = inp.get('name', '')
                        if name:
                            form_data[name] = payload
                        
                    if form_data:
                        time.sleep(0.6)  # Delay realista entre form tests (aumentado de 0.15 para 0.6)
                        test_response = self._make_request(form_url, method, form_data)
                        if test_response:
                            analysis = self.heuristic_analyzer.analyze_response_behavior(test_response, payload)
                            
                            if payload in test_response.text or analysis['confidence_score'] > 0.6:
                                context = {
                                    'form_action': action,
                                    'form_method': method,
                                    'heuristic_confidence': analysis['confidence_score'],
                                    'public_facing': True
                                }
                                
                                self._add_vulnerability(
                                    "XSS",
                                    form_url,
                                    payload,
                                    f"Cross-Site Scripting em formulário",
                                    f"Payload refletido via formulário. Confiança: {analysis['confidence_score']:.2f}",
                                    context
                                )
                                xss_found += 1
                            
        if xss_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {xss_found} vulnerabilidades XSS!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade XSS encontrada")
            
    def scan_advanced_sqli(self):
        """Advanced SQL Injection scanning with error pattern analysis"""
        print(f"{Fore.CYAN}💉 Iniciando scan avançado de SQL Injection...")
        
        sqli_found = 0
        
        # Use discovered paths or fallback to main URL
        paths_to_test = list(self.discovered_paths) if self.discovered_paths else [self.url]
        print(f"{Fore.CYAN}   Testando SQL Injection em {len(paths_to_test)} paths...")
        
        for current_url in paths_to_test:
            # Check scan timeout
            if self._check_scan_timeout():
                return
            
            print(f"{Fore.CYAN}   📄 Analisando: {current_url}")
            
            response = self._make_request(current_url)
            if not response:
                print(f"{Fore.YELLOW}      ⚠️ Sem resposta, pulando...")
                continue
            
            soup = BeautifulSoup(response.text, 'html.parser')
                
            # Test URL parameters
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            if params:
                print(f"{Fore.CYAN}      🔍 {len(params)} parâmetros GET encontrados")
            
            for param in params:
                # Check timeout before testing each parameter
                if self._check_scan_timeout():
                    return
                
                print(f"{Fore.CYAN}   Testando SQL Injection no parâmetro: {param} em {current_url}")
                for payload in SQL_PAYLOADS_ADVANCED[:40]:  # Aumentado de 20 para 40
                    # Check timeout in payload loop
                    if self._check_scan_timeout():
                        return
                    
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                    
                    time.sleep(0.5)  # Delay realista para SQL injection (aumentado de 0.12 para 0.5)
                    test_response = self._make_request(test_url)
                    if test_response:
                        analysis = self.heuristic_analyzer.analyze_response_behavior(test_response, payload)
                        
                        # Enhanced SQL error detection
                        sql_errors = [
                            'mysql_fetch_array', 'ORA-', 'Microsoft.*ODBC.*SQL Server',
                            'PostgreSQL.*ERROR', 'Warning.*mysql_', 'valid MySQL result',
                            'SQLServer JDBC Driver', 'sqlite3.OperationalError',
                            'mysql_num_rows', 'OracleException', 'SQL syntax.*MySQL'
                        ]
                        
                        error_detected = any(re.search(error, test_response.text, re.IGNORECASE) for error in sql_errors)
                        
                        if error_detected or analysis['confidence_score'] > 0.7:
                            context = {
                                'parameter': param,
                                'error_based': error_detected,
                                'heuristic_confidence': analysis['confidence_score'],
                                'public_facing': True,
                                'sensitive_data': True
                            }
                            
                            self._add_vulnerability(
                                "SQL Injection",
                                test_url,
                                payload,
                                f"SQL Injection no parâmetro '{param}'",
                                f"Erro SQL detectado ou comportamento suspeito. Confiança: {analysis['confidence_score']:.2f}",
                                context
                            )
                            sqli_found += 1
            
            # Test forms for SQL Injection
            forms = soup.find_all('form')
            if forms:
                print(f"{Fore.CYAN}      📋 {len(forms)} formulários encontrados, testando até 5")
            
            for form_idx, form in enumerate(forms[:5], 1):
                # Check timeout before testing each form
                if self._check_scan_timeout():
                    return
                
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    form_url = urljoin(current_url, action)
                else:
                    form_url = current_url
                
                print(f"{Fore.CYAN}         Form {form_idx}/{min(len(forms), 5)}: {method} {action or '(same page)'}")
                    
                inputs = form.find_all(['input', 'textarea', 'select'])
                testable_inputs = [inp for inp in inputs if inp.get('name') and inp.get('type') not in ['submit', 'button', 'reset']]
                
                if not testable_inputs:
                    print(f"{Fore.YELLOW}            ⚠️ Sem inputs testáveis, pulando...")
                    continue
                
                print(f"{Fore.CYAN}            🎯 {len(testable_inputs)} campos testáveis encontrados")
                
                for payload in SQL_PAYLOADS_ADVANCED[:30]:  # Test first 30 SQLi payloads on forms
                    # Check timeout in payload loop
                    if self._check_scan_timeout():
                        return
                    
                    form_data = {}
                    for inp in testable_inputs:
                        name = inp.get('name', '')
                        if name:
                            form_data[name] = payload
                    
                    if form_data:
                        time.sleep(0.6)  # Realistic delay for SQLi form testing
                        test_response = self._make_request(form_url, method, form_data)
                        if test_response:
                            analysis = self.heuristic_analyzer.analyze_response_behavior(test_response, payload)
                            
                            # Check for SQL errors
                            sql_errors = [
                                'mysql_fetch_array', 'ORA-', 'Microsoft.*ODBC.*SQL Server',
                                'PostgreSQL.*ERROR', 'Warning.*mysql_', 'valid MySQL result',
                                'SQLServer JDBC Driver', 'sqlite3.OperationalError',
                                'mysql_num_rows', 'OracleException', 'SQL syntax.*MySQL'
                            ]
                            
                            error_detected = any(re.search(error, test_response.text, re.IGNORECASE) for error in sql_errors)
                            
                            if error_detected or analysis['confidence_score'] > 0.7:
                                context = {
                                    'form_action': action,
                                    'form_method': method,
                                    'error_based': error_detected,
                                    'heuristic_confidence': analysis['confidence_score'],
                                    'public_facing': True,
                                    'sensitive_data': True
                                }
                                
                                self._add_vulnerability(
                                    "SQL Injection",
                                    form_url,
                                    payload,
                                    f"SQL Injection em formulário",
                                    f"Erro SQL detectado ou comportamento suspeito em formulário. Confiança: {analysis['confidence_score']:.2f}",
                                    context
                                )
                                sqli_found += 1
                        
        if sqli_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {sqli_found} vulnerabilidades SQL Injection!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade SQL Injection encontrada")

    def scan_csrf_protection(self):
        """Scan for CSRF protection mechanisms"""
        print(f"{Fore.CYAN}🛡️ Verificando proteções CSRF...")
        
        response = self._make_request(self.url)
        if not response:
            return
            
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            method = form.get('method', 'GET').upper()
            if method == 'POST':
                # Check for CSRF tokens
                csrf_tokens = form.find_all('input', {'name': re.compile(r'.*(csrf|token|_token).*', re.I)})
                
                if not csrf_tokens:
                    action = form.get('action', self.url)
                    form_url = urljoin(self.url, action)
                    
                    self._add_vulnerability(
                        "Cross-Site Request Forgery",
                        form_url,
                        "NO_CSRF_TOKEN",
                        "Formulário sem proteção CSRF",
                        "Token CSRF não encontrado em formulário POST",
                        {'public_facing': True, 'authentication_required': True}
                    )

    def scan_clickjacking_protection(self):
        """Check for clickjacking protection headers"""
        print(f"{Fore.CYAN}🖱️ Verificando proteções contra Clickjacking...")
        
        response = self._make_request(self.url)
        if not response:
            return
            
        headers = response.headers
        
        # Check X-Frame-Options
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            self._add_vulnerability(
                "Security Misconfiguration",
                self.url,
                "NO_FRAME_PROTECTION",
                "Falta de proteção contra Clickjacking",
                "Headers X-Frame-Options ou CSP frame-ancestors não encontrados",
                {'public_facing': True}
            )
            
    def scan_security_headers(self):
        """Comprehensive security headers analysis"""
        print(f"{Fore.CYAN}📋 Analisando cabeçalhos de segurança...")
        
        response = self._make_request(self.url)
        if not response:
            return
            
        headers = response.headers
        
        # Security headers to check
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'Referrer-Policy': None
        }
        
        for header, expected in security_headers.items():
            if header not in headers:
                self._add_vulnerability(
                    "Security Misconfiguration",
                    self.url,
                    f"MISSING_{header.upper().replace('-', '_')}",
                    f"Cabeçalho de segurança ausente: {header}",
                    f"O cabeçalho {header} não foi encontrado na resposta",
                    {'public_facing': True}
                )

    def scan_command_injection(self):
        """Scan for Command Injection vulnerabilities"""
        print(f"{Fore.CYAN}💻 Iniciando scan de Command Injection...")
        
        paths_to_test = list(self.discovered_paths) if self.discovered_paths else [self.url]
        print(f"{Fore.CYAN}   Testando Command Injection em {len(paths_to_test)} paths...")
        
        cmd_found = 0
        for current_url in paths_to_test:
            if self._check_scan_timeout():
                return
                
            response = self._make_request(current_url)
            if not response:
                continue
                
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:3]:
                if self._check_scan_timeout():
                    return
                    
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = urljoin(current_url, action) if action else current_url
                
                inputs = form.find_all(['input', 'textarea'])
                testable_inputs = [inp for inp in inputs if inp.get('name')]
                
                if not testable_inputs:
                    continue
                
                for payload in COMMAND_INJECTION_PAYLOADS[:15]:
                    if self._check_scan_timeout():
                        return
                        
                    form_data = {inp.get('name'): payload for inp in testable_inputs}
                    
                    time.sleep(0.3)
                    test_response = self._make_request(form_url, method, form_data)
                    if test_response:
                        # Check for command execution indicators
                        indicators = ['root:', 'bin/bash', 'uid=', 'gid=', 'groups=', 'Windows', 'Volume Serial']
                        if any(indicator in test_response.text for indicator in indicators):
                            context = {
                                'form_action': action,
                                'form_method': method,
                                'public_facing': True,
                                'sensitive_data': True
                            }
                            
                            self._add_vulnerability(
                                "Command Injection",
                                form_url,
                                payload,
                                "Possível execução de comandos do sistema operacional",
                                f"Indicadores de comando encontrados na resposta",
                                context
                            )
                            cmd_found += 1
                            break
        
        if cmd_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {cmd_found} possíveis vulnerabilidades de Command Injection!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade de Command Injection encontrada")
    
    def scan_directory_traversal(self):
        """Scan for Directory Traversal/Path Traversal vulnerabilities"""
        print(f"{Fore.CYAN}📂 Iniciando scan de Directory Traversal...")
        
        paths_to_test = list(self.discovered_paths) if self.discovered_paths else [self.url]
        print(f"{Fore.CYAN}   Testando Directory Traversal em {len(paths_to_test)} paths...")
        
        traversal_found = 0
        for current_url in paths_to_test:
            if self._check_scan_timeout():
                return
                
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            for param in params:
                if self._check_scan_timeout():
                    return
                    
                for payload in DIRECTORY_TRAVERSAL_PAYLOADS[:20]:
                    if self._check_scan_timeout():
                        return
                        
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                    
                    time.sleep(0.3)
                    test_response = self._make_request(test_url)
                    if test_response:
                        # Check for sensitive file disclosure
                        indicators = ['root:', '/bin/bash', 'passwd', '[boot loader]', 'Windows', 'System32']
                        if any(indicator in test_response.text for indicator in indicators):
                            context = {
                                'parameter': param,
                                'public_facing': True,
                                'sensitive_data': True
                            }
                            
                            self._add_vulnerability(
                                "Directory Traversal",
                                test_url,
                                payload,
                                f"Path Traversal no parâmetro '{param}'",
                                "Acesso a arquivos do sistema detectado",
                                context
                            )
                            traversal_found += 1
                            break
        
        if traversal_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {traversal_found} vulnerabilidades de Directory Traversal!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade de Directory Traversal encontrada")
    
    def scan_open_redirect(self):
        """Scan for Open Redirect vulnerabilities"""
        print(f"{Fore.CYAN}🔀 Iniciando scan de Open Redirect...")
        
        paths_to_test = list(self.discovered_paths) if self.discovered_paths else [self.url]
        print(f"{Fore.CYAN}   Testando Open Redirect em {len(paths_to_test)} paths...")
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri', 'goto', 'target', 'destination']
        redirect_payloads = [
            'https://evil.com',
            'http://malicious.com',
            '//evil.com',
            '/\\evil.com',
            'https://google.com'
        ]
        
        redirect_found = 0
        for current_url in paths_to_test:
            if self._check_scan_timeout():
                return
                
            parsed_url = urlparse(current_url)
            params = parse_qs(parsed_url.query)
            
            # Test existing parameters
            for param in params:
                if any(redir_param in param.lower() for redir_param in redirect_params):
                    if self._check_scan_timeout():
                        return
                        
                    for payload in redirect_payloads[:3]:
                        test_params = params.copy()
                        test_params[param] = [payload]
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                        
                        time.sleep(0.2)
                        test_response = self._make_request(test_url)
                        if test_response and (test_response.status_code in [301, 302, 303, 307, 308]):
                            location = test_response.headers.get('Location', '')
                            if payload in location or 'evil.com' in location or 'malicious.com' in location:
                                context = {
                                    'parameter': param,
                                    'redirect_location': location,
                                    'public_facing': True
                                }
                                
                                self._add_vulnerability(
                                    "Open Redirect",
                                    test_url,
                                    payload,
                                    f"Open Redirect no parâmetro '{param}'",
                                    f"Redirecionamento para: {location}",
                                    context
                                )
                                redirect_found += 1
                                break
        
        if redirect_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {redirect_found} vulnerabilidades de Open Redirect!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade de Open Redirect encontrada")
    
    def scan_information_disclosure(self):
        """Scan for Information Disclosure vulnerabilities"""
        print(f"{Fore.CYAN}🔍 Iniciando scan de Information Disclosure...")
        
        disclosure_found = 0
        base_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}"
        
        # Test common information disclosure paths
        for path in INFO_DISCLOSURE_PATHS[:30]:
            if self._check_scan_timeout():
                return
                
            test_url = urljoin(base_url, path)
            time.sleep(0.2)
            response = self._make_request(test_url)
            
            if response and response.status_code == 200:
                # Check for sensitive information in response
                sensitive_patterns = [
                    'api_key', 'apikey', 'password', 'secret', 'token',
                    'mysql', 'database', 'mongodb', 'redis',
                    'aws_access_key', 'private_key', 'ssh_key'
                ]
                
                content_lower = response.text.lower()
                found_patterns = [pattern for pattern in sensitive_patterns if pattern in content_lower]
                
                if found_patterns:
                    context = {
                        'exposed_path': path,
                        'sensitive_patterns': found_patterns,
                        'public_facing': True,
                        'sensitive_data': True
                    }
                    
                    self._add_vulnerability(
                        "Information Disclosure",
                        test_url,
                        path,
                        f"Exposição de informações sensíveis em {path}",
                        f"Padrões sensíveis encontrados: {', '.join(found_patterns[:3])}",
                        context
                    )
                    disclosure_found += 1
        
        if disclosure_found > 0:
            print(f"{Fore.RED}⚠️ Encontradas {disclosure_found} vulnerabilidades de Information Disclosure!")
        else:
            print(f"{Fore.GREEN}✅ Nenhuma vulnerabilidade de Information Disclosure encontrada")

    def scan_with_zap_api(self) -> List[Dict]:
        """Advanced scanning using OWASP ZAP API integration"""
        if not ZAP_AVAILABLE:
            print(f"{Fore.YELLOW}⚠️ ZAP API não disponível - pulando ZAP scan...")
            return []
            
        zap_results = []
        try:
            print(f"{Fore.CYAN}🔍 Tentando conectar ao OWASP ZAP daemon...")
            
            # Try to connect to ZAP daemon (try multiple endpoints)
            zap = None
            connected_host = None
            
            for zap_host in ['localhost', '127.0.0.1']:
                try:
                    print(f"{Fore.CYAN}   Tentando {zap_host}:8080...")
                    # Inicializar ZAP corretamente
                    test_zap = ZAPv2(apikey='', proxies={
                        'http': f'http://{zap_host}:8080',
                        'https': f'http://{zap_host}:8080'
                    })
                    
                    # Test connection with timeout
                    version = test_zap.core.version
                    print(f"{Fore.GREEN}✅ Conectado ao ZAP {version} em {zap_host}:8080")
                    zap = test_zap
                    connected_host = zap_host
                    break
                except Exception as e:
                    print(f"{Fore.YELLOW}   ❌ Falha ao conectar em {zap_host}: {str(e)[:50]}")
                    continue
            
            if not zap:
                print(f"{Fore.RED}❌ Não foi possível conectar ao ZAP em nenhum endpoint")
                print(f"{Fore.YELLOW}💡 Certifique-se de que o ZAP está rodando: docker logs <container>")
                return []
            
            print(f"{Fore.GREEN}✅ ZAP conectado com sucesso!")
            
            # Acessar o URL no ZAP para iniciar o contexto
            print(f"{Fore.CYAN}🌐 Acessando URL no ZAP: {self.url}")
            try:
                zap.urlopen(self.url)
                time.sleep(2)  # Give ZAP time to register the URL
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ Aviso ao acessar URL: {e}")
            
            # Spider the target (com timeout configurável)
            print(f"{Fore.CYAN}🕷️  Executando spider scan...")
            try:
                spider_scan_id = zap.spider.scan(self.url)
                print(f"{Fore.CYAN}   Spider scan ID: {spider_scan_id}")
                
                # Wait for spider with max time limit (usar max_scan_time se definido, senão sem limite)
                # Se max_scan_time estiver definido, usar 40% dele para o spider
                max_spider_time = int(self.max_scan_time * 0.4) if self.max_scan_time else None
                spider_start = time.time()
                
                while True:
                    if max_spider_time and (time.time() - spider_start > max_spider_time):
                        print(f"{Fore.YELLOW}⏰ Spider timeout ({max_spider_time}s) - continuando...")
                        break
                    
                    try:
                        status = int(zap.spider.status(spider_scan_id))
                        if status >= 100:
                            print(f"{Fore.GREEN}✅ Spider concluído!")
                            break
                        print(f"{Fore.CYAN}   Spider progress: {status}%")
                    except:
                        break
                    
                    time.sleep(5)
                
            except Exception as spider_error:
                print(f"{Fore.YELLOW}⚠️ Erro no spider: {spider_error}")
            
            # Active scan (com timeout configurável)
            print(f"{Fore.CYAN}🎯 Executando active scan...")
            try:
                ascan_scan_id = zap.ascan.scan(self.url)
                print(f"{Fore.CYAN}   Active scan ID: {ascan_scan_id}")
                
                # Wait for active scan with max time limit (usar max_scan_time se definido, senão sem limite)
                # Se max_scan_time estiver definido, usar 60% dele para o active scan
                max_ascan_time = int(self.max_scan_time * 0.6) if self.max_scan_time else None
                ascan_start = time.time()
                
                while True:
                    if max_ascan_time and (time.time() - ascan_start > max_ascan_time):
                        print(f"{Fore.YELLOW}⏰ Active scan timeout ({max_ascan_time}s) - coletando resultados...")
                        break
                    
                    try:
                        status = int(zap.ascan.status(ascan_scan_id))
                        if status >= 100:
                            print(f"{Fore.GREEN}✅ Active scan concluído!")
                            break
                        print(f"{Fore.CYAN}   Active scan progress: {status}%")
                    except:
                        break
                    
                    time.sleep(10)
                
            except Exception as ascan_error:
                print(f"{Fore.YELLOW}⚠️ Erro no active scan: {ascan_error}")
            
            # Get alerts (sempre tentar coletar, mesmo com timeout)
            print(f"{Fore.CYAN}📊 Coletando alertas do ZAP...")
            try:
                alerts = zap.core.alerts(baseurl=self.url)
                print(f"{Fore.GREEN}✅ {len(alerts)} alertas coletados")
                
                for alert in alerts:
                    # Map ZAP risk to our severity
                    risk = alert.get('risk', 'Medium')
                    risk_map = {
                        'High': 'HIGH',
                        'Medium': 'MEDIUM',
                        'Low': 'LOW',
                        'Informational': 'INFO'
                    }
                    severity = risk_map.get(risk, 'MEDIUM')
                    
                    vuln_type = f"ZAP - {alert.get('alert', 'Unknown')}"
                    
                    self._add_vulnerability(
                        vuln_type,
                        alert.get('url', self.url),
                        alert.get('param', ''),
                        f"ZAP Alert: {alert.get('alert', 'Unknown vulnerability')} - {alert.get('description', '')}",
                        alert.get('evidence', '')[:200],  # Limit evidence size
                        {
                            'confidence': alert.get('confidence', 'Medium'),
                            'risk': risk,
                            'severity': severity,
                            'tool': 'OWASP ZAP',
                            'plugin_id': alert.get('pluginId', ''),
                            'cweid': alert.get('cweid', ''),
                            'wascid': alert.get('wascid', ''),
                            'reference': alert.get('reference', '')
                        }
                    )
                    zap_results.append(alert)
                    
                print(f"{Fore.GREEN}✅ ZAP scan concluído - {len(alerts)} vulnerabilidades encontradas")
                
            except Exception as alerts_error:
                print(f"{Fore.RED}❌ Erro ao coletar alertas: {alerts_error}")
            
            return zap_results
            
        except Exception as e:
            print(f"{Fore.RED}❌ Erro geral no ZAP scan: {e}")
            import traceback
            traceback.print_exc()
            print(f"{Fore.YELLOW}💡 Dica: Verifique se o ZAP está rodando com 'docker logs <container> | grep ZAP'")
            return []

    def scan_with_nikto(self) -> List[Dict]:
        """Advanced scanning using Nikto integration"""
        if not NIKTO_AVAILABLE:
            print(f"{Fore.YELLOW}⚠️ Nikto não disponível - simulando integração...")
            return self._simulate_nikto_integration()
            
        nikto_results = []
        try:
            print(f"{Fore.CYAN}🔍 Executando scan com Nikto...")
            
            # Parse URL to get host and port
            parsed_url = urlparse(self.url)
            host = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # Execute Nikto scan without format flag (will parse stdout directly)
            nikto_cmd = [
                'nikto',
                '-h', f"{host}",
                '-p', str(port),
                '-nointeractive',
                '-Tuning', '1,2,3,4,6,7,8,9',  # Skip DoS tests (5) to avoid hanging
                '-timeout', '5',
                '-maxtime', '120'  # Max 2 minutes for Nikto scan
            ]
            
            if parsed_url.scheme == 'https':
                nikto_cmd.extend(['-ssl'])
            
            print(f"{Fore.CYAN}   Comando: {' '.join(nikto_cmd)}")
            
            try:
                result = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=150)
                
                # Nikto returns 0 even with findings, parse output
                output = result.stdout + result.stderr
                lines = output.split('\n')
                findings_count = 0
                
                print(f"{Fore.CYAN}   Analisando {len(lines)} linhas de output do Nikto...")
                
                for line in lines:
                    line = line.strip()
                    # Look for findings (lines starting with + and containing issues)
                    if line.startswith('+ '):
                        # Skip informational lines
                        if any(skip in line.lower() for skip in 
                               ['server:', 'start time:', 'end time:', 'target ip:', 
                                'target hostname:', 'target port:', 'requests:', 'elapsed time:']):
                            continue
                        
                        # This is a real finding
                        print(f"{Fore.YELLOW}   📌 Nikto finding: {line[:80]}...")
                        
                        # Extract URI if present
                        uri_match = re.search(r'(/[^\s:]+)', line)
                        uri = uri_match.group(0) if uri_match else ''
                        
                        # Extract OSVDB ID if present
                        osvdb_match = re.search(r'OSVDB-(\d+)', line)
                        osvdb_id = osvdb_match.group(1) if osvdb_match else None
                        
                        self._add_vulnerability(
                            'NIKTO_FINDING',
                            f"{self.url}{uri}" if uri else self.url,
                            'GET',
                            f"Nikto: {line[2:].split(':')[0]}",  # Remove '+ ' and take first part
                            line.strip(),
                            {
                                'tool': 'Nikto',
                                'finding_type': 'web_server_issue',
                                'raw_line': line,
                                'osvdb_id': osvdb_id
                            }
                        )
                        nikto_results.append({'finding': line.strip(), 'uri': uri})
                        findings_count += 1
                
                print(f"{Fore.GREEN}✅ Nikto scan concluído - {findings_count} findings encontrados")
                
                if findings_count == 0:
                    print(f"{Fore.YELLOW}⚠️ Nikto não encontrou vulnerabilidades (pode ser site bem protegido)")
                    
            except subprocess.TimeoutExpired:
                print(f"{Fore.YELLOW}⚠️ Timeout no Nikto scan após 150s")
                
        except Exception as e:
            print(f"{Fore.RED}❌ Erro no Nikto scan: {e}")
            import traceback
            traceback.print_exc()
            
        return nikto_results

    def _simulate_nikto_integration(self) -> List[Dict]:
        """Simula integração Nikto para demonstração"""
        print(f"{Fore.CYAN}🔄 Executando simulação de integração Nikto...")
        
        simulated_findings = []
        try:
            # Fazer alguns requests para simular análise Nikto
            response = self._make_request(self.url)
            if response:
                findings_count = 0
                
                # Simular detecção de diretórios comuns
                common_paths = ['/admin/', '/backup/', '/test/', '/dev/', '/config/']
                for path in common_paths[:2]:  # Teste apenas 2 para não demorar
                    test_response = self._make_request(self.url.rstrip('/') + path)
                    if test_response and test_response.status_code in [200, 301, 302, 403]:
                        self._add_vulnerability(
                            'NIKTO_SIMULATED_DIRECTORY',
                            self.url + path.lstrip('/'),
                            'GET',
                            f'Nikto Simulated: Potentially interesting directory found - {path}',
                            f'HTTP {test_response.status_code} response for {path}',
                            {
                                'tool': 'Nikto (Simulated)',
                                'finding_type': 'directory_listing',
                                'simulation': True
                            }
                        )
                        simulated_findings.append({
                            'finding': f'Potentially interesting directory: {path}',
                            'uri': path,
                            'status_code': test_response.status_code
                        })
                        findings_count += 1
                
                # Simular detecção de server version
                if 'Server' in response.headers:
                    server_header = response.headers['Server']
                    self._add_vulnerability(
                        'NIKTO_SIMULATED_SERVER_VERSION',
                        self.url,
                        'HEAD',
                        f'Nikto Simulated: Server version disclosure',
                        f'Server header reveals version: {server_header}',
                        {
                            'tool': 'Nikto (Simulated)',
                            'finding_type': 'information_disclosure',
                            'simulation': True
                        }
                    )
                    simulated_findings.append({
                        'finding': f'Server version disclosure: {server_header}',
                        'uri': '/'
                    })
                    findings_count += 1
                
                print(f"{Fore.GREEN}✅ Nikto simulado concluído - {findings_count} findings simulados")
                
        except Exception as e:
            print(f"{Fore.RED}❌ Erro na simulação Nikto: {e}")
            
        return simulated_findings

    def scan_with_nmap(self) -> List[Dict]:
        """Advanced port scanning and service detection using Nmap"""
        if not NMAP_AVAILABLE:
            print(f"{Fore.YELLOW}⚠️ Nmap não disponível - pulando port scan")
            return []
            
        nmap_results = []
        try:
            print(f"{Fore.CYAN}🔍 Executando port scan com Nmap...")
            
            # Parse target
            parsed_url = urlparse(self.url)
            host = parsed_url.netloc.split(':')[0]
            
            # Initialize Nmap scanner
            nm = nmap.PortScanner()
            
            # Scan ALL ports with timeout of 120 seconds
            print(f"{Fore.CYAN}📡 Scanning ALL ports on {host} (timeout: 120s)...")
            nm.scan(host, arguments='-p- -sV -T4 --host-timeout 120s')
            
            for host_ip in nm.all_hosts():
                for protocol in nm[host_ip].all_protocols():
                    ports = nm[host_ip][protocol].keys()
                    
                    for port in ports:
                        port_info = nm[host_ip][protocol][port]
                        state = port_info['state']
                        service = port_info.get('name', 'unknown')
                        version = port_info.get('version', '')
                        
                        # Check for security concerns
                        if state == 'open':
                            # Check for vulnerable services
                            vulnerable_services = {
                                'ftp': 'Serviço FTP detectado - verificar configurações de segurança',
                                'telnet': 'Telnet detectado - protocolo inseguro',
                                'smtp': 'SMTP detectado - verificar relay aberto'
                            }
                            
                            if service in vulnerable_services:
                                self._add_vulnerability(
                                    'NMAP_SERVICE_DETECTION',
                                    f"{host}:{port}",
                                    f"{service}:{version}",
                                    vulnerable_services[service],
                                    f"Porto {port}/{protocol} aberto - Serviço: {service} {version}",
                                    {
                                        'port': port,
                                        'protocol': protocol,
                                        'service': service,
                                        'version': version,
                                        'tool': 'Nmap'
                                    }
                                )
                            
                            # Check Nmap script results for vulnerabilities
                            if 'script' in port_info:
                                for script_name, script_output in port_info['script'].items():
                                    if any(keyword in script_output.lower() for keyword in ['vuln', 'cve', 'vulnerability', 'exploit']):
                                        self._add_vulnerability(
                                            'NMAP_SCRIPT_VULN',
                                            f"{host}:{port}",
                                            script_name,
                                            f"Vulnerabilidade detectada pelo script Nmap: {script_name}",
                                            script_output,
                                            {
                                                'port': port,
                                                'service': service,
                                                'script': script_name,
                                                'tool': 'Nmap NSE'
                                            }
                                        )
                            
                            nmap_results.append({
                                'port': port,
                                'protocol': protocol,
                                'state': state,
                                'service': service,
                                'version': version
                            })
                            
            print(f"{Fore.GREEN}✅ Nmap scan concluído - {len(nmap_results)} portos analisados")
            
        except Exception as e:
            print(f"{Fore.RED}❌ Erro no Nmap scan: {e}")
            
        return nmap_results

    def scan_with_auxiliary_tools(self):
        """Execute all auxiliary security tools for comprehensive analysis"""
        print(f"{Fore.MAGENTA}🛠️ Iniciando integração com ferramentas auxiliares...")
        print(f"{Fore.MAGENTA}📋 Ferramentas disponíveis: ZAP API, Nikto Scanner, Nmap")
        
        # Check timeout before starting auxiliary tools
        if self._check_scan_timeout():
            print(f"{Fore.YELLOW}⏰ Pulando ferramentas auxiliares devido ao timeout")
            return {'zap': [], 'nikto': [], 'nmap': []}
        
        auxiliary_results = {
            'zap': [],
            'nikto': [],
            'nmap': []
        }
        
        # ZAP scan with timeout check
        if not self._check_scan_timeout():
            auxiliary_results['zap'] = self.scan_with_zap_api()
        else:
            print(f"{Fore.YELLOW}⏰ Pulando ZAP devido ao timeout")
        
        # Nikto scan with timeout check
        if not self._check_scan_timeout():
            auxiliary_results['nikto'] = self.scan_with_nikto()
        else:
            print(f"{Fore.YELLOW}⏰ Pulando Nikto devido ao timeout")
        
        # Nmap scan with timeout check
        if not self._check_scan_timeout():
            auxiliary_results['nmap'] = self.scan_with_nmap()
        else:
            print(f"{Fore.YELLOW}⏰ Pulando Nmap devido ao timeout")
        
        # Update scan metadata with auxiliary results
        self.scan_metadata['auxiliary_tools'] = {
            'zap_alerts': len(auxiliary_results['zap']),
            'nikto_findings': len(auxiliary_results['nikto']),
            'nmap_ports': len(auxiliary_results['nmap'])
        }
        
        # Detailed summary
        total_findings = sum(len(results) for results in auxiliary_results.values())
        print(f"{Fore.MAGENTA}")
        print(f"� RESULTADOS DAS FERRAMENTAS AUXILIARES:")
        print(f"   🔴 ZAP API: {len(auxiliary_results['zap'])} alertas")
        print(f"   🟡 Nikto: {len(auxiliary_results['nikto'])} findings")
        print(f"   🔵 Nmap: {len(auxiliary_results['nmap'])} portas analisadas")
        print(f"   🎯 Total: {total_findings} findings adicionais das ferramentas auxiliares")
        print(f"{Style.RESET_ALL}")
        
        return auxiliary_results

    def perform_comprehensive_scan(self):
        """Perform comprehensive security scan with all vulnerability types"""
        print(f"{Fore.CYAN}🚀 Iniciando scan abrangente de segurança...")
        print(f"{Fore.CYAN}🎯 Target: {self.url}")
        print(f"{Fore.CYAN}📊 Scan ID: {self.scan_metadata['scan_id']}")
        display_limit = 'UNLIMITED ⚠️' if self.is_unlimited else self.max_paths
        print(f"{Fore.CYAN}📁 Max paths to scan: {display_limit}")
        if self.max_scan_time:
            print(f"{Fore.YELLOW}⏰ Max scan time: {self.max_scan_time}s ({self.max_scan_time//60} min)")
        
        # Set scan start time for timeout checks
        self.scan_start_time = datetime.now()
        
        # Test basic connectivity
        initial_response = self._make_request(self.url)
        if not initial_response:
            print(f"{Fore.RED}❌ Falha ao conectar com o target")
            return [], self.scan_metadata
        
        print(f"{Fore.GREEN}✅ Status da resposta: {initial_response.status_code}")
        
        # Discover paths from website
        discovered_paths = self.discover_paths()
        self.scan_metadata['discovered_paths'] = len(discovered_paths)
        self.scan_metadata['paths_list'] = discovered_paths[:10]  # Store first 10 for reference
        
        print(f"{Fore.CYAN}🔍 Scanning {len(discovered_paths)} discovered paths...")
        if self.is_unlimited:
            print(f"{Fore.YELLOW}⚠️  AVISO: Modo ILIMITADO ativado - o scan pode demorar muito tempo!")
        
        # Multi-threaded vulnerability scanning - OWASP Top 10 Completo
        scan_functions = [
            self.scan_advanced_xss,              # A03:2021 - Injection (XSS)
            self.scan_advanced_sqli,             # A03:2021 - Injection (SQLi)
            self.scan_command_injection,         # A03:2021 - Injection (Command)
            self.scan_directory_traversal,       # A01:2021 - Broken Access Control
            self.scan_open_redirect,             # A01:2021 - Broken Access Control
            self.scan_information_disclosure,    # A01:2021 - Broken Access Control
            self.scan_ssl_configuration,         # A02:2021 - Cryptographic Failures
            self.scan_csrf_protection,           # A01:2021 - Broken Access Control (CSRF)
            self.scan_clickjacking_protection,   # A05:2021 - Security Misconfiguration
            self.scan_security_headers           # A05:2021 - Security Misconfiguration
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(func) for func in scan_functions]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Fore.RED}❌ Erro durante scan: {e}")
        
        # 🔥 CONCEITO A+ - Execute auxiliary security tools for enhanced analysis
        print(f"{Fore.MAGENTA}🚀 CONCEITO A+ - Integrando ferramentas auxiliares avançadas...")
        auxiliary_results = self.scan_with_auxiliary_tools()
        
        # Calculate final metrics
        self.scan_metadata['end_time'] = datetime.now()
        self.scan_metadata['duration'] = (self.scan_metadata['end_time'] - self.scan_metadata['start_time']).total_seconds()
        self.scan_metadata['total_vulnerabilities'] = len(self.vulnerabilities)
        
        # Risk metrics
        if self.vulnerabilities:
            risk_scores = [v['risk_score'] for v in self.vulnerabilities]
            self.scan_metadata['risk_metrics'] = {
                'average_risk_score': sum(risk_scores) / len(risk_scores),
                'max_risk_score': max(risk_scores),
                'critical_count': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high_count': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium_count': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low_count': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        
        return self.vulnerabilities, self.scan_metadata

    def _check_scan_timeout(self) -> bool:
        """Check if scan has exceeded max_scan_time"""
        if self.max_scan_time is None or self.scan_start_time is None:
            return False
        
        elapsed = (datetime.now() - self.scan_start_time).total_seconds()
        if elapsed >= self.max_scan_time:
            if not self.scan_interrupted:
                print(f"\n{Fore.YELLOW}⏰ Tempo máximo de scan atingido ({self.max_scan_time}s)")
                print(f"{Fore.YELLOW}   Finalizando scan com vulnerabilidades encontradas até o momento...")
                self.scan_interrupted = True
                self.scan_metadata['interrupted'] = True
                self.scan_metadata['interruption_reason'] = 'max_scan_time_exceeded'
            return True
        return False
    
def main():
    """Main function with enhanced CLI interface"""
    parser = argparse.ArgumentParser(
        description='Enhanced Web Security Scanner - Conceito A',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python scanner.py -u http://example.com
  python scanner.py -u https://site.com --timeout 30 --format json,csv
  python scanner.py -u http://test.com --output /path/to/reports/
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL alvo para scanning')
    parser.add_argument('-t', '--timeout', type=int, default=20, help='Timeout para requisições (padrão: 20s)')
    parser.add_argument('--format', default='console,json', help='Formatos de relatório: console,json,csv,markdown')
    parser.add_argument('--output', default='./', help='Diretório para salvar relatórios')
    
    args = parser.parse_args()
    
    print(f"{Fore.MAGENTA}" + "="*80)
    print(f"{Fore.MAGENTA}🔍        ENHANCED WEB SECURITY SCANNER (Conceito A)")
    print(f"{Fore.MAGENTA}" + "="*80)
    
    scanner = EnhancedWebSecurityScanner(args.url, args.timeout)
    vulnerabilities, metadata = scanner.perform_comprehensive_scan()
    
    # Generate reports
    report_generator = AdvancedReportGeneratorA(args.output)
    formats = [f.strip() for f in args.format.split(',')]
    
    report_generator.generate_reports(vulnerabilities, metadata, formats)
    
    # Display summary
    print(f"\n{Fore.MAGENTA}" + "="*80)
    print(f"{Fore.MAGENTA}📊        SCAN SUMMARY (Conceito A)")
    print(f"{Fore.MAGENTA}" + "="*80)
    print(f"🎯 Target: {args.url}")
    print(f"📊 Scan ID: {metadata['scan_id']}")
    print(f"⏱️  Duration: {metadata['duration']:.2f} seconds")
    print(f"🔢 Total Vulnerabilities: {len(vulnerabilities)}")
    print(f"📡 Total Requests: {metadata['total_requests']}")
    
    if 'risk_metrics' in metadata:
        risk = metadata['risk_metrics']
        print(f"\n🎯 RISK ANALYSIS:")
        print(f"⚠️  Critical: {risk['critical_count']}")
        print(f"🔴 High: {risk['high_count']}")
        print(f"🟠 Medium: {risk['medium_count']}")
        print(f"🟡 Low: {risk['low_count']}")
        print(f"📊 Average Risk Score: {risk['average_risk_score']:.1f}/10")
        print(f"🚨 Maximum Risk Score: {risk['max_risk_score']:.1f}/10")
    
    if vulnerabilities:
        print(f"\n📋 VULNERABILITY BREAKDOWN:")
        for vuln_type, count in metadata['vulnerabilities_by_type'].items():
            print(f"   {vuln_type}: {count}")
            
    print(f"\n{Fore.GREEN}✅ Relatórios salvos em: {args.output}")

if __name__ == "__main__":
    main()
