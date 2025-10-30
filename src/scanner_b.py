#!/usr/bin/env python3
"""
Web Security Scanner - Conceito B (Automação e Integração)
Ferramenta avançada para detecção de múltiplas vulnerabilidades OWASP Top 10
"""
import requests
import argparse
import urllib.parse
import subprocess
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
import sys
import os
import time

# Adicionar o diretório src ao path para importações
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import (
    Logger, normalize_url, extract_forms, extract_parameters,
    XSS_PAYLOADS, SQL_PAYLOADS, DIRECTORY_TRAVERSAL_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS, INFORMATION_DISCLOSURE_PATHS,
    AUTHENTICATION_BYPASS_PAYLOADS, check_error_patterns
)

# Integração com ferramentas auxiliares - Conceito B
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️ Nmap não disponível. Instale com: pip install python-nmap")

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
    print("⚠️ ZAP API não disponível. Instale com: pip install python-owasp-zap-v2.4")

def check_nikto_available():
    """Verifica se Nikto está disponível no sistema"""
    try:
        result = subprocess.run(['nikto', '-Version'], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

NIKTO_AVAILABLE = check_nikto_available()
if not NIKTO_AVAILABLE:
    print("⚠️ Nikto não disponível. Instale com: apt-get install nikto")

class AdvancedWebSecurityScanner:
    """Scanner avançado de segurança web - Conceito B"""
    
    def __init__(self, target_url: str, timeout: int = 15, use_nmap: bool = True):
        self.target_url = normalize_url(target_url)
        self.timeout = timeout
        self.use_nmap = use_nmap
        self.logger = Logger("AdvancedScanner")
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Headers para simular um browser real
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def scan(self) -> Dict[str, Any]:
        """Executa o scan completo - Conceito B"""
        self.logger.info(f"🔍 Iniciando scan avançado em: {self.target_url}")
        
        scan_results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'scanner_version': 'Conceito B - v2.0',
            'vulnerabilities': [],
            'port_scan': {},
            'summary': {
                'total_vulnerabilities': 0,
                'xss_found': 0,
                'sql_injection_found': 0,
                'directory_traversal_found': 0,
                'command_injection_found': 0,
                'information_disclosure_found': 0,
                'broken_authentication_found': 0,
                'scan_duration': 0
            }
        }
        
        start_time = time.time()
        
        try:
            # 1. Port scanning (se habilitado)
            if self.use_nmap:
                scan_results['port_scan'] = self.run_port_scan()
            
            # Verificar se o site está acessível
            response = self.session.get(self.target_url, timeout=self.timeout)
            self.logger.info(f"✅ Status da resposta: {response.status_code}")
            
            if response.status_code == 200:
                # 2. Scan de vulnerabilidades
                self.logger.info("🎯 Iniciando testes de vulnerabilidades...")
                
                # XSS
                xss_vulns = self.scan_xss()
                scan_results['vulnerabilities'].extend(xss_vulns)
                scan_results['summary']['xss_found'] = len(xss_vulns)
                
                # SQL Injection
                sql_vulns = self.scan_sql_injection()
                scan_results['vulnerabilities'].extend(sql_vulns)
                scan_results['summary']['sql_injection_found'] = len(sql_vulns)
                
                # Directory Traversal
                dt_vulns = self.scan_directory_traversal()
                scan_results['vulnerabilities'].extend(dt_vulns)
                scan_results['summary']['directory_traversal_found'] = len(dt_vulns)
                
                # Command Injection
                ci_vulns = self.scan_command_injection()
                scan_results['vulnerabilities'].extend(ci_vulns)
                scan_results['summary']['command_injection_found'] = len(ci_vulns)
                
                # Information Disclosure
                id_vulns = self.scan_information_disclosure()
                scan_results['vulnerabilities'].extend(id_vulns)
                scan_results['summary']['information_disclosure_found'] = len(id_vulns)
                
                # Broken Authentication
                ba_vulns = self.scan_broken_authentication()
                scan_results['vulnerabilities'].extend(ba_vulns)
                scan_results['summary']['broken_authentication_found'] = len(ba_vulns)
                
                # Ferramentas auxiliares - Conceito B
                aux_vulns = self.scan_with_auxiliary_tools()
                scan_results['vulnerabilities'].extend(aux_vulns)
                scan_results['summary']['auxiliary_tools_found'] = len(aux_vulns)
                
                scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
                
            else:
                self.logger.error(f"❌ Não foi possível acessar o site. Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"❌ Erro ao conectar com o site: {str(e)}")
        
        # Calcular duração do scan
        end_time = time.time()
        scan_results['summary']['scan_duration'] = round(end_time - start_time, 2)
        
        return scan_results
    
    def run_port_scan(self) -> Dict[str, Any]:
        """Executa scan de portas usando nmap"""
        self.logger.info("🔌 Executando scan de portas...")
        
        try:
            import nmap
            nm = nmap.PortScanner()
            
            # Extrair host da URL
            parsed_url = urllib.parse.urlparse(self.target_url)
            host = parsed_url.netloc.split(':')[0]
            
            # Scan das portas mais comuns
            result = nm.scan(host, '21,22,23,25,53,80,110,443,993,995,8080,8443')
            
            port_info = {}
            if host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    for port in ports:
                        state = nm[host][protocol][port]['state']
                        service = nm[host][protocol][port].get('name', 'unknown')
                        port_info[f"{port}/{protocol}"] = {
                            'state': state,
                            'service': service
                        }
            
            self.logger.success(f"✅ Scan de portas concluído: {len(port_info)} portas verificadas")
            return port_info
            
        except ImportError:
            self.logger.warning("⚠️ python-nmap não disponível, pulando scan de portas")
            return {}
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan de portas: {str(e)}")
            return {}
    
    def scan_xss(self) -> List[Dict[str, Any]]:
        """Scan avançado para XSS"""
        self.logger.info("🕷️ Iniciando scan avançado de XSS...")
        vulnerabilities = []
        
        try:
            # Testar parâmetros GET
            params = extract_parameters(self.target_url)
            if params:
                vulnerabilities.extend(self._test_xss_parameters(params))
            
            # Testar formulários
            response = self.session.get(self.target_url, timeout=self.timeout)
            forms = extract_forms(response.text)
            
            for form in forms:
                form_vulns = self._test_xss_form(form)
                vulnerabilities.extend(form_vulns)
                
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan XSS: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades XSS!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade XSS encontrada")
        
        return vulnerabilities
    
    def scan_sql_injection(self) -> List[Dict[str, Any]]:
        """Scan avançado para SQL Injection"""
        self.logger.info("💉 Iniciando scan avançado de SQL Injection...")
        vulnerabilities = []
        
        try:
            # Testar parâmetros GET
            params = extract_parameters(self.target_url)
            if params:
                vulnerabilities.extend(self._test_sql_parameters(params))
            
            # Testar formulários
            response = self.session.get(self.target_url, timeout=self.timeout)
            forms = extract_forms(response.text)
            
            for form in forms:
                form_vulns = self._test_sql_form(form)
                vulnerabilities.extend(form_vulns)
                
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan SQL: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades SQL Injection!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade SQL Injection encontrada")
        
        return vulnerabilities
    
    def scan_directory_traversal(self) -> List[Dict[str, Any]]:
        """Scan para Directory Traversal"""
        self.logger.info("📁 Iniciando scan de Directory Traversal...")
        vulnerabilities = []
        
        try:
            # Testar em parâmetros existentes
            params = extract_parameters(self.target_url)
            if params:
                for param_name in params.keys():
                    for payload in DIRECTORY_TRAVERSAL_PAYLOADS[:4]:  # Teste 4 payloads
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        parsed_url = urllib.parse.urlparse(self.target_url)
                        query_string = urllib.parse.urlencode(test_params)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Verificar padrões de directory traversal
                            dt_patterns = check_error_patterns(response.text, 'directory_traversal')
                            
                            if dt_patterns:
                                vulnerability = {
                                    'type': 'Directory Traversal',
                                    'severity': 'High',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': test_url,
                                    'method': 'GET',
                                    'patterns_found': dt_patterns,
                                    'description': f'Possível Directory Traversal no parâmetro "{param_name}"'
                                }
                                vulnerabilities.append(vulnerability)
                                break
                                
                        except Exception as e:
                            continue
            
            # Testar caminhos comuns
            for path in INFORMATION_DISCLOSURE_PATHS[:5]:  # Teste 5 caminhos
                test_url = self.target_url.rstrip('/') + path
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        dt_patterns = check_error_patterns(response.text, 'directory_traversal')
                        
                        if dt_patterns:
                            vulnerability = {
                                'type': 'Directory Traversal',
                                'severity': 'Medium',
                                'path': path,
                                'url': test_url,
                                'method': 'GET',
                                'patterns_found': dt_patterns,
                                'description': f'Acesso não autorizado ao caminho "{path}"'
                            }
                            vulnerabilities.append(vulnerability)
                            
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan Directory Traversal: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades Directory Traversal!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade Directory Traversal encontrada")
        
        return vulnerabilities
    
    def scan_command_injection(self) -> List[Dict[str, Any]]:
        """Scan para Command Injection"""
        self.logger.info("⚡ Iniciando scan de Command Injection...")
        vulnerabilities = []
        
        try:
            params = extract_parameters(self.target_url)
            if params:
                for param_name in params.keys():
                    for payload in COMMAND_INJECTION_PAYLOADS[:3]:  # Teste 3 payloads
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        parsed_url = urllib.parse.urlparse(self.target_url)
                        query_string = urllib.parse.urlencode(test_params)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                        
                        try:
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # Verificar padrões de command injection
                            ci_patterns = check_error_patterns(response.text, 'command_injection')
                            
                            if ci_patterns:
                                vulnerability = {
                                    'type': 'Command Injection',
                                    'severity': 'Critical',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': test_url,
                                    'method': 'GET',
                                    'patterns_found': ci_patterns,
                                    'description': f'Possível Command Injection no parâmetro "{param_name}"'
                                }
                                vulnerabilities.append(vulnerability)
                                break
                                
                        except Exception:
                            continue
                            
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan Command Injection: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades Command Injection!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade Command Injection encontrada")
        
        return vulnerabilities
    
    def scan_information_disclosure(self) -> List[Dict[str, Any]]:
        """Scan para Information Disclosure"""
        self.logger.info("🔍 Iniciando scan de Information Disclosure...")
        vulnerabilities = []
        
        try:
            for path in INFORMATION_DISCLOSURE_PATHS:
                test_url = self.target_url.rstrip('/') + path
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Verificar padrões de information disclosure
                        id_patterns = check_error_patterns(response.text, 'information_disclosure')
                        
                        if id_patterns or len(response.text) > 100:  # Arquivo com conteúdo
                            severity = 'High' if any(pattern in response.text.lower() 
                                                  for pattern in ['password', 'key', 'secret', 'token']) else 'Medium'
                            
                            vulnerability = {
                                'type': 'Information Disclosure',
                                'severity': severity,
                                'path': path,
                                'url': test_url,
                                'method': 'GET',
                                'response_size': len(response.text),
                                'patterns_found': id_patterns,
                                'description': f'Informação sensível exposta em "{path}"'
                            }
                            vulnerabilities.append(vulnerability)
                            
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan Information Disclosure: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades Information Disclosure!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade Information Disclosure encontrada")
        
        return vulnerabilities
    
    def scan_broken_authentication(self) -> List[Dict[str, Any]]:
        """Scan para Broken Authentication"""
        self.logger.info("🔐 Iniciando scan de Broken Authentication...")
        vulnerabilities = []
        
        try:
            # Procurar por formulários de login
            response = self.session.get(self.target_url, timeout=self.timeout)
            forms = extract_forms(response.text)
            
            login_forms = []
            for form in forms:
                # Identificar formulários de login
                has_password = any(inp['type'] == 'password' for inp in form['inputs'])
                has_user_field = any(inp['name'].lower() in ['username', 'user', 'email', 'login'] 
                                   for inp in form['inputs'])
                
                if has_password and has_user_field:
                    login_forms.append(form)
            
            # Testar credenciais padrão
            for form in login_forms[:2]:  # Máximo 2 formulários
                for creds in AUTHENTICATION_BYPASS_PAYLOADS[:4]:  # Teste 4 credenciais
                    form_data = {}
                    
                    for input_field in form['inputs']:
                        if input_field['name']:
                            field_name = input_field['name'].lower()
                            if field_name in ['username', 'user', 'email', 'login']:
                                form_data[input_field['name']] = creds['username']
                            elif input_field['type'] == 'password':
                                form_data[input_field['name']] = creds['password']
                            else:
                                form_data[input_field['name']] = input_field['value'] or ''
                    
                    if len(form_data) < 2:
                        continue
                    
                    try:
                        # Determinar URL de destino
                        action = form['action']
                        if action:
                            if action.startswith('http'):
                                target_url = action
                            else:
                                target_url = urllib.parse.urljoin(self.target_url, action)
                        else:
                            target_url = self.target_url
                        
                        # Tentar login
                        if form['method'] == 'post':
                            login_response = self.session.post(target_url, data=form_data, timeout=self.timeout)
                        else:
                            login_response = self.session.get(target_url, params=form_data, timeout=self.timeout)
                        
                        # Verificar se o login foi bem-sucedido
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin']
                        error_indicators = ['error', 'invalid', 'incorrect', 'failed', 'denied']
                        
                        response_text_lower = login_response.text.lower()
                        
                        has_success = any(indicator in response_text_lower for indicator in success_indicators)
                        has_error = any(indicator in response_text_lower for indicator in error_indicators)
                        
                        # Se há indicadores de sucesso e não há indicadores de erro
                        if has_success and not has_error and login_response.status_code == 200:
                            vulnerability = {
                                'type': 'Broken Authentication',
                                'severity': 'Critical',
                                'credentials': f"{creds['username']}:{creds['password']}",
                                'url': target_url,
                                'method': form['method'].upper(),
                                'form_action': action,
                                'description': f'Credenciais fracas permitiram acesso: {creds["username"]}:{creds["password"]}'
                            }
                            vulnerabilities.append(vulnerability)
                            break
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.error(f"❌ Erro durante scan Broken Authentication: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"⚠️ Encontradas {len(vulnerabilities)} vulnerabilidades Broken Authentication!")
        else:
            self.logger.success("✅ Nenhuma vulnerabilidade Broken Authentication encontrada")
        
        return vulnerabilities
    
    # Métodos auxiliares dos scans básicos (XSS e SQL) - versões otimizadas
    def _test_xss_parameters(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Versão otimizada do teste XSS em parâmetros"""
        vulnerabilities = []
        
        for param_name, original_value in params.items():
            for payload in XSS_PAYLOADS[:4]:  # Teste mais payloads
                test_params = params.copy()
                test_params[param_name] = payload
                
                parsed_url = urllib.parse.urlparse(self.target_url)
                query_string = urllib.parse.urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if payload in response.text:
                        vulnerability = {
                            'type': 'XSS (Cross-Site Scripting)',
                            'severity': 'Medium',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'description': f'XSS refletido no parâmetro "{param_name}"'
                        }
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _test_xss_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Versão otimizada do teste XSS em formulários"""
        vulnerabilities = []
        
        if not form['inputs']:
            return vulnerabilities
        
        for payload in XSS_PAYLOADS[:3]:
            form_data = {}
            
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'search', 'email']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            if not form_data:
                continue
            
            try:
                action = form['action']
                if action:
                    if action.startswith('http'):
                        target_url = action
                    else:
                        target_url = urllib.parse.urljoin(self.target_url, action)
                else:
                    target_url = self.target_url
                
                if form['method'] == 'post':
                    response = self.session.post(target_url, data=form_data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=form_data, timeout=self.timeout)
                
                if payload in response.text:
                    vulnerability = {
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'Medium',
                        'form_action': action,
                        'payload': payload,
                        'method': form['method'].upper(),
                        'url': target_url,
                        'description': f'XSS em formulário via {form["method"].upper()}'
                    }
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception:
                continue
        
        return vulnerabilities
    
    def _test_sql_parameters(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Versão otimizada do teste SQL em parâmetros"""
        vulnerabilities = []
        
        for param_name, original_value in params.items():
            for payload in SQL_PAYLOADS[:5]:  # Teste mais payloads
                test_params = params.copy()
                test_params[param_name] = payload
                
                parsed_url = urllib.parse.urlparse(self.target_url)
                query_string = urllib.parse.urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    sql_errors = check_error_patterns(response.text, 'sql_error')
                    
                    if sql_errors:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'error_patterns': sql_errors,
                            'description': f'SQL Injection no parâmetro "{param_name}"'
                        }
                        vulnerabilities.append(vulnerability)
                        break
                        
                except Exception:
                    continue
        
        return vulnerabilities
    
    def _test_sql_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Versão otimizada do teste SQL em formulários"""
        vulnerabilities = []
        
        if not form['inputs']:
            return vulnerabilities
        
        for payload in SQL_PAYLOADS[:3]:
            form_data = {}
            
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'search', 'email', 'password']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            if not form_data:
                continue
            
            try:
                action = form['action']
                if action:
                    if action.startswith('http'):
                        target_url = action
                    else:
                        target_url = urllib.parse.urljoin(self.target_url, action)
                else:
                    target_url = self.target_url
                
                if form['method'] == 'post':
                    response = self.session.post(target_url, data=form_data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=form_data, timeout=self.timeout)
                
                sql_errors = check_error_patterns(response.text, 'sql_error')
                
                if sql_errors:
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'form_action': action,
                        'payload': payload,
                        'method': form['method'].upper(),
                        'url': target_url,
                        'error_patterns': sql_errors,
                        'description': f'SQL Injection em formulário via {form["method"].upper()}'
                    }
                    vulnerabilities.append(vulnerability)
                    break
                    
            except Exception:
                continue
        
        return vulnerabilities

    def scan_with_zap_api(self) -> List[Dict[str, Any]]:
        """Integração com OWASP ZAP API - Conceito B"""
        vulnerabilities = []
        
        if not ZAP_AVAILABLE:
            self.logger.info("⚠️ ZAP API não disponível")
            return vulnerabilities
        
        try:
            # Conectar ao ZAP (assumindo que está rodando em localhost:8080)
            zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
            
            # Spider scan
            self.logger.info("🕷️ Executando ZAP Spider scan...")
            scan_id = zap.spider.scan(self.target_url)
            
            # Aguardar spider completar
            while int(zap.spider.status(scan_id)) < 100:
                time.sleep(2)
            
            # Active scan
            self.logger.info("🎯 Executando ZAP Active scan...")
            scan_id = zap.ascan.scan(self.target_url)
            
            # Aguardar active scan completar (limitado a 60s para demo)
            timeout = 60
            while int(zap.ascan.status(scan_id)) < 100 and timeout > 0:
                time.sleep(5)
                timeout -= 5
            
            # Obter alerts do ZAP
            alerts = zap.core.alerts()
            
            for alert in alerts:
                vulnerability = {
                    'type': f"ZAP: {alert.get('alert', 'Unknown')}",
                    'severity': self._map_zap_risk(alert.get('risk', 'Low')),
                    'url': alert.get('url', self.target_url),
                    'description': alert.get('description', 'Vulnerability detected by ZAP'),
                    'solution': alert.get('solution', 'No solution provided'),
                    'reference': alert.get('reference', ''),
                    'tool': 'OWASP ZAP',
                    'timestamp': datetime.now().isoformat()
                }
                vulnerabilities.append(vulnerability)
            
            self.logger.info(f"✅ ZAP encontrou {len(vulnerabilities)} vulnerabilidades")
            
        except Exception as e:
            self.logger.info(f"❌ Erro ao conectar com ZAP: {e}")
            
        return vulnerabilities
    
    def scan_with_nikto(self) -> List[Dict[str, Any]]:
        """Integração com Nikto scanner - Conceito B"""
        vulnerabilities = []
        
        if not NIKTO_AVAILABLE:
            self.logger.info("⚠️ Nikto não disponível")
            return vulnerabilities
        
        try:
            self.logger.info("🔍 Executando Nikto scan...")
            
            # Executar Nikto
            cmd = [
                'nikto', 
                '-h', self.target_url,
                '-Format', 'json',
                '-timeout', '30',
                '-maxtime', '120'  # Limite de 2 minutos
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            
            if result.returncode == 0:
                # Parse da saída JSON do Nikto
                try:
                    nikto_data = json.loads(result.stdout)
                    
                    if 'vulnerabilities' in nikto_data:
                        for vuln in nikto_data['vulnerabilities']:
                            vulnerability = {
                                'type': f"Nikto: {vuln.get('msg', 'Web Server Issue')}",
                                'severity': 'Medium',
                                'url': vuln.get('url', self.target_url),
                                'description': vuln.get('msg', 'Issue detected by Nikto'),
                                'method': vuln.get('method', 'GET'),
                                'tool': 'Nikto',
                                'timestamp': datetime.now().isoformat()
                            }
                            vulnerabilities.append(vulnerability)
                            
                except json.JSONDecodeError:
                    # Se JSON falhar, parse da saída texto
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '+' in line and ('OSVDB' in line or 'CVE' in line):
                            vulnerability = {
                                'type': 'Nikto: Web Server Vulnerability',
                                'severity': 'Medium',
                                'url': self.target_url,
                                'description': line.strip(),
                                'tool': 'Nikto',
                                'timestamp': datetime.now().isoformat()
                            }
                            vulnerabilities.append(vulnerability)
            
            self.logger.info(f"✅ Nikto encontrou {len(vulnerabilities)} issues")
            
        except subprocess.TimeoutExpired:
            self.logger.info("⏰ Nikto timeout - continuando...")
        except Exception as e:
            self.logger.info(f"❌ Erro ao executar Nikto: {e}")
            
        return vulnerabilities
    
    def _map_zap_risk(self, zap_risk: str) -> str:
        """Mapeia níveis de risco do ZAP para nosso padrão"""
        mapping = {
            'High': 'High',
            'Medium': 'Medium', 
            'Low': 'Low',
            'Informational': 'Info'
        }
        return mapping.get(zap_risk, 'Medium')

    def scan_with_auxiliary_tools(self) -> List[Dict[str, Any]]:
        """Executa scan com todas as ferramentas auxiliares disponíveis"""
        all_vulnerabilities = []
        
        self.logger.info("🔧 Iniciando integração com ferramentas auxiliares...")
        
        # ZAP API
        zap_vulns = self.scan_with_zap_api()
        all_vulnerabilities.extend(zap_vulns)
        
        # Nikto
        nikto_vulns = self.scan_with_nikto()
        all_vulnerabilities.extend(nikto_vulns)
        
        return all_vulnerabilities

def main():
    """Função principal do scanner avançado"""
    parser = argparse.ArgumentParser(
        description='Web Security Scanner Avançado - Conceito B',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python scanner_b.py -u http://testphp.vulnweb.com/
  python scanner_b.py -u https://example.com -t 20 --no-nmap
  python scanner_b.py -u http://site.com --format json,csv,markdown
        """
    )
    
    parser.add_argument(
        '-u', '--url', 
        required=True,
        help='URL alvo para scanning'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=15,
        help='Timeout para requisições (segundos, padrão: 15)'
    )
    
    parser.add_argument(
        '--no-nmap',
        action='store_true',
        help='Desabilitar scan de portas com nmap'
    )
    
    parser.add_argument(
        '--format',
        default='console,json,markdown',
        help='Formatos de relatório (console,json,csv,markdown)'
    )
    
    args = parser.parse_args()
    
    # Inicializar scanner
    scanner = AdvancedWebSecurityScanner(
        args.url, 
        args.timeout, 
        use_nmap=not args.no_nmap
    )
    
    # Executar scan
    results = scanner.scan()
    
    # Gerar relatórios nos formatos especificados
    from report_generator_b import generate_advanced_reports
    formats = [f.strip() for f in args.format.split(',')]
    generate_advanced_reports(results, formats)

if __name__ == "__main__":
    main()
