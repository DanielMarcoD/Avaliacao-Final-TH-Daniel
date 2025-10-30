#!/usr/bin/env python3
"""
Web Security Scanner - Conceito C
Ferramenta básica para detecção de vulnerabilidades XSS e SQL Injection
"""
import requests
import argparse
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any
import sys
import os

# Adicionar o diretório src ao path para importações
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import (
    Logger, normalize_url, extract_forms, extract_parameters,
    XSS_PAYLOADS, SQL_PAYLOADS, check_error_patterns
)

class WebSecurityScanner:
    """Scanner básico de segurança web"""
    
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = normalize_url(target_url)
        self.timeout = timeout
        self.logger = Logger()
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Headers para simular um browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def scan(self) -> Dict[str, Any]:
        """Executa o scan completo"""
        self.logger.info(f"Iniciando scan em: {self.target_url}")
        
        scan_results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'xss_found': 0,
                'sql_injection_found': 0
            }
        }
        
        try:
            # Verificar se o site está acessível
            response = self.session.get(self.target_url, timeout=self.timeout)
            self.logger.info(f"Status da resposta: {response.status_code}")
            
            if response.status_code == 200:
                # Scan de XSS
                xss_vulns = self.scan_xss()
                scan_results['vulnerabilities'].extend(xss_vulns)
                scan_results['summary']['xss_found'] = len(xss_vulns)
                
                # Scan de SQL Injection
                sql_vulns = self.scan_sql_injection()
                scan_results['vulnerabilities'].extend(sql_vulns)
                scan_results['summary']['sql_injection_found'] = len(sql_vulns)
                
                scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
                
            else:
                self.logger.error(f"Não foi possível acessar o site. Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erro ao conectar com o site: {str(e)}")
        
        return scan_results
    
    def scan_xss(self) -> List[Dict[str, Any]]:
        """Scan para vulnerabilidades XSS"""
        self.logger.info("Iniciando scan de XSS...")
        vulnerabilities = []
        
        try:
            # Testar parâmetros GET existentes
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
            self.logger.error(f"Erro durante scan XSS: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"Encontradas {len(vulnerabilities)} vulnerabilidades XSS!")
        else:
            self.logger.success("Nenhuma vulnerabilidade XSS encontrada")
        
        return vulnerabilities
    
    def scan_sql_injection(self) -> List[Dict[str, Any]]:
        """Scan para vulnerabilidades SQL Injection"""
        self.logger.info("Iniciando scan de SQL Injection...")
        vulnerabilities = []
        
        try:
            # Testar parâmetros GET existentes
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
            self.logger.error(f"Erro durante scan SQL: {str(e)}")
        
        if vulnerabilities:
            self.logger.warning(f"Encontradas {len(vulnerabilities)} vulnerabilidades SQL Injection!")
        else:
            self.logger.success("Nenhuma vulnerabilidade SQL Injection encontrada")
        
        return vulnerabilities
    
    def _test_xss_parameters(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Testa XSS em parâmetros GET"""
        vulnerabilities = []
        
        for param_name, original_value in params.items():
            self.logger.info(f"Testando XSS no parâmetro: {param_name}")
            
            for payload in XSS_PAYLOADS[:3]:  # Testar apenas os 3 primeiros payloads
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Construir URL com payload
                parsed_url = urllib.parse.urlparse(self.target_url)
                query_string = urllib.parse.urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Verificar se o payload foi refletido
                    if payload in response.text:
                        vulnerability = {
                            'type': 'XSS (Cross-Site Scripting)',
                            'severity': 'Medium',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'description': f'Possível XSS refletido no parâmetro "{param_name}"'
                        }
                        vulnerabilities.append(vulnerability)
                        self.logger.warning(f"XSS encontrado no parâmetro {param_name}!")
                        break  # Parar no primeiro payload que funciona
                        
                except Exception as e:
                    self.logger.error(f"Erro testando XSS em {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def _test_xss_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Testa XSS em formulários"""
        vulnerabilities = []
        
        if not form['inputs']:
            return vulnerabilities
        
        self.logger.info(f"Testando XSS em formulário (action: {form['action']})")
        
        for payload in XSS_PAYLOADS[:2]:  # Testar apenas 2 payloads por formulário
            form_data = {}
            
            # Preparar dados do formulário
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'search', 'email']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            if not form_data:
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
                
                # Enviar dados
                if form['method'] == 'post':
                    response = self.session.post(target_url, data=form_data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=form_data, timeout=self.timeout)
                
                # Verificar se o payload foi refletido
                if payload in response.text:
                    vulnerability = {
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'Medium',
                        'form_action': action,
                        'payload': payload,
                        'method': form['method'].upper(),
                        'url': target_url,
                        'description': f'Possível XSS em formulário via {form["method"].upper()}'
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.warning("XSS encontrado em formulário!")
                    break
                    
            except Exception as e:
                self.logger.error(f"Erro testando XSS em formulário: {str(e)}")
        
        return vulnerabilities
    
    def _test_sql_parameters(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Testa SQL Injection em parâmetros GET"""
        vulnerabilities = []
        
        for param_name, original_value in params.items():
            self.logger.info(f"Testando SQL Injection no parâmetro: {param_name}")
            
            for payload in SQL_PAYLOADS[:3]:  # Testar apenas os 3 primeiros payloads
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Construir URL com payload
                parsed_url = urllib.parse.urlparse(self.target_url)
                query_string = urllib.parse.urlencode(test_params)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    # Verificar padrões de erro SQL
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
                            'description': f'Possível SQL Injection no parâmetro "{param_name}"'
                        }
                        vulnerabilities.append(vulnerability)
                        self.logger.warning(f"SQL Injection encontrado no parâmetro {param_name}!")
                        break
                        
                except Exception as e:
                    self.logger.error(f"Erro testando SQL em {param_name}: {str(e)}")
        
        return vulnerabilities
    
    def _test_sql_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Testa SQL Injection em formulários"""
        vulnerabilities = []
        
        if not form['inputs']:
            return vulnerabilities
        
        self.logger.info(f"Testando SQL Injection em formulário (action: {form['action']})")
        
        for payload in SQL_PAYLOADS[:2]:  # Testar apenas 2 payloads por formulário
            form_data = {}
            
            # Preparar dados do formulário
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'search', 'email', 'password']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            if not form_data:
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
                
                # Enviar dados
                if form['method'] == 'post':
                    response = self.session.post(target_url, data=form_data, timeout=self.timeout)
                else:
                    response = self.session.get(target_url, params=form_data, timeout=self.timeout)
                
                # Verificar padrões de erro SQL
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
                        'description': f'Possível SQL Injection em formulário via {form["method"].upper()}'
                    }
                    vulnerabilities.append(vulnerability)
                    self.logger.warning("SQL Injection encontrado em formulário!")
                    break
                    
            except Exception as e:
                self.logger.error(f"Erro testando SQL em formulário: {str(e)}")
        
        return vulnerabilities

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(
        description='Web Security Scanner - Conceito C',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python scanner.py -u http://testphp.vulnweb.com/
  python scanner.py -u https://example.com -t 15
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
        default=10,
        help='Timeout para requisições (segundos, padrão: 10)'
    )
    
    args = parser.parse_args()
    
    # Inicializar scanner
    scanner = WebSecurityScanner(args.url, args.timeout)
    
    # Executar scan
    results = scanner.scan()
    
    # Gerar relatório básico
    from report_generator import generate_basic_report
    generate_basic_report(results)

if __name__ == "__main__":
    main()
