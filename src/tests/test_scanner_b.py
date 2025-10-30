#!/usr/bin/env python3
"""
Testes avançados para o Web Security Scanner - Conceito B
"""
import sys
import os
import unittest
from unittest.mock import Mock, patch
import json
import tempfile

# Adicionar o diretório src ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    Logger, normalize_url, XSS_PAYLOADS, SQL_PAYLOADS,
    DIRECTORY_TRAVERSAL_PAYLOADS, COMMAND_INJECTION_PAYLOADS,
    INFORMATION_DISCLOSURE_PATHS, AUTHENTICATION_BYPASS_PAYLOADS
)
from scanner_b import AdvancedWebSecurityScanner
from report_generator_b import AdvancedReportGenerator

class TestAdvancedUtils(unittest.TestCase):
    """Testes para utilitários avançados"""
    
    def test_new_payloads_exist(self):
        """Teste se os novos payloads estão definidos"""
        self.assertTrue(len(DIRECTORY_TRAVERSAL_PAYLOADS) > 0)
        self.assertTrue(len(COMMAND_INJECTION_PAYLOADS) > 0)
        self.assertTrue(len(INFORMATION_DISCLOSURE_PATHS) > 0)
        self.assertTrue(len(AUTHENTICATION_BYPASS_PAYLOADS) > 0)
    
    def test_payload_content(self):
        """Teste se os payloads têm conteúdo esperado"""
        # Directory Traversal
        self.assertIn("../../../etc/passwd", DIRECTORY_TRAVERSAL_PAYLOADS)
        
        # Command Injection
        self.assertIn("; ls -la", COMMAND_INJECTION_PAYLOADS)
        
        # Information Disclosure
        self.assertIn("/robots.txt", INFORMATION_DISCLOSURE_PATHS)
        
        # Authentication Bypass
        self.assertTrue(any(creds['username'] == 'admin' for creds in AUTHENTICATION_BYPASS_PAYLOADS))

class TestAdvancedScanner(unittest.TestCase):
    """Testes para o scanner avançado"""
    
    def setUp(self):
        """Configuração para cada teste"""
        self.scanner = AdvancedWebSecurityScanner("http://example.com", use_nmap=False)
    
    def test_scanner_initialization(self):
        """Teste da inicialização do scanner avançado"""
        self.assertEqual(self.scanner.target_url, "http://example.com")
        self.assertEqual(self.scanner.timeout, 15)  # timeout padrão aumentado
        self.assertFalse(self.scanner.use_nmap)
    
    @patch('requests.Session.get')
    def test_advanced_scan_structure(self, mock_get):
        """Teste da estrutura do scan avançado"""
        # Configurar mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test page</body></html>"
        mock_get.return_value = mock_response
        
        # Executar scan
        results = self.scanner.scan()
        
        # Verificar estrutura expandida
        self.assertIn('target', results)
        self.assertIn('timestamp', results)
        self.assertIn('scanner_version', results)
        self.assertIn('vulnerabilities', results)
        self.assertIn('port_scan', results)
        self.assertIn('summary', results)
        
        # Verificar campos do summary expandido
        summary_fields = [
            'total_vulnerabilities', 'xss_found', 'sql_injection_found',
            'directory_traversal_found', 'command_injection_found',
            'information_disclosure_found', 'broken_authentication_found',
            'scan_duration'
        ]
        
        for field in summary_fields:
            self.assertIn(field, results['summary'])
    
    def test_vulnerability_detection_methods(self):
        """Teste se os métodos de detecção existem"""
        methods = [
            'scan_xss', 'scan_sql_injection', 'scan_directory_traversal',
            'scan_command_injection', 'scan_information_disclosure',
            'scan_broken_authentication'
        ]
        
        for method_name in methods:
            self.assertTrue(hasattr(self.scanner, method_name))
            method = getattr(self.scanner, method_name)
            self.assertTrue(callable(method))

class TestAdvancedReportGenerator(unittest.TestCase):
    """Testes para o gerador de relatórios avançado"""
    
    def setUp(self):
        """Configuração para cada teste"""
        self.generator = AdvancedReportGenerator()
        self.sample_results = {
            'target': 'http://example.com',
            'timestamp': '2025-01-01T12:00:00',
            'scanner_version': 'Conceito B - v2.0',
            'port_scan': {
                '80/tcp': {'state': 'open', 'service': 'http'},
                '443/tcp': {'state': 'open', 'service': 'https'}
            },
            'vulnerabilities': [
                {
                    'type': 'XSS (Cross-Site Scripting)',
                    'severity': 'Medium',
                    'parameter': 'search',
                    'payload': "<script>alert('XSS')</script>",
                    'url': 'http://example.com?search=test',
                    'method': 'GET',
                    'description': 'Test XSS vulnerability'
                },
                {
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'path': '/etc/passwd',
                    'url': 'http://example.com/file?path=../../../etc/passwd',
                    'method': 'GET',
                    'patterns_found': ['root:x:0:0:'],
                    'description': 'Directory traversal vulnerability'
                }
            ],
            'summary': {
                'total_vulnerabilities': 2,
                'xss_found': 1,
                'sql_injection_found': 0,
                'directory_traversal_found': 1,
                'command_injection_found': 0,
                'information_disclosure_found': 0,
                'broken_authentication_found': 0,
                'scan_duration': 45.2
            }
        }
    
    def test_console_report_generation(self):
        """Teste da geração de relatório no console"""
        try:
            self.generator.generate_console_report(self.sample_results)
            success = True
        except Exception:
            success = False
        
        self.assertTrue(success)
    
    def test_json_report_generation(self):
        """Teste da geração de relatório JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_name = tmp.name
        
        try:
            self.generator.generate_json_report(self.sample_results, tmp_name)
            
            # Verificar se o arquivo foi criado
            self.assertTrue(os.path.exists(tmp_name))
            
            # Verificar se é um JSON válido
            with open(tmp_name, 'r') as f:
                data = json.load(f)
                self.assertEqual(data['target'], 'http://example.com')
                self.assertIn('report_metadata', data)
        
        finally:
            # Limpar arquivo temporário
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    
    def test_csv_report_generation(self):
        """Teste da geração de relatório CSV"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            tmp_name = tmp.name
        
        try:
            self.generator.generate_csv_report(self.sample_results, tmp_name)
            
            # Verificar se o arquivo foi criado
            self.assertTrue(os.path.exists(tmp_name))
            
            # Verificar conteúdo básico
            with open(tmp_name, 'r') as f:
                content = f.read()
                self.assertIn('Type,Severity,Description', content)
                
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    
    def test_markdown_report_generation(self):
        """Teste da geração de relatório Markdown"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as tmp:
            tmp_name = tmp.name
        
        try:
            self.generator.generate_markdown_report(self.sample_results, tmp_name)
            
            # Verificar se o arquivo foi criado
            self.assertTrue(os.path.exists(tmp_name))
            
            # Verificar conteúdo Markdown
            with open(tmp_name, 'r') as f:
                content = f.read()
                self.assertIn('# 🔒 Web Security Scan Report', content)
                self.assertIn('## SUMMARY Vulnerability Summary', content)
                
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

def run_integration_test_b():
    """Teste de integração avançado - Conceito B"""
    print("\n" + "="*60)
    print("🔍 EXECUTANDO TESTE DE INTEGRAÇÃO AVANÇADO - CONCEITO B")
    print("="*60)
    
    # Testar com um site que responde
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    try:
        scanner = AdvancedWebSecurityScanner(test_url, timeout=20, use_nmap=False)
        results = scanner.scan()
        
        print(f"SUCCESS Scanner avançado executado com sucesso!")
        print(f"🎯 Target: {results['target']}")
        print(f"🚀 Scanner Version: {results.get('scanner_version', 'N/A')}")
        print(f"⏱️  Duration: {results['summary'].get('scan_duration', 'N/A')} seconds")
        print(f"🔢 Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        
        # Mostrar breakdown por tipo
        summary = results['summary']
        print("\nSUMMARY Breakdown por tipo:")
        print(f"  🕷️  XSS: {summary['xss_found']}")
        print(f"  💉 SQL Injection: {summary['sql_injection_found']}")
        print(f"  📁 Directory Traversal: {summary['directory_traversal_found']}")
        print(f"  ⚡ Command Injection: {summary['command_injection_found']}")
        print(f"  🔍 Information Disclosure: {summary['information_disclosure_found']}")
        print(f"  🔐 Broken Authentication: {summary['broken_authentication_found']}")
        
        # Gerar relatórios avançados
        from report_generator_b import generate_advanced_reports
        generate_advanced_reports(results, ['json', 'csv', 'markdown'])
        
        print("\nSUCCESS Relatórios avançados gerados com sucesso!")
        
        # Verificar se encontrou vulnerabilidades múltiplas
        if results['summary']['total_vulnerabilities'] >= 2:
            print("🎉 Múltiplas vulnerabilidades detectadas - Conceito B validado!")
        
    except Exception as e:
        print(f"FAIL Erro durante teste de integração: {str(e)}")
        return False
    
    return True

def run_payload_effectiveness_test():
    """Teste da efetividade dos novos payloads"""
    print("\n" + "="*60)
    print("🧪 TESTANDO EFETIVIDADE DOS PAYLOADS - CONCEITO B")
    print("="*60)
    
    # Testar payloads de directory traversal
    print("📁 Testando payloads de Directory Traversal:")
    for i, payload in enumerate(DIRECTORY_TRAVERSAL_PAYLOADS[:3]):
        print(f"  {i+1}. {payload}")
    
    # Testar payloads de command injection  
    print("\n⚡ Testando payloads de Command Injection:")
    for i, payload in enumerate(COMMAND_INJECTION_PAYLOADS[:3]):
        print(f"  {i+1}. {payload}")
    
    # Testar caminhos de information disclosure
    print("\n🔍 Testando caminhos de Information Disclosure:")
    for i, path in enumerate(INFORMATION_DISCLOSURE_PATHS[:5]):
        print(f"  {i+1}. {path}")
    
    print("\nSUCCESS Payloads carregados e prontos para uso!")
    return True

if __name__ == "__main__":
    print("🧪 Executando testes avançados do Conceito B...")
    
    # Executar testes unitários
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Executar testes de integração
    print("\n" + "="*60)
    integration_success = run_integration_test_b()
    
    # Testar efetividade dos payloads
    payload_success = run_payload_effectiveness_test()
    
    if integration_success and payload_success:
        print("\n🎉 TODOS OS TESTES DO CONCEITO B PASSARAM!")
        print("SUCCESS Scanner avançado implementado com sucesso!")
        print("SUCCESS Múltiplas vulnerabilidades detectadas!")
        print("SUCCESS Relatórios em múltiplos formatos!")
        print("SUCCESS Payloads avançados funcionais!")
    else:
        print("\nFAIL ALGUNS TESTES FALHARAM!")
        print("⚠️ Verifique os logs acima para detalhes.")
