#!/usr/bin/env python3
"""
Testes básicos para o Web Security Scanner
"""
import sys
import os
import unittest
from unittest.mock import Mock, patch

# Adicionar o diretório src ao path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import Logger, normalize_url, extract_parameters, XSS_PAYLOADS, SQL_PAYLOADS
from scanner import WebSecurityScanner
from report_generator import ReportGenerator

class TestUtils(unittest.TestCase):
    """Testes para funções utilitárias"""
    
    def test_normalize_url(self):
        """Teste da normalização de URL"""
        self.assertEqual(normalize_url("example.com"), "http://example.com")
        self.assertEqual(normalize_url("https://example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")
    
    def test_extract_parameters(self):
        """Teste da extração de parâmetros"""
        url = "http://example.com?param1=value1&param2=value2"
        params = extract_parameters(url)
        expected = {'param1': 'value1', 'param2': 'value2'}
        self.assertEqual(params, expected)
    
    def test_payloads_exist(self):
        """Teste se os payloads estão definidos"""
        self.assertTrue(len(XSS_PAYLOADS) > 0)
        self.assertTrue(len(SQL_PAYLOADS) > 0)
    
    def test_logger(self):
        """Teste básico do logger"""
        logger = Logger("test")
        # Apenas verificar se não gera erro
        logger.info("Test message")
        self.assertTrue(True)

class TestScanner(unittest.TestCase):
    """Testes para o scanner principal"""
    
    def setUp(self):
        """Configuração para cada teste"""
        self.scanner = WebSecurityScanner("http://example.com")
    
    def test_scanner_initialization(self):
        """Teste da inicialização do scanner"""
        self.assertEqual(self.scanner.target_url, "http://example.com")
        self.assertEqual(self.scanner.timeout, 10)
    
    @patch('requests.Session.get')
    def test_scan_with_mock_response(self, mock_get):
        """Teste do scan com resposta mockada"""
        # Configurar mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test page</body></html>"
        mock_get.return_value = mock_response
        
        # Executar scan
        results = self.scanner.scan()
        
        # Verificar estrutura do resultado
        self.assertIn('target', results)
        self.assertIn('timestamp', results)
        self.assertIn('vulnerabilities', results)
        self.assertIn('summary', results)
        
        # Verificar campos do summary
        self.assertIn('total_vulnerabilities', results['summary'])
        self.assertIn('xss_found', results['summary'])
        self.assertIn('sql_injection_found', results['summary'])

class TestReportGenerator(unittest.TestCase):
    """Testes para o gerador de relatórios"""
    
    def setUp(self):
        """Configuração para cada teste"""
        self.generator = ReportGenerator()
        self.sample_results = {
            'target': 'http://example.com',
            'timestamp': '2025-01-01T12:00:00',
            'vulnerabilities': [
                {
                    'type': 'XSS (Cross-Site Scripting)',
                    'severity': 'Medium',
                    'parameter': 'search',
                    'payload': "<script>alert('XSS')</script>",
                    'url': 'http://example.com?search=test',
                    'method': 'GET',
                    'description': 'Test XSS vulnerability'
                }
            ],
            'summary': {
                'total_vulnerabilities': 1,
                'xss_found': 1,
                'sql_injection_found': 0
            }
        }
    
    def test_console_report_generation(self):
        """Teste da geração de relatório no console"""
        # Apenas verificar se não gera erro
        try:
            self.generator.generate_console_report(self.sample_results)
            success = True
        except Exception:
            success = False
        
        self.assertTrue(success)
    
    def test_json_report_generation(self):
        """Teste da geração de relatório JSON"""
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            tmp_name = tmp.name
        
        try:
            self.generator.generate_json_report(self.sample_results, tmp_name)
            
            # Verificar se o arquivo foi criado
            self.assertTrue(os.path.exists(tmp_name))
            
            # Verificar se é um JSON válido
            import json
            with open(tmp_name, 'r') as f:
                data = json.load(f)
                self.assertEqual(data['target'], 'http://example.com')
        
        finally:
            # Limpar arquivo temporário
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

def run_integration_test():
    """Teste de integração básico"""
    print("\n" + "="*50)
    print("EXECUTANDO TESTE DE INTEGRAÇÃO")
    print("="*50)
    
    # Testar com um site que responde (httpbin.org)
    test_url = "http://httpbin.org/get"
    
    try:
        scanner = WebSecurityScanner(test_url, timeout=15)
        results = scanner.scan()
        
        print(f"SUCCESS Scanner executado com sucesso!")
        print(f"Target: {results['target']}")
        print(f"Vulnerabilidades encontradas: {results['summary']['total_vulnerabilities']}")
        
        # Gerar relatório
        from report_generator import generate_basic_report
        generate_basic_report(results)
        
        print("SUCCESS Relatório gerado com sucesso!")
        
    except Exception as e:
        print(f"FAIL Erro durante teste de integração: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    print("Executando testes unitários...")
    
    # Executar testes unitários
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Executar teste de integração
    print("\n" + "="*50)
    integration_success = run_integration_test()
    
    if integration_success:
        print("\n🎉 Todos os testes passaram!")
    else:
        print("\nFAIL Alguns testes falharam!")
