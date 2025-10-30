#!/usr/bin/env python3
"""
Gerador de relatórios para o Web Security Scanner
"""
import json
from datetime import datetime
from typing import Dict, Any
import os
import sys

# Adicionar o diretório src ao path para importações
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Logger

class ReportGenerator:
    """Gerador de relatórios básicos"""
    
    def __init__(self):
        self.logger = Logger("ReportGenerator")
    
    def generate_console_report(self, results: Dict[str, Any]):
        """Gera relatório para exibição no console"""
        print("\n" + "="*60)
        print("           WEB SECURITY SCAN REPORT")
        print("="*60)
        print(f"Target: {results['target']}")
        print(f"Timestamp: {results['timestamp']}")
        print(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print("-"*60)
        
        if results['vulnerabilities']:
            print("\nVULNERABILITIES FOUND:")
            print("-"*30)
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"\n[{i}] {vuln['type']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Method: {vuln.get('method', 'N/A')}")
                print(f"    URL: {vuln.get('url', 'N/A')}")
                
                if 'parameter' in vuln:
                    print(f"    Parameter: {vuln['parameter']}")
                if 'form_action' in vuln:
                    print(f"    Form Action: {vuln['form_action']}")
                    
                print(f"    Payload: {vuln['payload']}")
                
                if 'error_patterns' in vuln:
                    print(f"    Error Patterns Found: {len(vuln['error_patterns'])}")
        else:
            print("\n✅ Nenhuma vulnerabilidade encontrada!")
        
        print("\n" + "="*60)
        print("Summary:")
        print(f"  XSS Vulnerabilities: {results['summary']['xss_found']}")
        print(f"  SQL Injection Vulnerabilities: {results['summary']['sql_injection_found']}")
        print("="*60 + "\n")
    
    def generate_log_file(self, results: Dict[str, Any], filename: str = None):
        """Gera arquivo de log detalhado"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.log"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("WEB SECURITY SCAN REPORT\n")
                f.write("="*80 + "\n")
                f.write(f"Target URL: {results['target']}\n")
                f.write(f"Scan Time: {results['timestamp']}\n")
                f.write(f"Total Vulnerabilities Found: {results['summary']['total_vulnerabilities']}\n")
                f.write("-"*80 + "\n\n")
                
                if results['vulnerabilities']:
                    f.write("DETAILED VULNERABILITY REPORT:\n")
                    f.write("-"*40 + "\n")
                    
                    for i, vuln in enumerate(results['vulnerabilities'], 1):
                        f.write(f"\nVulnerability #{i}\n")
                        f.write("-"*20 + "\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Severity: {vuln['severity']}\n")
                        f.write(f"Description: {vuln['description']}\n")
                        f.write(f"Method: {vuln.get('method', 'N/A')}\n")
                        f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                        
                        if 'parameter' in vuln:
                            f.write(f"Parameter: {vuln['parameter']}\n")
                        if 'form_action' in vuln:
                            f.write(f"Form Action: {vuln['form_action']}\n")
                            
                        f.write(f"Payload Used: {vuln['payload']}\n")
                        
                        if 'error_patterns' in vuln:
                            f.write(f"Error Patterns Found: {vuln['error_patterns']}\n")
                        
                        f.write("\n")
                else:
                    f.write("No vulnerabilities found during the scan.\n")
                
                f.write("\n" + "="*80 + "\n")
                f.write("SCAN SUMMARY\n")
                f.write("="*80 + "\n")
                f.write(f"XSS Vulnerabilities: {results['summary']['xss_found']}\n")
                f.write(f"SQL Injection Vulnerabilities: {results['summary']['sql_injection_found']}\n")
                f.write(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}\n")
                f.write("="*80 + "\n")
            
            self.logger.success(f"Relatório salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar relatório: {str(e)}")
    
    def generate_json_report(self, results: Dict[str, Any], filename: str = None):
        """Gera relatório em formato JSON"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.success(f"Relatório JSON salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar relatório JSON: {str(e)}")

def generate_basic_report(results: Dict[str, Any]):
    """Função de conveniência para gerar relatório básico"""
    generator = ReportGenerator()
    
    # Relatório no console
    generator.generate_console_report(results)
    
    # Arquivo de log
    generator.generate_log_file(results)
    
    # Arquivo JSON
    generator.generate_json_report(results)

def main():
    """Função principal para testar o gerador de relatórios"""
    # Dados de exemplo para teste
    sample_results = {
        'target': 'http://example.com',
        'timestamp': datetime.now().isoformat(),
        'vulnerabilities': [
            {
                'type': 'XSS (Cross-Site Scripting)',
                'severity': 'Medium',
                'parameter': 'search',
                'payload': "<script>alert('XSS')</script>",
                'url': 'http://example.com?search=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E',
                'method': 'GET',
                'description': 'Possível XSS refletido no parâmetro "search"'
            }
        ],
        'summary': {
            'total_vulnerabilities': 1,
            'xss_found': 1,
            'sql_injection_found': 0
        }
    }
    
    generate_basic_report(sample_results)

if __name__ == "__main__":
    main()
