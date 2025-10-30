#!/usr/bin/env python3
"""
Gerador de relatórios avançado para o Web Security Scanner - Conceito B
Suporte a múltiplos formatos: JSON, CSV, Markdown
"""
import json
import csv
from datetime import datetime
from typing import Dict, Any, List
import os
import sys

# Adicionar o diretório src ao path para importações
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Logger

class AdvancedReportGenerator:
    """Gerador de relatórios avançados - Conceito B"""
    
    def __init__(self):
        self.logger = Logger("AdvancedReportGenerator")
    
    def generate_console_report(self, results: Dict[str, Any]):
        """Gera relatório avançado para console"""
        print("\n" + "="*80)
        print("🔍        ADVANCED WEB SECURITY SCAN REPORT (Conceito B)")
        print("="*80)
        print(f"🎯 Target: {results['target']}")
        print(f"📅 Timestamp: {results['timestamp']}")
        print(f"🚀 Scanner: {results.get('scanner_version', 'v2.0')}")
        print(f"⏱️  Duration: {results['summary'].get('scan_duration', 'N/A')} seconds")
        print(f"🔢 Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print("-"*80)
        
        # Port Scan Results
        if results.get('port_scan'):
            print("\n🔌 PORT SCAN RESULTS:")
            print("-"*30)
            for port, info in results['port_scan'].items():
                status_emoji = "🟢" if info['state'] == 'open' else "🔴"
                print(f"  {status_emoji} {port}: {info['state']} ({info['service']})")
        
        # Vulnerability Summary
        print("\n📊 VULNERABILITY SUMMARY:")
        print("-"*40)
        summary = results['summary']
        vuln_types = [
            ("XSS", summary['xss_found'], "🕷️"),
            ("SQL Injection", summary['sql_injection_found'], "💉"),
            ("Directory Traversal", summary['directory_traversal_found'], "📁"),
            ("Command Injection", summary['command_injection_found'], "⚡"),
            ("Information Disclosure", summary['information_disclosure_found'], "🔍"),
            ("Broken Authentication", summary['broken_authentication_found'], "🔐")
        ]
        
        for vuln_name, count, emoji in vuln_types:
            if count > 0:
                print(f"  {emoji} {vuln_name}: {count}")
        
        # Detailed Vulnerabilities
        if results['vulnerabilities']:
            print("\n🚨 DETAILED VULNERABILITIES:")
            print("-"*50)
            
            # Agrupar por tipo
            vuln_by_type = {}
            for vuln in results['vulnerabilities']:
                vuln_type = vuln['type']
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
            
            for vuln_type, vulns in vuln_by_type.items():
                print(f"\n💥 {vuln_type} ({len(vulns)} found):")
                for i, vuln in enumerate(vulns, 1):
                    severity_emoji = self._get_severity_emoji(vuln['severity'])
                    print(f"  [{i}] {severity_emoji} {vuln['severity']} - {vuln['description']}")
                    print(f"      🔗 URL: {vuln.get('url', 'N/A')}")
                    print(f"      🔧 Method: {vuln.get('method', 'N/A')}")
                    
                    if 'payload' in vuln:
                        print(f"      💣 Payload: {vuln['payload']}")
                    if 'parameter' in vuln:
                        print(f"      📝 Parameter: {vuln['parameter']}")
                    if 'patterns_found' in vuln and vuln['patterns_found']:
                        print(f"      🎯 Patterns: {len(vuln['patterns_found'])} matched")
                    print()
        else:
            print("\n✅ No vulnerabilities found!")
        
        print("="*80 + "\n")
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Retorna emoji baseado na severidade"""
        emoji_map = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢',
            'Info': '🔵'
        }
        return emoji_map.get(severity, '⚪')
    
    def generate_json_report(self, results: Dict[str, Any], filename: str = None):
        """Gera relatório JSON detalhado"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"advanced_scan_report_{timestamp}.json"
        
        try:
            # Adicionar metadados ao relatório
            enhanced_results = {
                **results,
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'format': 'json',
                    'version': '2.0'
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(enhanced_results, f, indent=2, ensure_ascii=False)
            
            self.logger.success(f"📄 Relatório JSON salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao salvar relatório JSON: {str(e)}")
    
    def generate_csv_report(self, results: Dict[str, Any], filename: str = None):
        """Gera relatório CSV das vulnerabilidades"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerabilities_report_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if not results['vulnerabilities']:
                    # Arquivo vazio se não há vulnerabilidades
                    writer = csv.writer(f)
                    writer.writerow(['No vulnerabilities found'])
                    self.logger.success(f"📊 Relatório CSV (vazio) salvo em: {filename}")
                    return
                
                # Headers do CSV
                fieldnames = [
                    'Type', 'Severity', 'Description', 'URL', 'Method',
                    'Parameter', 'Payload', 'Patterns_Found', 'Response_Size'
                ]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                # Escrever vulnerabilidades
                for vuln in results['vulnerabilities']:
                    row = {
                        'Type': vuln.get('type', ''),
                        'Severity': vuln.get('severity', ''),
                        'Description': vuln.get('description', ''),
                        'URL': vuln.get('url', ''),
                        'Method': vuln.get('method', ''),
                        'Parameter': vuln.get('parameter', ''),
                        'Payload': vuln.get('payload', ''),
                        'Patterns_Found': len(vuln.get('patterns_found', [])),
                        'Response_Size': vuln.get('response_size', '')
                    }
                    writer.writerow(row)
            
            self.logger.success(f"📊 Relatório CSV salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao salvar relatório CSV: {str(e)}")
    
    def generate_markdown_report(self, results: Dict[str, Any], filename: str = None):
        """Gera relatório em formato Markdown"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.md"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                # Header
                f.write("# 🔒 Web Security Scan Report\n\n")
                f.write("## 📋 Scan Information\n\n")
                f.write(f"- **Target:** {results['target']}\n")
                f.write(f"- **Scan Date:** {results['timestamp']}\n")
                f.write(f"- **Scanner Version:** {results.get('scanner_version', 'v2.0')}\n")
                f.write(f"- **Duration:** {results['summary'].get('scan_duration', 'N/A')} seconds\n")
                f.write(f"- **Total Vulnerabilities:** {results['summary']['total_vulnerabilities']}\n\n")
                
                # Port Scan Results
                if results.get('port_scan'):
                    f.write("## 🔌 Port Scan Results\n\n")
                    f.write("| Port | State | Service |\n")
                    f.write("|------|-------|----------|\n")
                    
                    for port, info in results['port_scan'].items():
                        state_emoji = "✅" if info['state'] == 'open' else "❌"
                        f.write(f"| {port} | {state_emoji} {info['state']} | {info['service']} |\n")
                    f.write("\n")
                
                # Summary
                f.write("## 📊 Vulnerability Summary\n\n")
                summary = results['summary']
                
                vuln_types = [
                    ("XSS", summary['xss_found'], "🕷️"),
                    ("SQL Injection", summary['sql_injection_found'], "💉"),
                    ("Directory Traversal", summary['directory_traversal_found'], "📁"),
                    ("Command Injection", summary['command_injection_found'], "⚡"),
                    ("Information Disclosure", summary['information_disclosure_found'], "🔍"),
                    ("Broken Authentication", summary['broken_authentication_found'], "🔐")
                ]
                
                f.write("| Vulnerability Type | Count | Status |\n")
                f.write("|--------------------|-------|--------|\n")
                
                for vuln_name, count, emoji in vuln_types:
                    status = "🔴 Found" if count > 0 else "✅ Clean"
                    f.write(f"| {emoji} {vuln_name} | {count} | {status} |\n")
                f.write("\n")
                
                # Detailed Vulnerabilities
                if results['vulnerabilities']:
                    f.write("## 🚨 Detailed Vulnerabilities\n\n")
                    
                    # Agrupar por tipo
                    vuln_by_type = {}
                    for vuln in results['vulnerabilities']:
                        vuln_type = vuln['type']
                        if vuln_type not in vuln_by_type:
                            vuln_by_type[vuln_type] = []
                        vuln_by_type[vuln_type].append(vuln)
                    
                    for vuln_type, vulns in vuln_by_type.items():
                        f.write(f"### {vuln_type}\n\n")
                        
                        for i, vuln in enumerate(vulns, 1):
                            severity_emoji = self._get_severity_emoji(vuln['severity'])
                            f.write(f"#### {i}. {severity_emoji} {vuln['severity']} - {vuln['description']}\n\n")
                            
                            f.write("**Details:**\n")
                            f.write(f"- **URL:** `{vuln.get('url', 'N/A')}`\n")
                            f.write(f"- **Method:** `{vuln.get('method', 'N/A')}`\n")
                            
                            if 'parameter' in vuln:
                                f.write(f"- **Parameter:** `{vuln['parameter']}`\n")
                            if 'payload' in vuln:
                                f.write(f"- **Payload:** `{vuln['payload']}`\n")
                            if 'patterns_found' in vuln and vuln['patterns_found']:
                                f.write(f"- **Patterns Matched:** {len(vuln['patterns_found'])}\n")
                            
                            f.write("\n---\n\n")
                else:
                    f.write("## ✅ No Vulnerabilities Found\n\n")
                    f.write("The scan completed successfully without finding any security vulnerabilities.\n\n")
                
                # Footer
                f.write("---\n")
                f.write("*Report generated by Advanced Web Security Scanner - Conceito B*\n")
            
            self.logger.success(f"📝 Relatório Markdown salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao salvar relatório Markdown: {str(e)}")
    
    def generate_log_report(self, results: Dict[str, Any], filename: str = None):
        """Gera relatório detalhado em log"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"advanced_scan_{timestamp}.log"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*100 + "\n")
                f.write("ADVANCED WEB SECURITY SCAN REPORT - CONCEITO B\n")
                f.write("="*100 + "\n")
                f.write(f"Target URL: {results['target']}\n")
                f.write(f"Scan Time: {results['timestamp']}\n")
                f.write(f"Scanner Version: {results.get('scanner_version', 'v2.0')}\n")
                f.write(f"Scan Duration: {results['summary'].get('scan_duration', 'N/A')} seconds\n")
                f.write(f"Total Vulnerabilities Found: {results['summary']['total_vulnerabilities']}\n")
                f.write("-"*100 + "\n\n")
                
                # Port Scan Results
                if results.get('port_scan'):
                    f.write("PORT SCAN RESULTS:\n")
                    f.write("-"*50 + "\n")
                    for port, info in results['port_scan'].items():
                        f.write(f"{port}: {info['state']} ({info['service']})\n")
                    f.write("\n")
                
                # Vulnerability Details
                if results['vulnerabilities']:
                    f.write("DETAILED VULNERABILITY REPORT:\n")
                    f.write("-"*60 + "\n")
                    
                    for i, vuln in enumerate(results['vulnerabilities'], 1):
                        f.write(f"\nVulnerability #{i}\n")
                        f.write("-"*30 + "\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Severity: {vuln['severity']}\n")
                        f.write(f"Description: {vuln['description']}\n")
                        f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                        f.write(f"Method: {vuln.get('method', 'N/A')}\n")
                        
                        if 'parameter' in vuln:
                            f.write(f"Parameter: {vuln['parameter']}\n")
                        if 'payload' in vuln:
                            f.write(f"Payload: {vuln['payload']}\n")
                        if 'patterns_found' in vuln:
                            f.write(f"Patterns Found: {vuln['patterns_found']}\n")
                        if 'response_size' in vuln:
                            f.write(f"Response Size: {vuln['response_size']} bytes\n")
                        
                        f.write("\n")
                else:
                    f.write("No vulnerabilities found during the scan.\n")
                
                # Summary
                f.write("\n" + "="*100 + "\n")
                f.write("SCAN SUMMARY\n")
                f.write("="*100 + "\n")
                summary = results['summary']
                f.write(f"XSS Vulnerabilities: {summary['xss_found']}\n")
                f.write(f"SQL Injection Vulnerabilities: {summary['sql_injection_found']}\n")
                f.write(f"Directory Traversal Vulnerabilities: {summary['directory_traversal_found']}\n")
                f.write(f"Command Injection Vulnerabilities: {summary['command_injection_found']}\n")
                f.write(f"Information Disclosure Issues: {summary['information_disclosure_found']}\n")
                f.write(f"Broken Authentication Issues: {summary['broken_authentication_found']}\n")
                f.write(f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
                f.write(f"Scan Duration: {summary.get('scan_duration', 'N/A')} seconds\n")
                f.write("="*100 + "\n")
            
            self.logger.success(f"📋 Relatório LOG salvo em: {filename}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao salvar relatório LOG: {str(e)}")

def generate_advanced_reports(results: Dict[str, Any], formats: List[str] = None):
    """Função de conveniência para gerar múltiplos relatórios"""
    if formats is None:
        formats = ['console', 'json', 'markdown']
    
    generator = AdvancedReportGenerator()
    
    for fmt in formats:
        fmt = fmt.lower().strip()
        
        if fmt == 'console':
            generator.generate_console_report(results)
        elif fmt == 'json':
            generator.generate_json_report(results)
        elif fmt == 'csv':
            generator.generate_csv_report(results)
        elif fmt == 'markdown' or fmt == 'md':
            generator.generate_markdown_report(results)
        elif fmt == 'log':
            generator.generate_log_report(results)
        else:
            generator.logger.warning(f"⚠️ Formato desconhecido: {fmt}")

def main():
    """Função principal para testar o gerador"""
    # Dados de exemplo para teste
    sample_results = {
        'target': 'http://testsite.com',
        'timestamp': datetime.now().isoformat(),
        'scanner_version': 'Conceito B - v2.0',
        'port_scan': {
            '80/tcp': {'state': 'open', 'service': 'http'},
            '443/tcp': {'state': 'open', 'service': 'https'},
            '22/tcp': {'state': 'closed', 'service': 'ssh'}
        },
        'vulnerabilities': [
            {
                'type': 'XSS (Cross-Site Scripting)',
                'severity': 'Medium',
                'parameter': 'search',
                'payload': "<script>alert('XSS')</script>",
                'url': 'http://testsite.com?search=xss',
                'method': 'GET',
                'description': 'XSS refletido no parâmetro search'
            },
            {
                'type': 'SQL Injection',
                'severity': 'High',
                'parameter': 'id',
                'payload': "' OR '1'='1",
                'url': 'http://testsite.com?id=sql',
                'method': 'GET',
                'error_patterns': ['MySQL syntax error'],
                'description': 'SQL Injection no parâmetro id'
            }
        ],
        'summary': {
            'total_vulnerabilities': 2,
            'xss_found': 1,
            'sql_injection_found': 1,
            'directory_traversal_found': 0,
            'command_injection_found': 0,
            'information_disclosure_found': 0,
            'broken_authentication_found': 0,
            'scan_duration': 45.2
        }
    }
    
    generate_advanced_reports(sample_results, ['console', 'json', 'csv', 'markdown'])

if __name__ == "__main__":
    main()
