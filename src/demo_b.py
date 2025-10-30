#!/usr/bin/env python3
"""
Demonstração avançada do Web Security Scanner - Conceito B
Showcase das funcionalidades expandidas do scanner
"""
import sys
import os
import time

# Adicionar o diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner_b import AdvancedWebSecurityScanner
from report_generator_b import generate_advanced_reports
from utils import Logger

def demo_advanced_scan():
    """Demonstração completa do scanner avançado - Conceito B"""
    logger = Logger("Demo-B")
    
    print("="*80)
    print("    WEB SECURITY SCANNER - DEMONSTRAÇÃO CONCEITO B")
    print("="*80)
    print("\n FUNCIONALIDADES AVANÇADAS:")
    print(" Detecção de 6+ vulnerabilidades OWASP Top 10")
    print(" Scan de portas integrado (Nmap)")
    print(" Relatórios em múltiplos formatos")
    print(" Interface web com Flask")
    print(" Automação e integração avançadas")
    print("\n" + "-"*80)
    
    # Lista de sites de teste para demonstração
    test_targets = [
        {
            'url': 'http://testphp.vulnweb.com/artists.php?artist=1',
            'description': 'Site vulnerável de demonstração',
            'expected_vulns': ['XSS', 'SQL Injection', 'Information Disclosure']
        }
    ]
    
    for i, target in enumerate(test_targets, 1):
        logger.info(f" DEMO {i}/{len(test_targets)}: {target['description']}")
        logger.info(f"🔗 Target: {target['url']}")
        
        print(f"\n Vulnerabilidades esperadas: {', '.join(target['expected_vulns'])}")
        
        try:
            # Criar scanner avançado
            scanner = AdvancedWebSecurityScanner(
                target['url'], 
                timeout=20, 
                use_nmap=False  # Desabilitar nmap para demo
            )
            
            print("\n Iniciando scan avançado...")
            start_time = time.time()
            
            # Executar scan
            results = scanner.scan()
            
            end_time = time.time()
            duration = round(end_time - start_time, 2)
            
            # Mostrar resultados
            print(f"\n RESULTADOS DO SCAN:")
            print(f"    Duração: {duration}s")
            print(f"    Total de vulnerabilidades: {results['summary']['total_vulnerabilities']}")
            
            # Breakdown por categoria
            summary = results['summary']
            categories = [
                (' XSS', summary['xss_found']),
                (' SQL Injection', summary['sql_injection_found']),
                (' Directory Traversal', summary['directory_traversal_found']),
                (' Command Injection', summary['command_injection_found']),
                (' Information Disclosure', summary['information_disclosure_found']),
                (' Broken Authentication', summary['broken_authentication_found'])
            ]
            
            print(f"\n BREAKDOWN POR CATEGORIA:")
            for category, count in categories:
                status = "" if count > 0 else ""
                print(f"   {status} {category}: {count}")
            
            # Gerar relatórios em todos os formatos
            logger.info("📄 Gerando relatórios em múltiplos formatos...")
            generate_advanced_reports(results, ['json', 'csv', 'markdown'])
            
            # Mostrar algumas vulnerabilidades encontradas
            if results['vulnerabilities']:
                print(f"\n🚨 EXEMPLOS DE VULNERABILIDADES ENCONTRADAS:")
                
                # Agrupar por tipo
                vuln_by_type = {}
                for vuln in results['vulnerabilities']:
                    vuln_type = vuln['type']
                    if vuln_type not in vuln_by_type:
                        vuln_by_type[vuln_type] = []
                    vuln_by_type[vuln_type].append(vuln)
                
                count = 0
                for vuln_type, vulns in vuln_by_type.items():
                    if count >= 3:  # Mostrar apenas 3 tipos
                        break
                    
                    print(f"\n   💥 {vuln_type} ({len(vulns)} encontradas):")
                    example = vulns[0]  # Pegar primeira como exemplo
                    print(f"       Severidade: {example.get('severity', 'N/A')}")
                    print(f"      📝 Descrição: {example.get('description', 'N/A')}")
                    if 'payload' in example:
                        print(f"      💣 Payload: {example['payload'][:50]}...")
                    
                    count += 1
            
            # Demonstrar capacidades avançadas
            print(f"\n🎉 CAPACIDADES AVANÇADAS DEMONSTRADAS:")
            print(f"    Scan completo executado em {duration}s")
            print(f"    {len(results['vulnerabilities'])} vulnerabilidades detectadas")
            print(f"    Relatórios gerados em 3 formatos (JSON, CSV, Markdown)")
            print(f"    Análise de {len(summary)} tipos diferentes de vulnerabilidades")
            
            if results['summary']['total_vulnerabilities'] >= 4:
                logger.success(" Critério do Conceito B atendido: 4+ vulnerabilidades detectadas!")
            
        except Exception as e:
            logger.error(f" Erro durante demo de {target['url']}: {str(e)}")
        
        print("-"*80)
    
    # Demonstração das funcionalidades de automação
    print(f"\n🤖 DEMONSTRAÇÃO DE AUTOMAÇÃO:")
    print(" Scanner executável via linha de comando")
    print(" Múltiplos formatos de saída configuráveis")
    print(" Interface web disponível (Flask)")
    print(" Integração com ferramentas externas (Nmap)")
    print(" Relatórios automáticos estruturados")
    
    print(f"\n COMO USAR AS FUNCIONALIDADES AVANÇADAS:")
    print(" Scanner CLI: python scanner_b.py -u <URL> --format json,csv")
    print("🌐 Interface Web: python web_interface.py")
    print(" Relatórios: Automáticos em JSON, CSV e Markdown")
    print("🔌 Com Nmap: python scanner_b.py -u <URL> (sem --no-nmap)")
    
    print(f"\n CONCEITO B IMPLEMENTADO COM SUCESSO!")
    print(" Múltiplas vulnerabilidades (6 tipos)")
    print(" Automação avançada")
    print(" Interface web simples") 
    print(" Relatórios em múltiplos formatos")
    print(" Integração com ferramentas auxiliares")
    
    print("="*80)
    print("🏆 DEMONSTRAÇÃO CONCEITO B CONCLUÍDA!")
    print("="*80)

def showcase_report_formats():
    """Demonstração dos formatos de relatório"""
    print(f"\n📄 DEMONSTRAÇÃO DOS FORMATOS DE RELATÓRIO:")
    print("1. 📟 Console: Exibição colorida com emojis")
    print("2.  JSON: Dados estruturados com metadados")  
    print("3.  CSV: Planilha para análise em Excel")
    print("4. 📝 Markdown: Documentação formatada")
    print("5. 🌐 Web: Interface interativa com progresso")
    
    print(f"\n EXEMPLO DE COMANDOS:")
    print("scanner_b.py -u <URL> --format console")
    print("scanner_b.py -u <URL> --format json,csv,markdown")
    print("scanner_b.py -u <URL> --format console,json")

if __name__ == "__main__":
    demo_advanced_scan()
    showcase_report_formats()
