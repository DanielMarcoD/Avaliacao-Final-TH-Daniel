#!/usr/bin/env python3
"""
Script de demonstração do Web Security Scanner - Conceito C
"""
import sys
import os

# Adicionar o diretório atual ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import WebSecurityScanner
from report_generator import generate_basic_report
from utils import Logger

def demo_scan():
    """Demonstração do scanner com múltiplos alvos"""
    logger = Logger("Demo")
    
    # Lista de sites de teste
    test_sites = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/search.php?test=query"
    ]
    
    print("="*60)
    print("   WEB SECURITY SCANNER - DEMONSTRAÇÃO CONCEITO C")
    print("="*60)
    print("\nEste script demonstra as funcionalidades básicas do scanner:")
    print("• Detecção de XSS (Cross-Site Scripting)")
    print("• Detecção de SQL Injection")
    print("• Geração de relatórios em múltiplos formatos")
    print("\n" + "-"*60)
    
    for i, site in enumerate(test_sites, 1):
        logger.info(f"Executando scan {i}/{len(test_sites)}: {site}")
        
        try:
            # Criar scanner
            scanner = WebSecurityScanner(site, timeout=15)
            
            # Executar scan
            results = scanner.scan()
            
            # Mostrar resumo
            print(f"\n RESUMO DO SCAN {i}:")
            print(f"   Target: {results['target']}")
            print(f"   Vulnerabilidades encontradas: {results['summary']['total_vulnerabilities']}")
            print(f"   • XSS: {results['summary']['xss_found']}")
            print(f"   • SQL Injection: {results['summary']['sql_injection_found']}")
            
            if results['summary']['total_vulnerabilities'] > 0:
                logger.warning(f" {results['summary']['total_vulnerabilities']} vulnerabilidade(s) detectada(s)!")
            else:
                logger.success(" Nenhuma vulnerabilidade encontrada")
            
        except Exception as e:
            logger.error(f"Erro durante scan de {site}: {str(e)}")
        
        print("-"*60)
    
    print("\n DEMONSTRAÇÃO CONCLUÍDA!")
    print("\nO scanner implementa as funcionalidades básicas do Conceito C:")
    print(" Varredura simples de URLs e parâmetros")
    print(" Detecção de vulnerabilidades XSS e SQL Injection")
    print(" Interface de linha de comando")
    print(" Relatórios básicos (console, log, JSON)")
    print("\nPara usar o scanner diretamente:")
    print("python scanner.py -u <URL_ALVO>")

if __name__ == "__main__":
    demo_scan()
