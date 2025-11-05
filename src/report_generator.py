#!/usr/bin/env python3
"""
Advanced Report Generator for Web Security Scanner - Conceito A
Enhanced with risk analysis, detailed metrics, and professional formatting
"""

import json
import csv
import os
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template
import base64
import io
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from colorama import Fore, Style

class AdvancedReportGeneratorA:
    """Advanced report generator with risk analysis and visualizations"""
    
    def __init__(self, output_dir: str = "./"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up matplotlib style
        plt.style.use('seaborn-v0_8' if 'seaborn-v0_8' in plt.style.available else 'default')
        sns.set_palette("husl")
        
    def generate_console_report(self, vulnerabilities: List[Dict], metadata: Dict):
        """Generate enhanced console report with risk analysis"""
        print(f"\n{Fore.MAGENTA}" + "="*80)
        print(f"{Fore.MAGENTA}🔍        ENHANCED SECURITY SCAN REPORT (Conceito A)")
        print(f"{Fore.MAGENTA}" + "="*80)
        
        print(f"🎯 Target: {metadata['target_url']}")
        print(f"📊 Scan ID: {metadata['scan_id']}")
        print(f"⏱️  Duration: {metadata['duration']:.2f} seconds")
        print(f"🔢 Total Vulnerabilities: {len(vulnerabilities)}")
        
        if 'risk_metrics' in metadata:
            risk = metadata['risk_metrics']
            print(f"\n🎯 RISK ANALYSIS:")
            print(f"⚠️  Critical: {risk['critical_count']} (Score ≥ 9.0)")
            print(f"🔴 High: {risk['high_count']} (Score 7.0-8.9)")
            print(f"🟠 Medium: {risk['medium_count']} (Score 4.0-6.9)")
            print(f"🟡 Low: {risk['low_count']} (Score < 4.0)")
            print(f"📊 Average Risk Score: {risk['average_risk_score']:.1f}/10")
            print(f"🚨 Maximum Risk Score: {risk['max_risk_score']:.1f}/10")
        
        if vulnerabilities:
            print(f"\n📋 DETAILED VULNERABILITIES:")
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln['severity']
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            # Display by severity (Critical first)
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            severity_colors = {
                'CRITICAL': Fore.MAGENTA,
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.CYAN,
                'INFO': Fore.WHITE
            }
            
            for severity in severity_order:
                if severity in by_severity:
                    color = severity_colors[severity]
                    print(f"\n{color}{'='*60}")
                    print(f"{color}{severity} RISK VULNERABILITIES ({len(by_severity[severity])})")
                    print(f"{color}{'='*60}")
                    
                    for vuln in by_severity[severity]:
                        print(f"{color}🔍 [{vuln['id']}] {vuln['type']}")
                        print(f"{color}📍 URL: {vuln['url']}")
                        print(f"{color}🎯 Payload: {vuln['payload']}")
                        print(f"{color}📊 Risk Score: {vuln['risk_score']:.1f}/10")
                        print(f"{color}📝 Description: {vuln['description']}")
                        if vuln['evidence']:
                            print(f"{color}🔍 Evidence: {vuln['evidence']}")
                        if vuln.get('context'):
                            context = vuln['context']
                            if 'heuristic_confidence' in context:
                                print(f"{color}🧠 Confidence: {context['heuristic_confidence']:.2f}")
                        print(f"{color}{'-'*50}")
        else:
            print(f"\n{Fore.GREEN}✅ Nenhuma vulnerabilidade encontrada!")
            
    def generate_json_report(self, vulnerabilities: List[Dict], metadata: Dict) -> str:
        """Generate comprehensive JSON report with enhanced metadata"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enhanced_scan_report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Enhanced report structure
        report = {
            "scan_metadata": metadata,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerability_types": list(set(v['type'] for v in vulnerabilities)),
                "severity_distribution": {},
                "risk_analysis": metadata.get('risk_metrics', {}),
                "scan_coverage": {
                    "total_requests": metadata.get('total_requests', 0),
                    "scan_techniques": [
                        "Heuristic Analysis",
                        "Pattern Matching", 
                        "Error-based Detection",
                        "Behavioral Analysis",
                        "SSL/TLS Analysis",
                        "Security Headers Check"
                    ]
                }
            },
            "vulnerabilities": vulnerabilities,
            "recommendations": self._generate_recommendations(vulnerabilities),
            "compliance_status": self._generate_compliance_status(vulnerabilities)
        }
        
        # Calculate severity distribution
        for vuln in vulnerabilities:
            severity = vuln['severity']
            if severity not in report['summary']['severity_distribution']:
                report['summary']['severity_distribution'][severity] = 0
            report['summary']['severity_distribution'][severity] += 1
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
        print(f"{Fore.GREEN}📄 Relatório JSON salvo: {filename}")
        return filepath
        
    def generate_csv_report(self, vulnerabilities: List[Dict], metadata: Dict) -> str:
        """Generate detailed CSV report with risk metrics"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enhanced_vulnerabilities_report_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        if not vulnerabilities:
            # Create empty CSV with headers
            headers = [
                'ID', 'Type', 'Severity', 'Risk_Score', 'URL', 'Payload', 
                'Description', 'Evidence', 'Timestamp', 'Confidence'
            ]
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
            return filepath
        
        # Flatten vulnerability data for CSV
        csv_data = []
        for vuln in vulnerabilities:
            row = {
                'ID': vuln['id'],
                'Type': vuln['type'],
                'Severity': vuln['severity'],
                'Risk_Score': vuln['risk_score'],
                'URL': vuln['url'],
                'Payload': vuln['payload'],
                'Description': vuln['description'],
                'Evidence': vuln.get('evidence', ''),
                'Timestamp': vuln['timestamp'],
                'Scan_ID': vuln['scan_id'],
                'Confidence': vuln.get('context', {}).get('heuristic_confidence', 'N/A'),
                'Public_Facing': vuln.get('context', {}).get('public_facing', 'Unknown'),
                'Auth_Required': vuln.get('context', {}).get('authentication_required', 'Unknown'),
                'Sensitive_Data': vuln.get('context', {}).get('sensitive_data', 'Unknown')
            }
            csv_data.append(row)
        
        df = pd.DataFrame(csv_data)
        df.to_csv(filepath, index=False, encoding='utf-8')
        
        print(f"{Fore.GREEN}📊 Relatório CSV salvo: {filename}")
        return filepath
        
    def generate_markdown_report(self, vulnerabilities: List[Dict], metadata: Dict) -> str:
        """Generate comprehensive Markdown report with risk analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"enhanced_security_report_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate charts for embedding
        charts_data = self._generate_charts(vulnerabilities, metadata)
        
        markdown_template = """# Enhanced Web Security Scan Report - Conceito A

## 🎯 Executive Summary

| Attribute | Value |
|-----------|-------|
| **Target URL** | {{ metadata.target_url }} |
| **Scan ID** | {{ metadata.scan_id }} |
| **Scan Date** | {{ metadata.start_time.strftime('%Y-%m-%d %H:%M:%S') }} |
| **Duration** | {{ "%.2f"|format(metadata.duration) }} seconds |
| **Total Vulnerabilities** | {{ vulnerabilities|length }} |
| **Scanner Version** | {{ metadata.scanner_version }} |

{% if metadata.risk_metrics %}
## 📊 Risk Analysis

| Risk Level | Count | Score Range |
|------------|-------|-------------|
| 🚨 **Critical** | {{ metadata.risk_metrics.critical_count }} | 9.0 - 10.0 |
| 🔴 **High** | {{ metadata.risk_metrics.high_count }} | 7.0 - 8.9 |
| 🟠 **Medium** | {{ metadata.risk_metrics.medium_count }} | 4.0 - 6.9 |
| 🟡 **Low** | {{ metadata.risk_metrics.low_count }} | < 4.0 |

**Overall Risk Metrics:**
- Average Risk Score: **{{ "%.1f"|format(metadata.risk_metrics.average_risk_score) }}/10**
- Maximum Risk Score: **{{ "%.1f"|format(metadata.risk_metrics.max_risk_score) }}/10**
{% endif %}

## 🔍 Vulnerability Details

{% if vulnerabilities %}
{% for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] %}
{% set severity_vulns = vulnerabilities | selectattr('severity', 'equalto', severity) | list %}
{% if severity_vulns %}

### {{ '🚨' if severity == 'CRITICAL' else '🔴' if severity == 'HIGH' else '🟠' if severity == 'MEDIUM' else '🟡' if severity == 'LOW' else '🔵' }} {{ severity }} Risk Vulnerabilities ({{ severity_vulns|length }})

{% for vuln in severity_vulns %}
#### [{{ vuln.id }}] {{ vuln.type }}

| Attribute | Details |
|-----------|---------|
| **URL** | `{{ vuln.url }}` |
| **Payload** | `{{ vuln.payload }}` |
| **Risk Score** | {{ "%.1f"|format(vuln.risk_score) }}/10 |
| **Description** | {{ vuln.description }} |
{% if vuln.evidence %}| **Evidence** | {{ vuln.evidence }} |{% endif %}
{% if vuln.context and vuln.context.heuristic_confidence %}| **Confidence** | {{ "%.2f"|format(vuln.context.heuristic_confidence) }} |{% endif %}

{% endfor %}
{% endif %}
{% endfor %}
{% else %}
✅ **No vulnerabilities were found during the scan.**
{% endif %}

## 🛡️ Security Recommendations

{% for rec in recommendations %}
### {{ rec.title }}
{{ rec.description }}

**Priority:** {{ rec.priority }}
**Effort:** {{ rec.effort }}

{% endfor %}

## 📋 Compliance Status

| Framework | Status | Issues |
|-----------|--------|--------|
{% for framework, status in compliance.items() %}
| {{ framework }} | {{ status.status }} | {{ status.issues }} |
{% endfor %}

## 📈 Scan Statistics

- **Total HTTP Requests:** {{ metadata.total_requests }}
- **Scan Techniques Used:** Heuristic Analysis, Pattern Matching, Behavioral Analysis
- **Coverage:** SSL/TLS, Security Headers, Input Validation, Authentication

---
*Report generated by Enhanced Web Security Scanner (Conceito A) on {{ metadata.end_time.strftime('%Y-%m-%d %H:%M:%S') }}*
"""

        template = Template(markdown_template)
        
        # Generate recommendations and compliance status
        recommendations = self._generate_recommendations(vulnerabilities)
        compliance = self._generate_compliance_status(vulnerabilities)
        
        content = template.render(
            vulnerabilities=vulnerabilities,
            metadata=metadata,
            recommendations=recommendations,
            compliance=compliance
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
        print(f"{Fore.GREEN}📝 Relatório Markdown salvo: {filename}")
        return filepath
        
    def _generate_charts(self, vulnerabilities: List[Dict], metadata: Dict) -> Dict:
        """Generate visualization charts for the report"""
        charts = {}
        
        if not vulnerabilities:
            return charts
            
        # Severity distribution pie chart
        plt.figure(figsize=(10, 6))
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        if severity_counts:
            colors = {
                'CRITICAL': '#8B0000',
                'HIGH': '#FF4500', 
                'MEDIUM': '#FFA500',
                'LOW': '#32CD32',
                'INFO': '#4169E1'
            }
            
            plt.subplot(1, 2, 1)
            plt.pie(severity_counts.values(), 
                   labels=severity_counts.keys(),
                   colors=[colors.get(k, '#Gray') for k in severity_counts.keys()],
                   autopct='%1.1f%%')
            plt.title('Vulnerability Distribution by Severity')
            
            # Vulnerability types bar chart
            plt.subplot(1, 2, 2)
            type_counts = {}
            for vuln in vulnerabilities:
                vuln_type = vuln['type']
                type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
                
            plt.barh(list(type_counts.keys()), list(type_counts.values()))
            plt.title('Vulnerabilities by Type')
            plt.xlabel('Count')
            
            # Save chart
            chart_path = os.path.join(self.output_dir, 'vulnerability_charts.png')
            plt.tight_layout()
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            charts['distribution'] = chart_path
            
        return charts
        
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on found vulnerabilities"""
        recommendations = []
        
        vuln_types = set(v['type'] for v in vulnerabilities)
        
        rec_map = {
            'XSS': {
                'title': 'Cross-Site Scripting (XSS) Mitigation',
                'description': 'Implement input validation, output encoding, and Content Security Policy (CSP) headers.',
                'priority': 'HIGH',
                'effort': 'MEDIUM'
            },
            'SQL Injection': {
                'title': 'SQL Injection Prevention',
                'description': 'Use parameterized queries, prepared statements, and input validation.',
                'priority': 'CRITICAL',
                'effort': 'MEDIUM'
            },
            'Security Misconfiguration': {
                'title': 'Security Configuration Hardening',
                'description': 'Implement security headers, disable unused services, and follow security baselines.',
                'priority': 'MEDIUM',
                'effort': 'LOW'
            },
            'Cross-Site Request Forgery': {
                'title': 'CSRF Protection Implementation',
                'description': 'Implement CSRF tokens, SameSite cookies, and origin validation.',
                'priority': 'HIGH',
                'effort': 'LOW'
            }
        }
        
        for vuln_type in vuln_types:
            if vuln_type in rec_map:
                recommendations.append(rec_map[vuln_type])
                
        return recommendations
        
    def _generate_compliance_status(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate compliance status for security frameworks"""
        vuln_types = set(v['type'] for v in vulnerabilities)
        
        compliance = {
            'OWASP Top 10': {
                'status': '❌ Non-Compliant' if vuln_types else '✅ Compliant',
                'issues': len(vulnerabilities)
            },
            'PCI DSS': {
                'status': '❌ Non-Compliant' if 'SQL Injection' in vuln_types or 'XSS' in vuln_types else '✅ Compliant',
                'issues': len([v for v in vulnerabilities if v['type'] in ['SQL Injection', 'XSS']])
            },
            'ISO 27001': {
                'status': '❌ Non-Compliant' if 'Security Misconfiguration' in vuln_types else '✅ Compliant',
                'issues': len([v for v in vulnerabilities if 'Security' in v['type']])
            }
        }
        
        return compliance
        
    def generate_reports(self, vulnerabilities: List[Dict], metadata: Dict, formats: List[str]):
        """Generate all requested report formats"""
        print(f"\n{Fore.CYAN}📊 Gerando relatórios avançados...")
        
        generated_files = []
        
        for format_type in formats:
            if format_type.lower() == 'console':
                self.generate_console_report(vulnerabilities, metadata)
            elif format_type.lower() == 'json':
                file_path = self.generate_json_report(vulnerabilities, metadata)
                generated_files.append(file_path)
            elif format_type.lower() == 'csv':
                file_path = self.generate_csv_report(vulnerabilities, metadata)
                generated_files.append(file_path)
            elif format_type.lower() == 'markdown' or format_type.lower() == 'md':
                file_path = self.generate_markdown_report(vulnerabilities, metadata)
                generated_files.append(file_path)
                
        return generated_files
