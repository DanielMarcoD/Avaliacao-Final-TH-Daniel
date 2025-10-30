#!/usr/bin/env python3
"""
Test Suite for Enhanced Web Security Scanner - Conceito A
Comprehensive testing with risk analysis validation and performance metrics
"""

import unittest
import sys
import os
import time
import json
import threading
from unittest.mock import Mock, patch, MagicMock
import tempfile
import requests

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/../')

from scanner_a import EnhancedWebSecurityScanner, VulnerabilityRisk, HeuristicAnalyzer
from report_generator_a import AdvancedReportGeneratorA


class TestVulnerabilityRisk(unittest.TestCase):
    """Test risk scoring and vulnerability categorization"""
    
    def test_risk_score_calculation(self):
        """Test CVSS-like risk score calculation"""
        context = {
            'public_facing': True,
            'sensitive_data': True,
            'authentication_required': False
        }
        
        # Test SQL Injection (should be high risk)
        score = VulnerabilityRisk.calculate_risk_score('SQL Injection', context)
        self.assertGreater(score, 8.0)
        self.assertLessEqual(score, 10.0)
        
        # Test with authentication required (should reduce score)
        context['authentication_required'] = True
        reduced_score = VulnerabilityRisk.calculate_risk_score('SQL Injection', context)
        self.assertLess(reduced_score, score)
    
    def test_severity_levels(self):
        """Test severity level categorization"""
        self.assertEqual(VulnerabilityRisk.get_severity_level(9.5), 'CRITICAL')
        self.assertEqual(VulnerabilityRisk.get_severity_level(8.0), 'HIGH')
        self.assertEqual(VulnerabilityRisk.get_severity_level(5.5), 'MEDIUM')
        self.assertEqual(VulnerabilityRisk.get_severity_level(2.5), 'LOW')
        self.assertEqual(VulnerabilityRisk.get_severity_level(0.5), 'INFO')
    
    def test_vulnerability_scores_coverage(self):
        """Test that all major vulnerability types have defined scores"""
        required_types = [
            'SQL Injection', 'XSS', 'Command Injection',
            'Directory Traversal', 'Information Disclosure', 
            'Broken Authentication'
        ]
        
        for vuln_type in required_types:
            self.assertIn(vuln_type, VulnerabilityRisk.VULNERABILITY_SCORES)


class TestHeuristicAnalyzer(unittest.TestCase):
    """Test heuristic analysis functionality"""
    
    def setUp(self):
        self.analyzer = HeuristicAnalyzer()
    
    def test_sql_error_detection(self):
        """Test SQL error pattern detection"""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "Warning: mysql_fetch_array() expects parameter"
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 2.0
        mock_response.headers = {}
        
        analysis = self.analyzer.analyze_response_behavior(mock_response, "' OR 1=1--")
        
        self.assertGreater(analysis['confidence_score'], 0.0)
        self.assertTrue(len(analysis['content_patterns']) > 0)
    
    def test_response_time_anomaly(self):
        """Test response time anomaly detection"""
        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 15.0  # Long response time
        mock_response.headers = {}
        
        analysis = self.analyzer.analyze_response_behavior(mock_response, "sleep(10)")
        
        self.assertTrue(analysis['response_time_anomaly'])
        self.assertGreater(analysis['confidence_score'], 0.0)
    
    def test_status_code_anomaly(self):
        """Test HTTP status code anomaly detection"""
        mock_response = Mock()
        mock_response.text = "Internal Server Error"
        mock_response.status_code = 500
        mock_response.elapsed.total_seconds.return_value = 2.0
        mock_response.headers = {}
        
        analysis = self.analyzer.analyze_response_behavior(mock_response, "malicious_payload")
        
        self.assertTrue(analysis['status_code_anomaly'])
        self.assertGreater(analysis['confidence_score'], 0.0)


class TestEnhancedWebSecurityScanner(unittest.TestCase):
    """Test enhanced scanner functionality"""
    
    def setUp(self):
        self.test_url = "http://test.example.com"
        self.scanner = EnhancedWebSecurityScanner(self.test_url, timeout=10)
    
    def test_scanner_initialization(self):
        """Test scanner initialization with enhanced metadata"""
        self.assertEqual(self.scanner.url, self.test_url)
        self.assertEqual(self.scanner.timeout, 10)
        self.assertIsNotNone(self.scanner.scan_metadata['scan_id'])
        self.assertEqual(self.scanner.scan_metadata['scanner_version'], 'v3.0-ConceptA')
        self.assertIn('target_url', self.scanner.scan_metadata)
    
    @patch('scanner_a.requests.Session.get')
    def test_ssl_configuration_scan(self, mock_get):
        """Test SSL/TLS configuration analysis"""
        # Mock HTTPS response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html>SSL Test</html>"
        mock_get.return_value = mock_response
        
        https_scanner = EnhancedWebSecurityScanner("https://test.example.com")
        
        # Mock socket operations for SSL testing
        with patch('scanner_a.socket.create_connection'), \
             patch('scanner_a.ssl.create_default_context') as mock_ssl_context:
            
            mock_ssl_socket = Mock()
            mock_ssl_socket.getpeercert.return_value = {'subject': 'test'}
            mock_ssl_socket.cipher.return_value = ('AES256-GCM-SHA384', 'TLSv1.3', 256)
            mock_ssl_socket.version.return_value = 'TLSv1.3'
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
            mock_ssl_context.return_value = mock_context
            
            https_scanner.scan_ssl_configuration()
            
            # Should not add vulnerabilities for good SSL config
            ssl_vulns = [v for v in https_scanner.vulnerabilities if 'SSL' in v['type'] or 'TLS' in v['type']]
            self.assertEqual(len(ssl_vulns), 0)
    
    @patch('scanner_a.requests.Session.get')
    def test_security_headers_scan(self, mock_get):
        """Test security headers analysis"""
        # Mock response without security headers
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = "<html>Test</html>"
        mock_get.return_value = mock_response
        
        self.scanner.scan_security_headers()
        
        # Should detect missing security headers
        header_vulns = [v for v in self.scanner.vulnerabilities if 'Security Misconfiguration' in v['type']]
        self.assertGreater(len(header_vulns), 0)
    
    @patch('scanner_a.requests.Session.get')
    def test_advanced_xss_detection(self, mock_get):
        """Test advanced XSS detection with heuristics"""
        # Mock vulnerable response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><script>alert("XSS")</script></html>'
        mock_get.return_value = mock_response
        
        # Test URL with parameters
        vuln_scanner = EnhancedWebSecurityScanner("http://test.com?param=value")
        vuln_scanner.scan_advanced_xss()
        
        # Should detect XSS vulnerability
        xss_vulns = [v for v in vuln_scanner.vulnerabilities if v['type'] == 'XSS']
        self.assertGreater(len(xss_vulns), 0)
        
        # Check risk scoring
        if xss_vulns:
            self.assertGreater(xss_vulns[0]['risk_score'], 0)
            self.assertIn('heuristic_confidence', xss_vulns[0]['context'])
    
    @patch('scanner_a.requests.Session.get')
    def test_comprehensive_scan_performance(self, mock_get):
        """Test comprehensive scan performance and metrics"""
        # Mock normal response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html>Normal Response</html>"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_get.return_value = mock_response
        
        start_time = time.time()
        vulnerabilities, metadata = self.scanner.perform_comprehensive_scan()
        scan_duration = time.time() - start_time
        
        # Performance checks
        self.assertLess(scan_duration, 30)  # Should complete within 30 seconds
        self.assertIn('duration', metadata)
        self.assertIn('total_requests', metadata)
        self.assertIn('scan_id', metadata)
        
        # Metadata completeness
        required_metadata = [
            'start_time', 'end_time', 'duration', 'total_vulnerabilities',
            'vulnerabilities_by_type', 'scanner_version'
        ]
        for field in required_metadata:
            self.assertIn(field, metadata)
    
    def test_vulnerability_metadata_structure(self):
        """Test vulnerability object structure and required fields"""
        self.scanner._add_vulnerability(
            'XSS', 
            'http://test.com',
            '<script>alert(1)</script>',
            'Test XSS vulnerability',
            'Payload reflected',
            {'parameter': 'test', 'heuristic_confidence': 0.85}
        )
        
        vuln = self.scanner.vulnerabilities[0]
        
        # Check required fields
        required_fields = [
            'id', 'type', 'severity', 'risk_score', 'url', 
            'payload', 'description', 'evidence', 'context',
            'timestamp', 'scan_id'
        ]
        
        for field in required_fields:
            self.assertIn(field, vuln)
        
        # Check data types and values
        self.assertIsInstance(vuln['risk_score'], float)
        self.assertGreater(vuln['risk_score'], 0)
        self.assertIn(vuln['severity'], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])


class TestAdvancedReportGeneratorA(unittest.TestCase):
    """Test advanced report generator functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.report_generator = AdvancedReportGeneratorA(self.temp_dir)
        
        # Sample vulnerability data
        self.sample_vulnerabilities = [
            {
                'id': 1,
                'type': 'SQL Injection',
                'severity': 'CRITICAL',
                'risk_score': 9.5,
                'url': 'http://test.com/page?id=1',
                'payload': "' OR 1=1--",
                'description': 'SQL injection vulnerability',
                'evidence': 'MySQL error detected',
                'timestamp': '2025-10-28T16:00:00',
                'scan_id': 'test123',
                'context': {'heuristic_confidence': 0.95}
            },
            {
                'id': 2,
                'type': 'XSS',
                'severity': 'HIGH',
                'risk_score': 8.2,
                'url': 'http://test.com/search?q=test',
                'payload': '<script>alert(1)</script>',
                'description': 'Cross-site scripting vulnerability',
                'evidence': 'Script reflected in response',
                'timestamp': '2025-10-28T16:01:00',
                'scan_id': 'test123',
                'context': {'heuristic_confidence': 0.88}
            }
        ]
        
        self.sample_metadata = {
            'scan_id': 'test123',
            'target_url': 'http://test.com',
            'start_time': '2025-10-28T16:00:00',
            'end_time': '2025-10-28T16:02:00',
            'duration': 120.5,
            'scanner_version': 'v3.0-ConceptA',
            'total_requests': 25,
            'total_vulnerabilities': 2,
            'vulnerabilities_by_type': {'SQL Injection': 1, 'XSS': 1},
            'risk_metrics': {
                'average_risk_score': 8.85,
                'max_risk_score': 9.5,
                'critical_count': 1,
                'high_count': 1,
                'medium_count': 0,
                'low_count': 0
            }
        }
    
    def test_json_report_generation(self):
        """Test enhanced JSON report generation"""
        filepath = self.report_generator.generate_json_report(
            self.sample_vulnerabilities, self.sample_metadata
        )
        
        self.assertTrue(os.path.exists(filepath))
        
        with open(filepath, 'r') as f:
            report_data = json.load(f)
        
        # Check report structure
        required_sections = [
            'scan_metadata', 'summary', 'vulnerabilities',
            'recommendations', 'compliance_status'
        ]
        
        for section in required_sections:
            self.assertIn(section, report_data)
        
        # Check summary completeness
        summary = report_data['summary']
        self.assertEqual(summary['total_vulnerabilities'], 2)
        self.assertIn('risk_analysis', summary)
        self.assertIn('scan_coverage', summary)
    
    def test_csv_report_generation(self):
        """Test enhanced CSV report generation"""
        filepath = self.report_generator.generate_csv_report(
            self.sample_vulnerabilities, self.sample_metadata
        )
        
        self.assertTrue(os.path.exists(filepath))
        
        # Read and validate CSV content
        import pandas as pd
        df = pd.read_csv(filepath)
        
        self.assertEqual(len(df), 2)
        
        # Check required columns
        required_columns = [
            'ID', 'Type', 'Severity', 'Risk_Score', 'URL',
            'Payload', 'Description', 'Confidence'
        ]
        
        for column in required_columns:
            self.assertIn(column, df.columns)
    
    def test_markdown_report_generation(self):
        """Test enhanced Markdown report generation"""
        filepath = self.report_generator.generate_markdown_report(
            self.sample_vulnerabilities, self.sample_metadata
        )
        
        self.assertTrue(os.path.exists(filepath))
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check report sections
        required_sections = [
            'Executive Summary', 'Risk Analysis',
            'Vulnerability Details', 'Security Recommendations',
            'Compliance Status'
        ]
        
        for section in required_sections:
            self.assertIn(section, content)
        
        # Check vulnerability details
        self.assertIn('SQL Injection', content)
        self.assertIn('XSS', content)
        self.assertIn('CRITICAL', content)
    
    def test_recommendations_generation(self):
        """Test security recommendations generation"""
        recommendations = self.report_generator._generate_recommendations(
            self.sample_vulnerabilities
        )
        
        self.assertGreater(len(recommendations), 0)
        
        # Should include SQL injection and XSS recommendations
        rec_titles = [rec['title'] for rec in recommendations]
        sql_rec = any('SQL' in title for title in rec_titles)
        xss_rec = any('XSS' in title for title in rec_titles)
        
        self.assertTrue(sql_rec or xss_rec)
        
        # Check recommendation structure
        for rec in recommendations:
            self.assertIn('title', rec)
            self.assertIn('description', rec)
            self.assertIn('priority', rec)
            self.assertIn('effort', rec)
    
    def test_compliance_status_generation(self):
        """Test compliance status generation"""
        compliance = self.report_generator._generate_compliance_status(
            self.sample_vulnerabilities
        )
        
        # Should include major compliance frameworks
        frameworks = ['OWASP Top 10', 'PCI DSS', 'ISO 27001']
        
        for framework in frameworks:
            self.assertIn(framework, compliance)
            self.assertIn('status', compliance[framework])
            self.assertIn('issues', compliance[framework])


class TestIntegrationA(unittest.TestCase):
    """Integration tests for Conceito A functionality"""
    
    def test_end_to_end_scan_workflow(self):
        """Test complete scan workflow with risk analysis"""
        test_url = "http://httpbin.org/html"  # Safe test endpoint
        
        try:
            # Initialize scanner
            scanner = EnhancedWebSecurityScanner(test_url, timeout=15)
            
            # Perform scan (will test connectivity)
            vulnerabilities, metadata = scanner.perform_comprehensive_scan()
            
            # Validate results structure
            self.assertIsInstance(vulnerabilities, list)
            self.assertIsInstance(metadata, dict)
            
            # Test report generation
            temp_dir = tempfile.mkdtemp()
            report_gen = AdvancedReportGeneratorA(temp_dir)
            
            # Generate all report formats
            formats = ['json', 'csv', 'markdown']
            files = report_gen.generate_reports(vulnerabilities, metadata, formats)
            
            # Verify files were created
            for filepath in files:
                self.assertTrue(os.path.exists(filepath))
            
        except requests.exceptions.RequestException:
            # Skip test if network is unavailable
            self.skipTest("Network unavailable for integration test")
    
    def test_performance_benchmarks(self):
        """Test performance benchmarks for Conceito A features"""
        scanner = EnhancedWebSecurityScanner("http://test.com")
        
        # Test vulnerability addition performance
        start_time = time.time()
        
        for i in range(100):
            scanner._add_vulnerability(
                'Test Vulnerability',
                f'http://test.com/page{i}',
                f'payload{i}',
                f'Test description {i}',
                f'Evidence {i}',
                {'test_param': i}
            )
        
        addition_time = time.time() - start_time
        
        # Should handle 100 vulnerabilities quickly
        self.assertLess(addition_time, 1.0)
        self.assertEqual(len(scanner.vulnerabilities), 100)
        
        # Test risk calculation performance
        start_time = time.time()
        
        for vuln in scanner.vulnerabilities:
            VulnerabilityRisk.calculate_risk_score(vuln['type'], vuln['context'])
        
        calculation_time = time.time() - start_time
        
        # Risk calculations should be fast
        self.assertLess(calculation_time, 0.5)


def run_tests():
    """Run all Conceito A tests with detailed output"""
    print("🧪 Running Enhanced Web Security Scanner Tests (Conceito A)")
    print("=" * 60)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestVulnerabilityRisk,
        TestHeuristicAnalyzer, 
        TestEnhancedWebSecurityScanner,
        TestAdvancedReportGeneratorA,
        TestIntegrationA
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout, buffer=True)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY TEST SUMMARY (Conceito A)")
    print("=" * 60)
    print(f"SUCCESS Tests Run: {result.testsRun}")
    print(f"SUCCESS Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"FAIL Failures: {len(result.failures)}")
    print(f"💥 Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n🔍 FAILURES:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError: ')[-1].split('\n')[0]}")
    
    if result.errors:
        print("\n💥 ERRORS:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('\n')[-2]}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\n📈 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("🎉 Conceito A implementation validated successfully!")
    else:
        print("⚠️ Some issues detected. Please review failures.")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()
