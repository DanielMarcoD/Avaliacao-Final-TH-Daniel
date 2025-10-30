#!/usr/bin/env python3
"""
Teste Simplificado para Enhanced Web Security Scanner - Conceito A
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/../')

def test_imports():
    """Test basic imports"""
    try:
        from scanner_a import EnhancedWebSecurityScanner, VulnerabilityRisk, HeuristicAnalyzer
        from report_generator_a import AdvancedReportGeneratorA
        print("PASS Imports successful")
        return True
    except Exception as e:
        print(f"FAIL Import error: {e}")
        return False

def test_risk_calculation():
    """Test risk calculation"""
    try:
        from scanner_a import VulnerabilityRisk
        
        context = {'public_facing': True, 'sensitive_data': True}
        score = VulnerabilityRisk.calculate_risk_score('SQL Injection', context)
        severity = VulnerabilityRisk.get_severity_level(score)
        
        print(f"PASS Risk calculation: SQL Injection = {score:.1f}/10 ({severity})")
        return True
    except Exception as e:
        print(f"FAIL Risk calculation error: {e}")
        return False

def test_scanner_init():
    """Test scanner initialization"""
    try:
        from scanner_a import EnhancedWebSecurityScanner
        
        scanner = EnhancedWebSecurityScanner("http://test.com")
        print(f"PASS Scanner initialized: {scanner.scan_metadata['scan_id']}")
        return True
    except Exception as e:
        print(f"FAIL Scanner init error: {e}")
        return False

def test_heuristic_analyzer():
    """Test heuristic analyzer"""
    try:
        from scanner_a import HeuristicAnalyzer
        from unittest.mock import Mock
        
        analyzer = HeuristicAnalyzer()
        
        mock_response = Mock()
        mock_response.text = "Warning: mysql_fetch_array() expects"
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.elapsed.total_seconds.return_value = 2.0
        
        analysis = analyzer.analyze_response_behavior(mock_response, "' OR 1=1--")
        
        print(f"PASS Heuristic analysis: confidence = {analysis['confidence_score']:.2f}")
        return True
    except Exception as e:
        print(f"FAIL Heuristic analyzer error: {e}")
        return False

def test_report_generator():
    """Test report generator"""
    try:
        from report_generator_a import AdvancedReportGeneratorA
        import tempfile
        
        temp_dir = tempfile.mkdtemp()
        generator = AdvancedReportGeneratorA(temp_dir)
        
        print(f"PASS Report generator initialized: {temp_dir}")
        return True
    except Exception as e:
        print(f"FAIL Report generator error: {e}")
        return False

def main():
    """Run simplified tests"""
    print("🧪 Conceito A - Testes Simplificados")
    print("=" * 40)
    
    tests = [
        ("Imports", test_imports),
        ("Risk Calculation", test_risk_calculation),
        ("Scanner Init", test_scanner_init), 
        ("Heuristic Analyzer", test_heuristic_analyzer),
        ("Report Generator", test_report_generator)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nTesting Testing {test_name}...")
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"FAIL {test_name} failed: {e}")
    
    print(f"\nResults: Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Conceito A is ready!")
    else:
        print("WARNING Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    main()
