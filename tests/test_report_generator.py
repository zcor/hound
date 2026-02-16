"""
Tests for ReportGenerator to ensure it builds reports and calls LLM.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from analysis.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Create project structure
        (self.tmp / 'graphs').mkdir()
        # Simple graph file
        (self.tmp / 'graphs' / 'graph_SystemArchitecture.json').write_text(
            json.dumps({
                'name': 'SystemArchitecture',
                'nodes': [{'id': 'n1', 'label': 'Comp', 'type': 'component'}],
                'edges': []
            })
        )
        # Hypotheses
        (self.tmp / 'hypotheses.json').write_text(json.dumps({
            'hypotheses': {
                'h1': {'title': 'test', 'vulnerability_type': 'x', 'severity': 'low', 'confidence': 0.9, 'status': 'confirmed'}
            }
        }))
        # No agent_runs required

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_generate_html_report(self):
        cfg = {'models': {'reporting': {'provider': 'openai', 'model': 'x'}}}
        with patch('analysis.report_generator.UnifiedLLMClient') as MockLLM:
            mock_llm = MagicMock()
            MockLLM.return_value = mock_llm
            
            # Setup mock to return different responses for different calls
            def mock_raw_side_effect(*args, **kwargs):
                user_prompt = kwargs.get('user', '')
                system_prompt = kwargs.get('system', '')
                # Match based on system prompt for more reliable differentiation
                if 'senior security auditor' in system_prompt and 'PROJECT_NAME' in user_prompt:
                    return ('{"application_name": "Test App", '
                            '"executive_summary": "Executive Summary Here", '
                            '"system_overview": "System Overview Here"}')
                elif 'Vulnerabilities to describe' in user_prompt:
                    return '{"0": {"description": "Professional description", "affected_components": "Test component"}}'
                elif 'remediation advice' in user_prompt.lower():
                    return '{"0": "Add input validation and implement proper access controls."}'
                else:
                    return '{}'
            
            mock_llm.raw.side_effect = mock_raw_side_effect

            rg = ReportGenerator(self.tmp, cfg)
            html = rg.generate(project_name='Proj', project_source='repo', title='Report', auditors=['A'])
            self.assertIn('Executive Summary', html)
            self.assertIn('Proj', html)
            self.assertIn('Findings', html)
            self.assertIn('System Overview', html)
            # Verify remediation advice is included
            self.assertIn('Remediation', html)
            # Verify badge section is included
            self.assertIn('README Badge', html)
            self.assertIn('Audited_by-Firepan', html)  # Badge URL format uses underscores
    
    def test_remediation_advice_generation(self):
        """Test that remediation advice is generated for findings."""
        cfg = {'models': {'reporting': {'provider': 'openai', 'model': 'x'}}}
        with patch('analysis.report_generator.UnifiedLLMClient') as MockLLM:
            mock_llm = MagicMock()
            MockLLM.return_value = mock_llm
            
            # Mock the remediation advice generation
            mock_llm.raw.return_value = '{"0": "Implement proper input validation and add access control checks."}'
            
            rg = ReportGenerator(self.tmp, cfg)
            findings = [
                {
                    'title': 'Access Control Issue',
                    'type': 'access_control',
                    'severity': 'high',
                    'description': 'Missing access control',
                    'professional_description': 'The function lacks proper access control.',
                    'affected_description': 'the main contract'
                }
            ]
            
            result = rg._batch_generate_remediation_advice(findings)
            
            # Verify LLM was called
            self.assertTrue(mock_llm.raw.called)
            # Verify result contains remediation advice
            self.assertIn(0, result)
            self.assertIn('validation', result[0].lower())
    
    def test_badge_generation(self):
        """Test that badge HTML is generated correctly."""
        cfg = {'models': {'reporting': {'provider': 'openai', 'model': 'x'}}}
        with patch('analysis.report_generator.UnifiedLLMClient') as MockLLM:
            mock_llm = MagicMock()
            MockLLM.return_value = mock_llm
            
            rg = ReportGenerator(self.tmp, cfg)
            
            # Test with no findings
            badge_html = rg._generate_badge_section_html('TestProject', 'January 1, 2025', 0)
            self.assertIn('README Badge', badge_html)
            self.assertIn('28a745', badge_html)  # Green color for no issues
            self.assertIn('Audited_by-Firepan', badge_html)  # Check for badge URL format
            self.assertIn('Firepan Security Audit', badge_html)  # Check for alt text
            self.assertIn('Copy', badge_html)
            
            # Test with findings
            badge_html_with_findings = rg._generate_badge_section_html('TestProject', 'January 1, 2025', 5)
            self.assertIn('dc3545', badge_html_with_findings)  # Red color for multiple issues
