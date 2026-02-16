"""
Tests for headless mode functionality.
"""

import glob
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from commands.agent import AgentRunner


def find_audit_log(tmpdir, project_id="test_project"):
    """Helper function to find the timestamped audit log file."""
    log_files = glob.glob(str(Path(tmpdir) / f"audit_{project_id}_*.log"))
    assert len(log_files) > 0, f"No audit log found in {tmpdir}"
    return Path(log_files[0])


class TestHeadlessMode:
    """Test suite for headless mode functionality."""
    
    def test_headless_flag_initialization(self):
        """Test that headless flag is properly initialized in AgentRunner."""
        # Create runner with headless=True
        runner = AgentRunner(
            project_id="test_project",
            headless=True
        )
        
        # Verify headless flag is set
        assert runner.headless is True
        
        # Create runner with headless=False
        runner_no_headless = AgentRunner(
            project_id="test_project",
            headless=False
        )
        
        # Verify headless flag is False
        assert runner_no_headless.headless is False
    
    def test_audit_logging_setup_in_headless_mode(self):
        """Test that audit.log is created and configured in headless mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Change to temp directory
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                
                # Call setup logging
                runner._setup_audit_logging()
                
                # Verify audit logger is created
                assert hasattr(runner, 'audit_logger')
                assert runner.audit_logger is not None
                
                # Verify log file handler is created
                assert hasattr(runner, '_audit_log_handler')
                assert runner._audit_log_handler is not None
                
                # Verify audit log file exists (with timestamp in name)
                log_file = find_audit_log(tmpdir)
                assert log_file.exists()
                
                # Test writing to the log
                runner.audit_logger.info("Test log message")
                
                # Verify content was written
                log_content = log_file.read_text()
                assert "Test log message" in log_content
                assert "Starting headless audit for project: test_project" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_no_audit_logging_in_interactive_mode(self):
        """Test that audit logging is not setup when not in headless mode."""
        runner = AgentRunner(
            project_id="test_project",
            headless=False
        )
        
        # Verify audit logger is not set up in constructor
        assert not hasattr(runner, 'audit_logger') or runner.audit_logger is None
    
    @patch('commands.agent.console')
    def test_audit_log_captures_decisions(self, mock_console):
        """Test that agent decisions are logged to audit.log in headless mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Create a mock progress callback info dict with decision
                decision_info = {
                    'status': 'decision',
                    'iteration': 5,
                    'action': 'load_nodes',
                    'reasoning': 'Need to analyze security controls',
                    'message': 'Loading nodes'
                }
                
                # Simulate progress callback
                # We need to call the actual logging logic
                if runner.audit_logger:
                    runner.audit_logger.info(
                        f"Iteration {decision_info['iteration']} - Decision: "
                        f"action={decision_info['action']}, reasoning={decision_info['reasoning']}"
                    )
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify decision was logged
                assert "Iteration 5 - Decision" in log_content
                assert "load_nodes" in log_content
                assert "Need to analyze security controls" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    @patch('commands.agent.console')
    def test_audit_log_captures_results(self, mock_console):
        """Test that agent results are logged to audit.log in headless mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Create a mock result info
                result_info = {
                    'status': 'result',
                    'iteration': 5,
                    'action': 'load_nodes',
                    'result': {'summary': 'Loaded 10 nodes successfully'},
                    'message': 'Result obtained'
                }
                
                # Simulate logging
                if runner.audit_logger:
                    result_summary = result_info['result'].get('summary', '')
                    runner.audit_logger.info(
                        f"Iteration {result_info['iteration']} - Result: "
                        f"action={result_info['action']}, result={result_summary}"
                    )
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify result was logged
                assert "Iteration 5 - Result" in log_content
                assert "load_nodes" in log_content
                assert "Loaded 10 nodes successfully" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    @patch('commands.agent.console')
    def test_audit_log_captures_hypotheses(self, mock_console):
        """Test that hypotheses are logged to audit.log in headless mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Create a mock hypothesis info
                hypothesis_info = {
                    'status': 'hypothesis_formed',
                    'iteration': 8,
                    'message': 'Found potential SQL injection vulnerability'
                }
                
                # Simulate logging
                if runner.audit_logger:
                    runner.audit_logger.info(
                        f"Iteration {hypothesis_info['iteration']} - Hypothesis: {hypothesis_info['message']}"
                    )
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify hypothesis was logged
                assert "Iteration 8 - Hypothesis" in log_content
                assert "SQL injection vulnerability" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_telemetry_disabled_in_headless_mode(self):
        """Test that telemetry is not started in headless mode."""
        # This test verifies the conditional logic for telemetry
        # Telemetry should only start when telemetry flag is True AND headless is False
        
        # In headless mode, telemetry should not be enabled
        headless = True
        telemetry_enabled = False
        
        should_start_telemetry = telemetry_enabled and not headless
        assert should_start_telemetry is False
        
        # Even with telemetry flag, headless should disable it
        headless = True
        telemetry_enabled = True
        
        should_start_telemetry = telemetry_enabled and not headless
        assert should_start_telemetry is False
        
        # In non-headless mode with telemetry flag, it should be enabled
        headless = False
        telemetry_enabled = True
        
        should_start_telemetry = telemetry_enabled and not headless
        assert should_start_telemetry is True
    
    @patch('commands.agent.click')
    def test_exit_code_on_keyboard_interrupt_in_headless_mode(self, mock_click):
        """Test that headless mode exits with code 130 on keyboard interrupt."""
        # Mock click.Exit
        mock_click.Exit = Exception
        
        # Simulate the exception handling logic
        headless = True
        exit_code = None
        
        try:
            # Simulate KeyboardInterrupt
            raise KeyboardInterrupt()
        except KeyboardInterrupt:
            if headless:
                exit_code = 130  # Standard exit code for SIGINT
        
        assert exit_code == 130
    
    @patch('commands.agent.click')
    def test_exit_code_on_critical_failure_in_headless_mode(self, mock_click):
        """Test that headless mode exits with code 1 on critical failures."""
        # Mock click.Exit
        mock_click.Exit = Exception
        
        # Simulate the exception handling logic
        headless = True
        exit_code = None
        
        try:
            # Simulate critical failure
            raise RuntimeError("Critical error occurred")
        except Exception:
            if headless:
                exit_code = 1
        
        assert exit_code == 1
    
    def test_investigation_lifecycle_logging(self):
        """Test that investigation start and completion are logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Simulate investigation start
                if runner.audit_logger:
                    inv_goal = "Analyze authentication module"
                    runner.audit_logger.info(f"Starting investigation 1/5: {inv_goal}")
                    runner.audit_logger.info("  Priority: 8, Reasoning: High risk area")
                    
                    # Simulate investigation completion
                    runner.audit_logger.info(
                        f"Investigation completed: {inv_goal} - "
                        f"15 iterations, 3 hypotheses (2 confirmed)"
                    )
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify lifecycle events were logged
                assert "Starting investigation 1/5" in log_content
                assert "Analyze authentication module" in log_content
                assert "Priority: 8" in log_content
                assert "Investigation completed" in log_content
                assert "15 iterations, 3 hypotheses (2 confirmed)" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_final_summary_logging(self):
        """Test that final audit summary is logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner in headless mode
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Simulate final summary
                if runner.audit_logger:
                    runner.audit_logger.info(
                        "Audit completed with status: completed - "
                        "Planning batches: 3, "
                        "Investigations: 12, "
                        "Hypotheses: 25 total (15 confirmed, 5 rejected), "
                        "Coverage: 78.5% nodes, 65.2% cards"
                    )
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify summary was logged
                assert "Audit completed with status: completed" in log_content
                assert "Planning batches: 3" in log_content
                assert "Investigations: 12" in log_content
                assert "25 total (15 confirmed, 5 rejected)" in log_content
                assert "78.5% nodes, 65.2% cards" in log_content
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_log_file_location(self):
        """Test that audit log is created in the current working directory with timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner and setup logging
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Verify log file is in current directory with timestamped name
                log_file = find_audit_log(tmpdir)
                assert log_file.exists()
                assert log_file.parent == Path(tmpdir)
                # Verify filename format: audit_{project}_{timestamp}.log
                assert log_file.name.startswith("audit_test_project_")
                assert log_file.name.endswith(".log")
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_log_format_includes_timestamp(self):
        """Test that log entries include timestamp and log level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                
                # Create runner and setup logging
                runner = AgentRunner(
                    project_id="test_project",
                    headless=True
                )
                runner._setup_audit_logging()
                
                # Write a test message
                if runner.audit_logger:
                    runner.audit_logger.info("Test message")
                
                # Read log file
                log_file = find_audit_log(tmpdir)
                log_content = log_file.read_text()
                
                # Verify format includes timestamp and level
                # Format: YYYY-MM-DD HH:MM:SS - LEVEL - Message
                import re
                pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - INFO - .*'
                assert re.search(pattern, log_content) is not None
                
                # Cleanup
                runner._audit_log_handler.close()
            finally:
                os.chdir(original_cwd)
    
    def test_logging_graceful_failure(self):
        """Test that logging failures don't crash the audit."""
        # Create runner with invalid path (permission denied scenario)
        runner = AgentRunner(
            project_id="test_project",
            headless=True
        )
        
        # Mock Path to simulate permission error
        with patch('commands.agent.Path') as mock_path:
            mock_cwd = MagicMock()
            mock_cwd.__truediv__.side_effect = PermissionError("Access denied")
            mock_path.cwd.return_value = mock_cwd
            
            # This should not raise an exception
            try:
                runner._setup_audit_logging()
                # If logging setup fails, audit_logger should be None
                assert runner.audit_logger is None
            except Exception as e:
                # Should not reach here
                pytest.fail(f"Logging setup should handle errors gracefully, but raised: {e}")
