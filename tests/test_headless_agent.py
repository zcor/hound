"""
Unit tests for headless agent adaptation features.

Tests rate limit handling, budget tracking, and database-driven abort mechanism.
"""

import json
import os
import sys
import unittest
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.exceptions import BudgetExceededException, RateLimitException


class TestRateLimitException(unittest.TestCase):
    """Test RateLimitException class."""
    
    def test_exception_creation(self):
        """Test that RateLimitException can be created with parameters."""
        exc = RateLimitException(
            message="Rate limit hit",
            provider="openai",
            retry_after=60,
            state={'test': 'data'}
        )
        
        self.assertEqual(exc.message, "Rate limit hit")
        self.assertEqual(exc.provider, "openai")
        self.assertEqual(exc.retry_after, 60)
        self.assertEqual(exc.state, {'test': 'data'})
    
    def test_exception_str(self):
        """Test string representation of exception."""
        exc = RateLimitException(
            message="Rate limit hit",
            provider="anthropic",
            retry_after=30
        )
        
        str_repr = str(exc)
        self.assertIn("Rate limit hit", str_repr)
        self.assertIn("anthropic", str_repr)
        self.assertIn("30s", str_repr)


class TestBudgetExceededException(unittest.TestCase):
    """Test BudgetExceededException class."""
    
    def test_exception_creation(self):
        """Test that BudgetExceededException can be created with parameters."""
        exc = BudgetExceededException(
            message="Budget exceeded",
            budget_limit=1000,
            current_usage=1100,
            usage_type='tokens'
        )
        
        self.assertEqual(exc.message, "Budget exceeded")
        self.assertEqual(exc.budget_limit, 1000)
        self.assertEqual(exc.current_usage, 1100)
        self.assertEqual(exc.usage_type, 'tokens')
    
    def test_exception_str(self):
        """Test string representation of exception."""
        exc = BudgetExceededException(
            message="Budget exceeded",
            budget_limit=1000,
            current_usage=1100,
            usage_type='tokens'
        )
        
        str_repr = str(exc)
        self.assertIn("Budget exceeded", str_repr)
        self.assertIn("1000", str_repr)
        self.assertIn("1100", str_repr)
        self.assertIn("tokens", str_repr)


class TestAgentBudgetTracking(unittest.TestCase):
    """Test budget tracking functionality."""
    
    def test_update_budget_usage_tokens(self):
        """Test budget tracking for tokens."""
        # Import agent_core to test the _update_budget_usage method
        from analysis.agent_core import AutonomousAgent
        
        # Create a minimal agent-like object for testing
        agent = Mock(spec=AutonomousAgent)
        agent.budget_limit = 1000
        agent.budget_type = 'tokens'
        agent.budget_used = 0.0
        agent.debug = False
        
        # Bind the method to our mock agent
        from types import MethodType
        agent._update_budget_usage = MethodType(AutonomousAgent._update_budget_usage, agent)
        
        # Mock token tracker
        with patch('analysis.agent_core.get_token_tracker') as mock_tracker:
            mock_tracker_instance = Mock()
            mock_tracker_instance.get_last_usage.return_value = {
                'input_tokens': 100,
                'output_tokens': 50
            }
            mock_tracker.return_value = mock_tracker_instance
            
            # Update budget
            agent._update_budget_usage()
            
            # Check that budget was updated
            self.assertEqual(agent.budget_used, 150)
    
    def test_update_budget_usage_cost(self):
        """Test budget tracking for cost."""
        from analysis.agent_core import AutonomousAgent
        
        agent = Mock(spec=AutonomousAgent)
        agent.budget_limit = 1.0
        agent.budget_type = 'cost'
        agent.budget_used = 0.0
        agent.debug = False
        # Add class constants to mock
        agent.DEFAULT_INPUT_TOKEN_COST = AutonomousAgent.DEFAULT_INPUT_TOKEN_COST
        agent.DEFAULT_OUTPUT_TOKEN_COST = AutonomousAgent.DEFAULT_OUTPUT_TOKEN_COST
        
        from types import MethodType
        agent._update_budget_usage = MethodType(AutonomousAgent._update_budget_usage, agent)
        
        with patch('analysis.agent_core.get_token_tracker') as mock_tracker:
            mock_tracker_instance = Mock()
            mock_tracker_instance.get_last_usage.return_value = {
                'input_tokens': 1000,  # $0.01
                'output_tokens': 1000   # $0.03
            }
            mock_tracker.return_value = mock_tracker_instance
            
            agent._update_budget_usage()
            
            # Check that budget was updated (approximately $0.04)
            self.assertAlmostEqual(agent.budget_used, 0.04, places=4)
    
    def test_update_budget_usage_no_limit(self):
        """Test that budget tracking is skipped when no limit is set."""
        from analysis.agent_core import AutonomousAgent
        
        agent = Mock(spec=AutonomousAgent)
        agent.budget_limit = None
        agent.budget_used = 0.0
        agent.debug = False
        
        from types import MethodType
        agent._update_budget_usage = MethodType(AutonomousAgent._update_budget_usage, agent)
        
        agent._update_budget_usage()
        
        # Budget should still be 0
        self.assertEqual(agent.budget_used, 0.0)


class TestAgentStatePersistence(unittest.TestCase):
    """Test agent state save and restore functionality."""
    
    def test_save_investigation_state(self):
        """Test that investigation state can be saved."""
        from analysis.agent_core import AutonomousAgent
        
        agent = Mock(spec=AutonomousAgent)
        agent.agent_id = "test_agent"
        agent.session_id = "test_session"
        agent.investigation_goal = "Test investigation"
        agent.conversation_history = [{'role': 'user', 'content': 'test'}]
        agent.memory_notes = ['note 1', 'note 2']
        agent.action_log = [{'action': 'test', 'result': 'success'}]
        agent.loaded_data = {
            'graphs': {'graph1': {}, 'graph2': {}},
            'nodes': {'node1': {}, 'node2': {}}
        }
        agent.budget_used = 100.0
        agent.debug = False
        
        from types import MethodType
        agent._save_investigation_state = MethodType(AutonomousAgent._save_investigation_state, agent)
        
        state = agent._save_investigation_state()
        
        # Check that state was saved
        self.assertEqual(state['agent_id'], "test_agent")
        self.assertEqual(state['session_id'], "test_session")
        self.assertEqual(state['investigation_goal'], "Test investigation")
        self.assertEqual(len(state['conversation_history']), 1)
        self.assertEqual(len(state['memory_notes']), 2)
        self.assertEqual(len(state['action_log']), 1)
        self.assertEqual(len(state['loaded_graphs']), 2)
        self.assertEqual(len(state['loaded_nodes']), 2)
        self.assertEqual(state['budget_used'], 100.0)
        self.assertIsNotNone(state['timestamp'])


class TestDatabaseAbortMechanism(unittest.TestCase):
    """Test database-driven abort mechanism."""
    
    def test_request_abort(self):
        """Test that request_abort sets the abort flag correctly."""
        from analysis.agent_core import AutonomousAgent
        
        agent = Mock(spec=AutonomousAgent)
        agent._abort_requested = False
        agent._abort_reason = None
        
        from types import MethodType
        agent.request_abort = MethodType(AutonomousAgent.request_abort, agent)
        
        agent.request_abort("test reason")
        
        self.assertTrue(agent._abort_requested)
        self.assertEqual(agent._abort_reason, "test reason")


if __name__ == "__main__":
    unittest.main()

