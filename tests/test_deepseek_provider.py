"""
Tests for DeepSeek provider integration.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from llm.deepseek_provider import DeepSeekProvider
from llm.unified_client import UnifiedLLMClient


class SimpleSchema(BaseModel):
    """Simple test schema."""
    message: str
    count: int


class TestDeepSeekProvider(unittest.TestCase):
    """Test suite for DeepSeek provider."""
    
    def test_provider_initialization_with_api_key(self):
        """Test that DeepSeek provider initializes with API key."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY",
                "base_url": "https://api.deepseek.com"
            }
        }
        
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test_key"}):
            with patch('llm.deepseek_provider.OpenAI') as mock_openai:
                DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
                
                # Verify OpenAI client was initialized with correct parameters
                mock_openai.assert_called_once()
                call_kwargs = mock_openai.call_args[1]
                self.assertEqual(call_kwargs['api_key'], "test_key")
                self.assertEqual(call_kwargs['base_url'], "https://api.deepseek.com")
    
    def test_provider_initialization_missing_api_key(self):
        """Test that provider raises error when API key is missing."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY"
            }
        }
        
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as context:
                DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
            
            self.assertIn("DEEPSEEK_API_KEY", str(context.exception))
    
    def test_provider_uses_env_base_url(self):
        """Test that DEEPSEEK_BASE_URL environment variable is used."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY",
                "base_url": "https://default.deepseek.com"
            }
        }
        
        with patch.dict(os.environ, {
            "DEEPSEEK_API_KEY": "test_key",
            "DEEPSEEK_BASE_URL": "https://custom.deepseek.com"
        }):
            with patch('llm.deepseek_provider.OpenAI') as mock_openai:
                DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
                
                # Verify environment variable takes precedence
                call_kwargs = mock_openai.call_args[1]
                self.assertEqual(call_kwargs['base_url'], "https://custom.deepseek.com")
    
    def test_provider_uses_default_base_url(self):
        """Test that default base URL is used when not specified."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY"
            }
        }
        
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test_key"}):
            with patch('llm.deepseek_provider.OpenAI') as mock_openai:
                DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
                
                # Verify default base URL is used
                call_kwargs = mock_openai.call_args[1]
                self.assertEqual(call_kwargs['base_url'], "https://api.deepseek.com")
    
    def test_unified_client_selects_deepseek_provider(self):
        """Test that UnifiedLLMClient correctly initializes DeepSeek provider."""
        config = {
            "models": {
                "scout": {
                    "provider": "deepseek",
                    "model": "deepseek-chat"
                }
            },
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY"
            }
        }
        
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test_key"}):
            with patch('llm.unified_client.DeepSeekProvider') as MockDeepSeekProvider:
                mock_provider_instance = MagicMock()
                mock_provider_instance.provider_name = "DeepSeek"
                mock_provider_instance.supports_thinking = False
                MockDeepSeekProvider.return_value = mock_provider_instance
                
                client = UnifiedLLMClient(config, profile="scout")
                
                # Verify DeepSeekProvider was instantiated
                MockDeepSeekProvider.assert_called_once()
                self.assertEqual(client.provider.provider_name, "DeepSeek")
    
    def test_provider_name(self):
        """Test that provider reports correct name."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY"
            }
        }
        
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test_key"}):
            with patch('llm.deepseek_provider.OpenAI'):
                provider = DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
                
                self.assertEqual(provider.provider_name, "DeepSeek")
    
    def test_supports_thinking(self):
        """Test that DeepSeek provider reports thinking support correctly."""
        config = {
            "deepseek": {
                "api_key_env": "DEEPSEEK_API_KEY"
            }
        }
        
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test_key"}):
            with patch('llm.deepseek_provider.OpenAI'):
                provider = DeepSeekProvider(
                    config=config,
                    model_name="deepseek-chat"
                )
                
                # DeepSeek supports complex reasoning but not explicit thinking mode
                self.assertFalse(provider.supports_thinking)


if __name__ == '__main__':
    unittest.main()
