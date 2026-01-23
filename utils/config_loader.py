"""
Centralized configuration loading utility.
"""

import os
from pathlib import Path
from typing import Any

import yaml


def get_default_config() -> dict[str, Any]:
    """
    Generate a default configuration based on available API keys.
    
    This allows the system to work without a config.yaml file when
    API keys are set via environment variables.
    """
    config: dict[str, Any] = {
        "models": {},
        "context": {
            "max_tokens": 256000,
            "compression_threshold": 0.75,
        },
        "timeouts": {
            "request_seconds": 300,
        },
        "retries": {
            "max_attempts": 3,
            "backoff_min_seconds": 1,
            "backoff_max_seconds": 2,
        },
    }
    
    # Add model profiles based on available API keys
    # Priority: DeepSeek (cheapest) > OpenAI > Gemini > Anthropic
    
    has_deepseek = bool(os.environ.get("DEEPSEEK_API_KEY"))
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    has_gemini = bool(os.environ.get("GOOGLE_API_KEY"))
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY"))
    
    # Graph profile - prefer DeepSeek for cost efficiency (large 256k context)
    if has_deepseek:
        config["models"]["graph"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "max_context": 256000,
        }
    elif has_openai:
        config["models"]["graph"] = {
            "provider": "openai",
            "model": "gpt-4o",
            "max_context": 128000,
        }
    elif has_gemini:
        config["models"]["graph"] = {
            "provider": "gemini",
            "model": "gemini-2.5-pro",
            "max_context": 1000000,
            "thinking_enabled": True,
            "thinking_budget": -1,
        }
    elif has_anthropic:
        config["models"]["graph"] = {
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "max_context": 200000,
        }
    
    # Scout profile - prefer DeepSeek for cost efficiency
    if has_deepseek:
        config["models"]["scout"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "max_context": 256000,
        }
    elif has_openai:
        config["models"]["scout"] = {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "max_context": 128000,
        }
    elif has_gemini:
        config["models"]["scout"] = {
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "max_context": 1000000,
        }
    
    # Strategist profile - prefer DeepSeek
    if has_deepseek:
        config["models"]["strategist"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "max_context": 256000,
        }
    elif has_openai:
        config["models"]["strategist"] = {
            "provider": "openai",
            "model": "gpt-4o",
            "max_context": 128000,
        }
    elif has_gemini:
        config["models"]["strategist"] = {
            "provider": "gemini",
            "model": "gemini-2.5-pro",
            "max_context": 1000000,
        }
    
    # Finalize/QA profile - prefer DeepSeek
    if has_deepseek:
        config["models"]["finalize"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "max_context": 256000,
        }
    elif has_openai:
        config["models"]["finalize"] = {
            "provider": "openai",
            "model": "gpt-4o",
            "max_context": 128000,
        }
    elif has_gemini:
        config["models"]["finalize"] = {
            "provider": "gemini",
            "model": "gemini-2.5-pro",
            "max_context": 1000000,
        }
    elif has_anthropic:
        config["models"]["finalize"] = {
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "max_context": 200000,
        }
    
    # Reporting profile - prefer DeepSeek
    if has_deepseek:
        config["models"]["reporting"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
            "max_context": 256000,
        }
    elif has_openai:
        config["models"]["reporting"] = {
            "provider": "openai",
            "model": "gpt-4o",
            "max_context": 128000,
        }
    elif has_gemini:
        config["models"]["reporting"] = {
            "provider": "gemini",
            "model": "gemini-2.5-flash",
            "max_context": 1000000,
        }
    
    # Lightweight profile for quick tasks - prefer DeepSeek
    if has_deepseek:
        config["models"]["lightweight"] = {
            "provider": "deepseek",
            "model": "deepseek-chat",
        }
    elif has_openai:
        config["models"]["lightweight"] = {
            "provider": "openai",
            "model": "gpt-4o-mini",
        }
    elif has_gemini:
        config["models"]["lightweight"] = {
            "provider": "gemini",
            "model": "gemini-2.5-flash",
        }
    
    # Add API key configurations
    if has_openai:
        config["openai"] = {"api_key_env": "OPENAI_API_KEY"}
    if has_gemini:
        config["gemini"] = {"api_key_env": "GOOGLE_API_KEY"}
    if has_anthropic:
        config["anthropic"] = {"api_key_env": "ANTHROPIC_API_KEY"}
    if has_deepseek:
        config["deepseek"] = {"api_key_env": "DEEPSEEK_API_KEY", "base_url": "https://api.deepseek.com"}
    
    return config


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Priority order:
    1. Explicitly provided config_path
    2. HOUND_CONFIG environment variable
    3. config.yaml in current directory
    4. config.yaml in hound directory
    5. config.example.yaml in hound directory (renamed to config.yaml.example)
    6. Auto-generated default config based on environment variables
    """
    
    # If explicit path provided, use it
    if config_path and config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    
    # Check environment variable
    if os.environ.get('HOUND_CONFIG'):
        env_config = Path(os.environ['HOUND_CONFIG'])
        if env_config.exists():
            with open(env_config) as f:
                return yaml.safe_load(f) or {}
    
    # Try current directory
    cwd_config = Path.cwd() / "config.yaml"
    if cwd_config.exists():
        with open(cwd_config) as f:
            return yaml.safe_load(f) or {}
    
    # Try hound directory (where this module lives)
    hound_dir = Path(__file__).parent.parent
    
    # Try config.yaml in hound directory
    hound_config = hound_dir / "config.yaml"
    if hound_config.exists():
        with open(hound_config) as f:
            return yaml.safe_load(f) or {}
    
    # Fallback to example config (try both naming conventions)
    for example_name in ["config.example.yaml", "config.yaml.example"]:
        example_config = hound_dir / example_name
        if example_config.exists():
            with open(example_config) as f:
                return yaml.safe_load(f) or {}
    
    # Last resort: generate default config from environment variables
    # This allows Docker/cloud deployments to work without a config file
    return get_default_config()