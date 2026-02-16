"""DeepSeek provider implementation."""
from __future__ import annotations

import os
import random
import re
import time
from typing import Any, TypeVar

from openai import OpenAI
from pydantic import BaseModel

from .base_provider import BaseLLMProvider

T = TypeVar('T', bound=BaseModel)


class DeepSeekProvider(BaseLLMProvider):
    """DeepSeek API provider implementation."""
    
    def __init__(
        self, 
        config: dict[str, Any], 
        model_name: str,
        timeout: int = 120,
        retries: int = 3,
        backoff_min: float = 2.0,
        backoff_max: float = 8.0,
        reasoning_effort: str | None = None,
        **kwargs
    ):
        """Initialize DeepSeek provider."""
        self.config = config
        self.model_name = model_name
        self.timeout = timeout
        self.retries = retries
        self.backoff_min = backoff_min
        self.backoff_max = backoff_max
        self.reasoning_effort = reasoning_effort
        # Verbose logging toggle (suppress request logs by default)
        logging_cfg = config.get("logging", {}) if isinstance(config, dict) else {}
        env_verbose = os.environ.get("HOUND_LLM_VERBOSE", "").lower() in {"1","true","yes","on"}
        self.verbose = bool(logging_cfg.get("llm_verbose", False) or env_verbose)
        self._last_token_usage = None
        self._last_reasoning_content = None  # Store reasoning from R1 model
        
        # Check if this is a reasoner model (R1)
        self.is_reasoner = "reasoner" in model_name.lower() or "r1" in model_name.lower()
        
        # Get API key from environment
        api_key_env = config.get("deepseek", {}).get("api_key_env", "DEEPSEEK_API_KEY")
        api_key = os.environ.get(api_key_env)
        if not api_key:
            raise ValueError(f"API key not found in environment variable: {api_key_env}")
        
        # Get base URL from environment variable first, then config, then default
        base_url = os.environ.get("DEEPSEEK_BASE_URL")
        if not base_url:
            base_url = config.get("deepseek", {}).get("base_url", "https://api.deepseek.com")
        
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
    
    def _extract_json_from_text(self, text: str) -> str:
        """Extract JSON from text that may contain markdown or other content."""
        # Try to find JSON in code blocks first
        code_block_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', text)
        if code_block_match:
            return code_block_match.group(1).strip()
        
        # Try to find raw JSON object or array
        # Look for outermost { } or [ ]
        brace_start = text.find('{')
        bracket_start = text.find('[')
        
        if brace_start == -1 and bracket_start == -1:
            return text  # Return as-is, let validation fail with clear error
        
        # Find the first JSON structure
        if brace_start >= 0 and (bracket_start == -1 or brace_start < bracket_start):
            # Find matching closing brace
            depth = 0
            for i, c in enumerate(text[brace_start:], brace_start):
                if c == '{':
                    depth += 1
                elif c == '}':
                    depth -= 1
                    if depth == 0:
                        return text[brace_start:i+1]
        elif bracket_start >= 0:
            # Find matching closing bracket
            depth = 0
            for i, c in enumerate(text[bracket_start:], bracket_start):
                if c == '[':
                    depth += 1
                elif c == ']':
                    depth -= 1
                    if depth == 0:
                        return text[bracket_start:i+1]
        
        return text  # Return as-is if no valid JSON found
    
    def parse(self, *, system: str, user: str, schema: type[T]) -> T:
        """Make a structured call using DeepSeek's chat completions."""
        # Log request details
        request_chars = len(system) + len(user)
        if self.verbose:
            print("\n[DeepSeek Request]")
            print(f"  Model: {self.model_name}")
            print(f"  Reasoner mode: {self.is_reasoner}")
            print(f"  Schema: {schema.__name__}")
            print(f"  Total prompt: {request_chars:,} chars (~{request_chars//4:,} tokens)")
        
        last_err = None
        
        for attempt in range(self.retries):
            try:
                attempt_start = time.time()
                if self.verbose:
                    print(f"  Attempt {attempt + 1}/{self.retries}...")
                
                json_instruction = f"\nPlease respond with valid JSON that matches this schema: {schema.model_json_schema()}"
                enhanced_system = system + json_instruction
                
                if self.is_reasoner:
                    # DeepSeek-Reasoner (R1) has specific requirements:
                    # 1. Does NOT support response_format (JSON mode)
                    # 2. Does NOT support system messages - must use user message only
                    # 3. Returns reasoning_content separately from content
                    # 4. Multi-turn must alternate user/assistant
                    
                    # Combine system + user into single user message for R1
                    combined_prompt = f"{enhanced_system}\n\n---\n\n{user}\n\nIMPORTANT: Your final response must be ONLY valid JSON, no explanations or markdown."
                    
                    messages = [
                        {"role": "user", "content": combined_prompt}
                    ]
                    
                    completion = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=messages,
                        timeout=self.timeout
                        # No response_format for reasoner!
                    )
                    
                    # R1 returns reasoning in a separate field
                    message = completion.choices[0].message
                    if hasattr(message, 'reasoning_content') and message.reasoning_content:
                        self._last_reasoning_content = message.reasoning_content
                        if self.verbose:
                            reasoning_preview = message.reasoning_content[:200] + "..." if len(message.reasoning_content) > 200 else message.reasoning_content
                            print(f"  Reasoning: {reasoning_preview}")
                    
                    # Extract JSON from the content (may have text around it)
                    raw_content = message.content or ""
                    json_str = self._extract_json_from_text(raw_content)
                    
                else:
                    # Standard DeepSeek-Chat model - use JSON mode
                    messages = [
                        {"role": "system", "content": enhanced_system},
                        {"role": "user", "content": user}
                    ]
                    
                    completion = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=messages,
                        timeout=self.timeout,
                        response_format={"type": "json_object"}
                    )
                    
                    json_str = completion.choices[0].message.content
                
                # Parse JSON response
                parsed_result = schema.model_validate_json(json_str)
                
                # Log response details
                response_time = time.time() - attempt_start
                response_content = completion.choices[0].message.content or ""
                
                # Store token usage (R1 includes reasoning_tokens in completion_tokens_details)
                if hasattr(completion, 'usage') and completion.usage:
                    usage_dict = {
                        'input_tokens': completion.usage.prompt_tokens or 0,
                        'output_tokens': completion.usage.completion_tokens or 0,
                        'total_tokens': completion.usage.total_tokens or 0
                    }
                    # R1 model has reasoning_tokens in completion_tokens_details
                    if hasattr(completion.usage, 'completion_tokens_details'):
                        details = completion.usage.completion_tokens_details
                        if details and hasattr(details, 'reasoning_tokens'):
                            usage_dict['reasoning_tokens'] = details.reasoning_tokens or 0
                    self._last_token_usage = usage_dict
                
                if self.verbose:
                    print(f"  Response in {response_time:.2f}s ({len(response_content):,} chars)")
                    if hasattr(completion, 'usage'):
                        usage_info = f"Tokens: {completion.usage.total_tokens}"
                        if self._last_token_usage and 'reasoning_tokens' in self._last_token_usage:
                            usage_info += f" (reasoning: {self._last_token_usage['reasoning_tokens']})"
                        print(f"  {usage_info}")
                
                return parsed_result
                    
            except Exception as e:
                last_err = e
                if self.verbose:
                    print(f"  Error: {e}")
                if attempt < self.retries - 1:
                    sleep_time = random.uniform(self.backoff_min, self.backoff_max)
                    if self.verbose:
                        print(f"  Retrying after {sleep_time:.2f}s...")
                    time.sleep(sleep_time)
        
        raise RuntimeError(f"DeepSeek call failed after {self.retries} attempts: {last_err}")
    
    def raw(self, *, system: str, user: str) -> str:
        """Make a plain text call."""
        if self.is_reasoner:
            # R1 doesn't support system messages
            combined_prompt = f"{system}\n\n---\n\n{user}"
            messages = [{"role": "user", "content": combined_prompt}]
        else:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ]
        
        last_err = None
        for attempt in range(self.retries):
            try:
                completion = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    timeout=self.timeout
                )
                
                # Store reasoning content for R1
                message = completion.choices[0].message
                if self.is_reasoner and hasattr(message, 'reasoning_content') and message.reasoning_content:
                    self._last_reasoning_content = message.reasoning_content
                
                # Store token usage
                if hasattr(completion, 'usage') and completion.usage:
                    usage_dict = {
                        'input_tokens': completion.usage.prompt_tokens or 0,
                        'output_tokens': completion.usage.completion_tokens or 0,
                        'total_tokens': completion.usage.total_tokens or 0
                    }
                    if hasattr(completion.usage, 'completion_tokens_details'):
                        details = completion.usage.completion_tokens_details
                        if details and hasattr(details, 'reasoning_tokens'):
                            usage_dict['reasoning_tokens'] = details.reasoning_tokens or 0
                    self._last_token_usage = usage_dict
                
                return message.content
                
            except Exception as e:
                last_err = e
                if attempt < self.retries - 1:
                    sleep_time = random.uniform(self.backoff_min, self.backoff_max)
                    time.sleep(sleep_time)
        
        raise RuntimeError(f"DeepSeek raw call failed after {self.retries} attempts: {last_err}")
    
    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "DeepSeek"
    
    @property
    def supports_thinking(self) -> bool:
        """DeepSeek models support complex reasoning but not explicit thinking mode."""
        return False
    
    def get_last_token_usage(self) -> dict[str, int] | None:
        """Return token usage from the last call if available."""
        return self._last_token_usage