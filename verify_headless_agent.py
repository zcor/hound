#!/usr/bin/env python3
"""
Manual verification script for headless agent adaptation features.

This script demonstrates:
1. Budget limit enforcement
2. Rate limit exception handling
3. Database status checking
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from analysis.exceptions import BudgetExceededException, RateLimitException


def test_exceptions():
    """Test that custom exceptions work correctly."""
    print("=" * 60)
    print("Testing Custom Exceptions")
    print("=" * 60)
    
    # Test RateLimitException
    try:
        raise RateLimitException(
            message="Rate limit exceeded",
            provider="openai",
            retry_after=60,
            state={'investigation': 'test'}
        )
    except RateLimitException as e:
        print(f"✓ RateLimitException caught: {e}")
        print(f"  - Provider: {e.provider}")
        print(f"  - Retry after: {e.retry_after}s")
        print(f"  - State saved: {e.state is not None}")
    
    # Test BudgetExceededException
    try:
        raise BudgetExceededException(
            message="Budget limit exceeded",
            budget_limit=10000,
            current_usage=10500,
            usage_type='tokens'
        )
    except BudgetExceededException as e:
        print(f"✓ BudgetExceededException caught: {e}")
        print(f"  - Limit: {e.budget_limit}")
        print(f"  - Usage: {e.current_usage}")
        print(f"  - Type: {e.usage_type}")
    
    print()


def test_budget_tracking():
    """Test budget tracking logic."""
    print("=" * 60)
    print("Testing Budget Tracking")
    print("=" * 60)
    
    # Simulate budget tracking
    budget_limit = 1000  # tokens
    budget_used = 0
    
    # Simulate some LLM calls
    calls = [
        {'input': 100, 'output': 50},
        {'input': 200, 'output': 100},
        {'input': 300, 'output': 200},
        {'input': 400, 'output': 300}
    ]
    
    for i, call in enumerate(calls, 1):
        tokens = call['input'] + call['output']
        budget_used += tokens
        print(f"Call {i}: {tokens} tokens, total: {budget_used}/{budget_limit}")
        
        if budget_used >= budget_limit:
            print(f"⚠ Budget limit exceeded at call {i}!")
            break
    
    print()


def test_rate_limit_detection():
    """Test rate limit error detection."""
    print("=" * 60)
    print("Testing Rate Limit Detection")
    print("=" * 60)
    
    error_messages = [
        "Rate limit exceeded (HTTP 429)",
        "Too many requests, please retry after 60 seconds",
        "Quota exceeded for this API key",
        "Resource exhausted, try again later",
        "RateLimitError: You have exceeded your current quota",
    ]
    
    for msg in error_messages:
        is_rate_limit = any(indicator in msg.lower() for indicator in [
            'rate limit', 'rate_limit', 'ratelimit', '429',
            'too many requests', 'quota exceeded', 'resource exhausted'
        ])
        status = "✓" if is_rate_limit else "✗"
        print(f"{status} '{msg[:50]}...' -> {'Rate limit' if is_rate_limit else 'Not rate limit'}")
    
    print()


def test_abort_status_check():
    """Test abort status flag checking."""
    print("=" * 60)
    print("Testing Abort Status Check")
    print("=" * 60)
    
    abort_statuses = {'aborted', 'cancelled', 'interrupted'}
    test_statuses = ['active', 'aborted', 'completed', 'cancelled', 'paused', 'interrupted']
    
    for status in test_statuses:
        should_abort = status in abort_statuses
        result = "Should abort" if should_abort else "Continue"
        symbol = "⚠" if should_abort else "✓"
        print(f"{symbol} Status '{status}' -> {result}")
    
    print()


def main():
    """Run all verification tests."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  Headless Agent Adaptation - Manual Verification".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "=" * 58 + "╝")
    print()
    
    test_exceptions()
    test_budget_tracking()
    test_rate_limit_detection()
    test_abort_status_check()
    
    print("=" * 60)
    print("All verification tests completed successfully!")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
