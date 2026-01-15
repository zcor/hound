"""
Custom exceptions for analysis module.

This module defines exceptions that can occur during security analysis operations.
"""


class RateLimitException(Exception):
    """
    Exception raised when an LLM provider rate limit is hit.
    
    This exception indicates that the agent should pause execution and
    optionally save state for later resumption when rate limits reset.
    
    Attributes:
        message: Description of the rate limit error
        provider: LLM provider name (e.g., 'openai', 'anthropic')
        retry_after: Optional seconds to wait before retrying
        state: Optional serialized state for resumption
    """
    
    def __init__(
        self,
        message: str,
        provider: str | None = None,
        retry_after: int | None = None,
        state: dict | None = None
    ):
        """
        Initialize RateLimitException.
        
        Args:
            message: Description of the rate limit error
            provider: LLM provider name
            retry_after: Seconds to wait before retrying
            state: Serialized state for resumption
        """
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.retry_after = retry_after
        self.state = state
    
    def __str__(self) -> str:
        """Return a string representation of the exception."""
        parts = [self.message]
        if self.provider:
            parts.append(f"provider={self.provider}")
        if self.retry_after:
            parts.append(f"retry_after={self.retry_after}s")
        return f"RateLimitException({', '.join(parts)})"


class BudgetExceededException(Exception):
    """
    Exception raised when the agent's budget limit is exceeded.
    
    This exception indicates that the agent should stop execution because
    it has consumed its allocated budget (tokens or cost).
    
    Attributes:
        message: Description of the budget exceeded error
        budget_limit: The configured budget limit
        current_usage: The current usage that exceeded the limit
        usage_type: Type of usage ('tokens' or 'cost')
    """
    
    def __init__(
        self,
        message: str,
        budget_limit: float | None = None,
        current_usage: float | None = None,
        usage_type: str = 'tokens'
    ):
        """
        Initialize BudgetExceededException.
        
        Args:
            message: Description of the budget exceeded error
            budget_limit: The configured budget limit
            current_usage: The current usage that exceeded the limit
            usage_type: Type of usage ('tokens' or 'cost')
        """
        super().__init__(message)
        self.message = message
        self.budget_limit = budget_limit
        self.current_usage = current_usage
        self.usage_type = usage_type
    
    def __str__(self) -> str:
        """Return a string representation of the exception."""
        if self.budget_limit and self.current_usage:
            return f"BudgetExceededException({self.message}, limit={self.budget_limit}, usage={self.current_usage}, type={self.usage_type})"
        return f"BudgetExceededException({self.message})"
