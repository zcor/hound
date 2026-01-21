"""Token usage tracking for LLM providers."""
import json
import os
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock

# Context variables for tracking request context
_current_project_id: ContextVar[int | None] = ContextVar('current_project_id', default=None)
_current_session_id: ContextVar[str | None] = ContextVar('current_session_id', default=None)
_current_tenant_id: ContextVar[int | None] = ContextVar('current_tenant_id', default=None)
_current_endpoint: ContextVar[str | None] = ContextVar('current_endpoint', default=None)


@dataclass
class TokenUsage:
    """Token usage for a single LLM call."""
    timestamp: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    profile: str | None = None  # e.g., "agent", "graph", "guidance"
    
    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp,
            'provider': self.provider,
            'model': self.model,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'total_tokens': self.total_tokens,
            'profile': self.profile
        }


class TokenTracker:
    """Tracks token usage across all LLM calls."""
    
    def __init__(self):
        self.usage_history: list[TokenUsage] = []
        self.usage_by_model: dict[str, dict[str, int]] = {}
        self._lock = Lock()
        self._output_file: Path | None = None
    
    def set_output_file(self, file_path: Path):
        """Set the output file for real-time updates."""
        self._output_file = file_path
        # Initialize the file with empty data
        self._save_to_file()
    
    def track_usage(self, 
                   provider: str,
                   model: str, 
                   input_tokens: int, 
                   output_tokens: int,
                   profile: str | None = None):
        """Track token usage for a single LLM call."""
        with self._lock:
            usage = TokenUsage(
                timestamp=datetime.now().isoformat(),
                provider=provider,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                profile=profile
            )
            self.usage_history.append(usage)
            
            # Update model aggregates
            model_key = f"{provider}:{model}"
            if model_key not in self.usage_by_model:
                self.usage_by_model[model_key] = {
                    'input_tokens': 0,
                    'output_tokens': 0,
                    'total_tokens': 0,
                    'call_count': 0
                }
            
            self.usage_by_model[model_key]['input_tokens'] += input_tokens
            self.usage_by_model[model_key]['output_tokens'] += output_tokens
            self.usage_by_model[model_key]['total_tokens'] += input_tokens + output_tokens
            self.usage_by_model[model_key]['call_count'] += 1
            
            # Save to file if configured
            if self._output_file:
                self._save_to_file()
            
            # Save to database if DATABASE_URL is set
            self._save_to_database(provider, model, input_tokens, output_tokens, profile)
    
    def _save_to_database(self, provider: str, model: str, input_tokens: int, output_tokens: int, profile: str | None):
        """Save token usage to database (non-blocking)."""
        database_url = os.environ.get("DATABASE_URL")
        if not database_url:
            return
        
        try:
            # Import here to avoid circular dependency
            from database.models import TokenUsageLog, calculate_cost, create_db_engine, create_db_session
            
            # Get context variables
            project_id = _current_project_id.get()
            session_id = _current_session_id.get()
            tenant_id = _current_tenant_id.get()
            endpoint = _current_endpoint.get()
            
            # Calculate cost
            cost = calculate_cost(model, input_tokens, output_tokens)
            
            # Create log entry
            engine = create_db_engine(database_url)
            db = create_db_session(engine)
            
            try:
                log_entry = TokenUsageLog(
                    project_id=project_id,
                    session_id=session_id,
                    tenant_id=tenant_id,
                    provider=provider,
                    model=model,
                    profile=profile,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    total_tokens=input_tokens + output_tokens,
                    cost_usd=cost,
                    endpoint=endpoint,
                )
                db.add(log_entry)
                db.commit()
            finally:
                db.close()
                engine.dispose()
        except Exception as e:
            # Don't fail on database errors - just log to stderr
            import sys
            print(f"Warning: Failed to save token usage to database: {e}", file=sys.stderr)
    
    def _save_to_file(self):
        """Save current state to file (called within lock)."""
        if not self._output_file:
            return
        
        data = self.get_summary()
        with open(self._output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_summary(self) -> dict:
        """Get summary of token usage."""
        with self._lock:
            return {
                'total_usage': {
                    'input_tokens': sum(u.input_tokens for u in self.usage_history),
                    'output_tokens': sum(u.output_tokens for u in self.usage_history),
                    'total_tokens': sum(u.total_tokens for u in self.usage_history),
                    'call_count': len(self.usage_history)
                },
                'by_model': dict(self.usage_by_model),
                'history': [u.to_dict() for u in self.usage_history]
            }

    def get_last_usage(self) -> dict | None:
        """Return the most recent usage entry as a dict, or None if empty."""
        with self._lock:
            if not self.usage_history:
                return None
            return self.usage_history[-1].to_dict()
    
    def reset(self):
        """Reset all tracking data."""
        with self._lock:
            self.usage_history.clear()
            self.usage_by_model.clear()
            if self._output_file:
                self._save_to_file()


# Global token tracker instance
_token_tracker = TokenTracker()


def get_token_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _token_tracker


def set_token_context(project_id: int | None = None, session_id: str | None = None, 
                     tenant_id: int | None = None, endpoint: str | None = None):
    """
    Set the context for token tracking.
    
    This should be called at the start of API requests to associate
    token usage with specific projects, sessions, etc.
    """
    if project_id is not None:
        _current_project_id.set(project_id)
    if session_id is not None:
        _current_session_id.set(session_id)
    if tenant_id is not None:
        _current_tenant_id.set(tenant_id)
    if endpoint is not None:
        _current_endpoint.set(endpoint)


def clear_token_context():
    """Clear the token tracking context."""
    _current_project_id.set(None)
    _current_session_id.set(None)
    _current_tenant_id.set(None)
    _current_endpoint.set(None)
