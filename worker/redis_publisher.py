"""
Redis Pub/Sub publisher for live agent updates.

Provides a channel for streaming agent thoughts, decisions, and progress
to the SaaS frontend in real-time.
"""

import json
import os
from datetime import datetime, timezone


class RedisPublisher:
    """
    Publishes agent updates to Redis Pub/Sub channels.
    
    Channel naming convention:
    - audit:updates:{scan_id} - Live updates during audit execution
    - audit:status:{scan_id} - Status changes (started, completed, failed)
    
    Message format:
    {
        "type": "thought" | "decision" | "action" | "result" | "status" | "error",
        "scan_id": str,
        "timestamp": ISO8601,
        "iteration": int (optional),
        "data": {...}
    }
    """
    
    def __init__(self, scan_id: str, redis_url: str | None = None):
        """
        Initialize Redis publisher.
        
        Args:
            scan_id: Unique identifier for this scan/audit
            redis_url: Redis connection URL (defaults to REDIS_URL env var)
        """
        self.scan_id = scan_id
        self.redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        self._redis_client = None
        self._connected = False
        
    def _get_client(self):
        """Lazy initialization of Redis client."""
        if self._redis_client is None:
            try:
                import redis
                self._redis_client = redis.from_url(self.redis_url)
                self._connected = True
            except ImportError:
                # Redis not installed - graceful degradation
                self._connected = False
            except Exception:
                self._connected = False
        return self._redis_client
    
    @property
    def channel_updates(self) -> str:
        """Channel for live updates."""
        return f"audit:updates:{self.scan_id}"
    
    @property
    def channel_status(self) -> str:
        """Channel for status changes."""
        return f"audit:status:{self.scan_id}"
    
    def _publish(self, channel: str, message: dict) -> bool:
        """
        Publish a message to a Redis channel.
        
        Args:
            channel: Channel name
            message: Message dict to publish
            
        Returns:
            True if published successfully, False otherwise
        """
        client = self._get_client()
        if not client or not self._connected:
            return False
        
        try:
            # Add metadata
            message["scan_id"] = self.scan_id
            message["timestamp"] = datetime.now(timezone.utc).isoformat()
            
            # Serialize and publish
            result = client.publish(channel, json.dumps(message, default=str))
            # Log subscriber count for debugging
            if result == 0:
                import sys
                print(f"[Redis] Published {message.get('type')} (no subscribers)", file=sys.stderr)
            return True
        except Exception as e:
            import sys
            print(f"[Redis] Publish error: {e}", file=sys.stderr)
            return False
    
    def publish_thought(self, thought: str, iteration: int = 0, context: dict | None = None):
        """
        Publish agent's current thinking/reasoning.
        
        Args:
            thought: The agent's thought or reasoning text
            iteration: Current iteration number
            context: Optional additional context
        """
        self._publish(self.channel_updates, {
            "type": "thought",
            "iteration": iteration,
            "data": {
                "thought": thought,
                "context": context or {}
            }
        })
    
    def publish_decision(
        self,
        action: str,
        reasoning: str,
        parameters: dict,
        iteration: int = 0
    ):
        """
        Publish agent's decision.
        
        Args:
            action: The action the agent decided to take
            reasoning: Why the agent chose this action
            parameters: Action parameters
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "decision",
            "iteration": iteration,
            "data": {
                "action": action,
                "reasoning": reasoning,
                "parameters": parameters
            }
        })
    
    def publish_action_start(self, action: str, iteration: int = 0):
        """
        Publish that an action is starting.
        
        Args:
            action: The action being executed
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "action_start",
            "iteration": iteration,
            "data": {
                "action": action,
                "status": "executing"
            }
        })
    
    def publish_action_result(
        self,
        action: str,
        result: dict,
        iteration: int = 0
    ):
        """
        Publish the result of an action.
        
        Args:
            action: The action that was executed
            result: The result data
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "action_result",
            "iteration": iteration,
            "data": {
                "action": action,
                "result": result
            }
        })
    
    def publish_hypothesis(
        self,
        hypothesis_id: str,
        title: str,
        confidence: float,
        severity: str,
        iteration: int = 0
    ):
        """
        Publish a new hypothesis formation.
        
        Args:
            hypothesis_id: Unique hypothesis ID
            title: Hypothesis title/description
            confidence: Confidence score (0-1)
            severity: Severity level (critical, high, medium, low)
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "hypothesis",
            "iteration": iteration,
            "data": {
                "hypothesis_id": hypothesis_id,
                "title": title,
                "confidence": confidence,
                "severity": severity
            }
        })
    
    def publish_context_usage(
        self,
        tokens_used: int,
        tokens_limit: int,
        percentage: float,
        iteration: int = 0
    ):
        """
        Publish context window usage statistics.
        
        Args:
            tokens_used: Number of tokens used
            tokens_limit: Maximum tokens allowed
            percentage: Usage percentage
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "context_usage",
            "iteration": iteration,
            "data": {
                "tokens_used": tokens_used,
                "tokens_limit": tokens_limit,
                "percentage": percentage
            }
        })
    
    def publish_status(self, status: str, message: str = "", details: dict | None = None):
        """
        Publish a status change.
        
        Args:
            status: New status (started, running, completed, failed, aborted)
            message: Optional status message
            details: Optional additional details
        """
        self._publish(self.channel_status, {
            "type": "status",
            "data": {
                "status": status,
                "message": message,
                "details": details or {}
            }
        })
    
    def publish_error(self, error: str, error_type: str = "general", iteration: int = 0):
        """
        Publish an error.
        
        Args:
            error: Error message
            error_type: Type of error
            iteration: Current iteration number
        """
        self._publish(self.channel_updates, {
            "type": "error",
            "iteration": iteration,
            "data": {
                "error": error,
                "error_type": error_type
            }
        })
    
    def publish_progress(
        self,
        iteration: int,
        max_iterations: int,
        nodes_visited: int = 0,
        hypotheses_count: int = 0,
        graphs_loaded: int = 0
    ):
        """
        Publish overall progress update.
        
        Args:
            iteration: Current iteration
            max_iterations: Maximum iterations
            nodes_visited: Number of nodes visited
            hypotheses_count: Number of hypotheses formed
            graphs_loaded: Number of graphs loaded
        """
        # Guard against division by zero
        safe_max = max(max_iterations, 1)
        self._publish(self.channel_updates, {
            "type": "progress",
            "iteration": iteration,
            "data": {
                "iteration": iteration,
                "max_iterations": max_iterations,
                "progress_percent": round(iteration / safe_max * 100, 1),
                "nodes_visited": nodes_visited,
                "hypotheses_count": hypotheses_count,
                "graphs_loaded": graphs_loaded
            }
        })
    
    def close(self):
        """Close the Redis connection."""
        if self._redis_client:
            try:
                self._redis_client.close()
            except Exception:
                pass
            self._redis_client = None
            self._connected = False


def create_publisher(scan_id: str) -> RedisPublisher:
    """
    Factory function to create a RedisPublisher.
    
    Args:
        scan_id: Unique identifier for the scan/audit
        
    Returns:
        RedisPublisher instance
    """
    return RedisPublisher(scan_id)
