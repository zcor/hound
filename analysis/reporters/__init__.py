"""
Reporter modules for outputting security findings to various destinations.
"""

from abc import ABC, abstractmethod
from typing import Any


class Reporter(ABC):
    """Base class for all reporters."""
    
    @abstractmethod
    def report(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Report the findings to the destination.
        
        Args:
            findings: List of finding dictionaries from report_generator._get_confirmed_findings()
                     Each finding has keys: id, title, severity, type, description, 
                     confidence, affected, etc.
        
        Returns:
            Dictionary with status and any relevant metadata about the reporting action
        """
        pass
