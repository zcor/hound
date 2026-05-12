"""Regression tests: providers must accept ``reasoning_effort`` (and other
forward-compatible per-call kwargs) without raising TypeError.

The unified client always passes ``reasoning_effort=`` to ``provider.parse``;
providers that do not consume the hint must silently ignore it. Without this,
each non-OpenAI call wasted three retries inside the provider before falling
back, producing the "Failed after 3 attempts" log spam observed during the
end-to-end Anthropic audit run.
"""
from __future__ import annotations

import inspect
import unittest

from llm.anthropic_provider import AnthropicProvider
from llm.deepseek_provider import DeepSeekProvider
from llm.gemini_provider import GeminiProvider
from llm.mock_provider import MockProvider
from llm.xai_provider import XAIProvider


class TestProviderParseAcceptsReasoningEffort(unittest.TestCase):
    """Every provider's ``parse`` must accept ``reasoning_effort``."""

    PROVIDER_CLASSES = (
        AnthropicProvider,
        DeepSeekProvider,
        GeminiProvider,
        MockProvider,
        XAIProvider,
    )

    def test_parse_accepts_reasoning_effort_kwarg(self):
        for cls in self.PROVIDER_CLASSES:
            with self.subTest(provider=cls.__name__):
                sig = inspect.signature(cls.parse)
                # Either an explicit ``reasoning_effort`` parameter or a
                # ``**kwargs``-style catch-all is acceptable.
                accepts_kwarg = any(
                    p.name == "reasoning_effort"
                    or p.kind is inspect.Parameter.VAR_KEYWORD
                    for p in sig.parameters.values()
                )
                self.assertTrue(
                    accepts_kwarg,
                    f"{cls.__name__}.parse must accept reasoning_effort "
                    f"(found signature: {sig})",
                )

    def test_mock_provider_ignores_reasoning_effort_at_runtime(self):
        # MockProvider is the only one we can call without an SDK; assert that
        # passing the hint does not raise TypeError end-to-end.
        from pydantic import BaseModel

        class _Schema(BaseModel):
            ok: bool = True

        provider = MockProvider({}, model_name="mock")
        # Should not raise.
        provider.parse(system="s", user="u", schema=_Schema, reasoning_effort="high")


if __name__ == "__main__":
    unittest.main()
