"""Provider-agnostic LLM wrapper.

Default is an offline MockLLM so the pipeline runs with no API key tonight.
The point AEGIS proves is upstream of the model anyway: whatever LLM you plug
in only ever receives tokenized context, so a prompt-log leak exposes tokens.
"""
from __future__ import annotations


class MockLLM:
    name = "mock"

    def complete(self, prompt: str) -> str:
        ctx = prompt.split("CONTEXT:", 1)[-1].strip()
        return (
            "[MOCK-LLM] Answer grounded strictly in the retrieved records below. "
            "Every identifier here is a token, the model never received raw PII:\n"
            + ctx[:800]
        )


class OpenAILLM:  # pragma: no cover - requires key + package
    name = "openai"

    def __init__(self, model: str = "gpt-4o-mini"):
        from openai import OpenAI

        self.client = OpenAI()
        self.model = model

    def complete(self, prompt: str) -> str:
        r = self.client.chat.completions.create(
            model=self.model, messages=[{"role": "user", "content": prompt}]
        )
        return r.choices[0].message.content


class AnthropicLLM:  # pragma: no cover - requires key + package
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, prompt: str) -> str:
        r = self.client.messages.create(
            model=self.model, max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text")


def get_llm(provider: str, model: str = ""):
    provider = (provider or "mock").lower()
    if provider == "openai":
        return OpenAILLM(model or "gpt-4o-mini")
    if provider == "anthropic":
        return AnthropicLLM(model or "claude-sonnet-5")
    return MockLLM()
