"""OpenAI-compatible chat providers used by the public benchmarks.

Only public corpora (CVEfixes, OWASP Benchmark) are sent through these clients; the
product pipeline uses its own authorized provider runtime.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class Provider:
    name: str
    base_url: str
    key_variable: str
    model: str
    input_microusd_per_million: int
    output_microusd_per_million: int
    parameters: dict[str, Any] = field(default_factory=dict)
    currency: str = "USD"


PROVIDERS: Final[dict[str, Provider]] = {
    "deepseek": Provider(
        "DeepSeek Flash",
        "https://api.deepseek.com",
        "DEEPSEEK_API_KEY",
        "deepseek-flash",
        150_000,
        600_000,
        {"temperature": 0, "thinking": {"type": "disabled"}, "max_tokens": 256},
    ),
    "luna": Provider(
        "GPT-5.6 Luna",
        "https://api.openai.com/v1",
        "OPENAI_API_KEY",
        "gpt-5.6-luna",
        200_000,
        1_200_000,
        {"reasoning_effort": "low", "max_completion_tokens": 4096},
    ),
    "glm": Provider(
        "GLM-5.3",
        "https://api.z.ai/api/paas/v4",
        "ZAI_API_KEY",
        "glm-5.3",
        1_400_000,
        4_400_000,
        {"reasoning_effort": "low", "max_tokens": 4096},
    ),
}

# Open-weight models usually deployed locally, served by neuraldeep.ru over the same API.
# Prices are in rubles (micro-RUB per million tokens); "-noreason" variants answer directly.
_NEURALDEEP: Final = "https://api.neuraldeep.ru/v1"
for _key, _name, _model, _input, _output in (
    ("qwen3.8-27b", "Qwen 3.8 27B", "qwen3.8-27b-noreason", 24_480_000, 122_400_000),
    ("qwen3.6-35b", "Qwen 3.6 35B-A3B", "qwen3.6-35b-a3b-noreason", 7_140_000, 40_800_000),
    ("qwen3.6-fp8", "Qwen 3.6 FP8", "qwen3.6-fp8-noreason", 7_140_000, 40_800_000),
    ("gpt-oss-120b", "gpt-oss-120b", "gpt-oss-120b", 5_100_000, 20_400_000),
    ("gpt-oss-20b", "gpt-oss-20b", "gpt-oss-20b", 3_060_000, 14_280_000),
    ("gemma-4-31b", "Gemma 4 31B", "gemma-4-31b-noreason", 11_000_000, 37_400_000),
):
    PROVIDERS[_key] = Provider(
        _name,
        _NEURALDEEP,
        "NEURALDEEP_API_KEY",
        _model,
        _input,
        _output,
        {"temperature": 0, "max_tokens": 1024},
        currency="RUB",
    )


def load_dotenv() -> None:
    dotenv = Path.cwd() / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.strip().partition("=")
            if separator and name and not name.startswith("#"):
                os.environ.setdefault(name, value.strip().strip("'\""))


def _last_json_object(text: str) -> dict[str, Any]:
    """Return the last parseable JSON object in ``text`` (models sometimes add prose)."""

    decoder = json.JSONDecoder()
    found: dict[str, Any] | None = None
    index = text.find("{")
    while index != -1:
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index = text.find("{", index + 1)
            continue
        if isinstance(value, dict):
            found = value
        index = text.find("{", end)
    if found is None:
        raise ValueError("no JSON object in the model answer")
    return found


def complete_json(
    provider: Provider, prompt: str, *, attempts: int = 3
) -> tuple[dict[str, Any], int]:
    """Send one JSON-mode prompt; return the parsed object and its cost in micro-USD."""

    key = os.environ.get(provider.key_variable)
    if not key:
        raise ValueError(f"{provider.key_variable} is not set")
    payload = {
        "model": provider.model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_object"},
        **provider.parameters,
    }
    request = urllib.request.Request(
        provider.base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                frame = json.loads(response.read().decode("utf-8"))
            usage = frame.get("usage") or {}
            cost = (
                int(usage.get("prompt_tokens", 0)) * provider.input_microusd_per_million
                + int(usage.get("completion_tokens", 0)) * provider.output_microusd_per_million
            ) // 1_000_000
            content = frame["choices"][0]["message"]["content"] or ""
            return _last_json_object(content), cost
        except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError) as error:
            last_error = error
            time.sleep(2 * (attempt + 1))
    raise ValueError(f"{provider.name} request failed: {last_error}")
