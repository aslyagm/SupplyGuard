"""Slopsquatting check: ask an LLM for package suggestions, verify they exist on PyPI.

Uses Groq's OpenAI-compatible chat API. The API key is read from the
GROQ_API_KEY environment variable and is never stored in the repo.
Nothing is ever registered on PyPI; we only *read* the public JSON API.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass, field

from . import pypi
from .parser import normalize

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = os.environ.get("SUPPLYGUARD_MODEL", "llama-3.3-70b-versatile")

PROMPT = (
    "I am writing a Python program. Task: {task}\n"
    "List the PyPI packages I should pip install for this task. "
    "Reply ONLY with a JSON array of package names, no explanation."
)


@dataclass
class SlopResult:
    task: str
    model: str
    suggested: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)       # not on PyPI -> hallucinated
    suspicious: list[str] = field(default_factory=list)    # exists but very new / few releases


def ask_llm(task: str, model: str = DEFAULT_MODEL, api_key: str | None = None) -> list[str]:
    api_key = api_key or os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("Set the GROQ_API_KEY environment variable first.")
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": PROMPT.format(task=task)}],
        "temperature": 0.7,
    }).encode()
    req = urllib.request.Request(
        GROQ_URL, data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                 "User-Agent": pypi.USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        content = json.load(resp)["choices"][0]["message"]["content"]
    return extract_names(content)


def extract_names(text: str) -> list[str]:
    """Pull a JSON array out of the model's reply, tolerating extra text."""
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end <= start:
        return []
    try:
        items = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    if not isinstance(items, list):
        return []
    names = []
    for item in items:
        if isinstance(item, str):
            # drop version pins / extras: "requests>=2" -> "requests"
            n = re.split(r"[\s<>=!~\[;]", item.strip(), maxsplit=1)[0]
            if n:
                names.append(normalize(n))
    return list(dict.fromkeys(names))


def check_task(task: str, model: str = DEFAULT_MODEL) -> SlopResult:
    res = SlopResult(task=task, model=model, suggested=ask_llm(task, model))
    for name in res.suggested:
        info = pypi.fetch(name)
        if info is None:
            continue  # network error, skip
        if not info.exists:
            res.missing.append(name)
        else:
            age = info.age_days()
            if (age is not None and age < 90) or info.release_count <= 1:
                res.suspicious.append(name)
    return res
