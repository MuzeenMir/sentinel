"""Strict prompt-template renderer.

Templates live as ``prompts/<name>.md`` next to this module and use a
``{{variable}}`` placeholder syntax (double-brace so JSON/code examples in a
template are unaffected). Missing variables and unknown templates raise rather
than silently producing a half-rendered prompt.
"""

from __future__ import annotations

import re
from pathlib import Path

_PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
_PLACEHOLDER = re.compile(r"{{\s*(\w+)\s*}}")


class PromptRenderError(Exception):
    """Raised on unknown template or missing variable."""


def render(name: str, **variables: object) -> str:
    path = _PROMPT_DIR / f"{name}.md"
    if not path.is_file():
        raise PromptRenderError(f"unknown prompt template: {name}")
    text = path.read_text(encoding="utf-8")

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in variables:
            raise PromptRenderError(f"missing variable '{key}' for template '{name}'")
        return str(variables[key])

    return _PLACEHOLDER.sub(_replace, text)
