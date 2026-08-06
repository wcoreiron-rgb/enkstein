"""Keep current operational documentation aligned with the FastAPI schema.

Historical changelog entries and scaffolding examples are deliberately outside
this contract. Everything presented as a current method/path pair in the README
or operator documentation must exist in the generated OpenAPI document.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from main import app


ROOT = Path(__file__).resolve().parents[2]
CURRENT_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "docs.html",
    ROOT / "docs" / "marcellus-architecture.md",
    ROOT / "docs" / "production-deployment.md",
    ROOT / "docs" / "runtime-reference.md",
)
METHOD_PATH = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE)\s+(/api/v1/[A-Za-z0-9_{}./:-]+)",
    re.IGNORECASE,
)


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        # Preserve a separator where tags split the method and path into spans.
        return " ".join(self.parts)


def _text(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    if path.suffix != ".html":
        return source
    parser = _TextParser()
    parser.feed(source)
    return parser.text()


def _normalized(path: str) -> str:
    path = re.sub(r"\{[^}]+\}", "{}", path).rstrip("/.,;:")
    return path


def test_current_documented_method_paths_exist_in_openapi() -> None:
    openapi = app.openapi()
    operations = {
        (method.upper(), _normalized(path))
        for path, methods in openapi["paths"].items()
        for method in methods
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    missing: list[str] = []
    for document in CURRENT_DOCS:
        for match in METHOD_PATH.finditer(_text(document)):
            operation = (match.group(1).upper(), _normalized(match.group(2)))
            # These are explicitly scaffolding placeholders in the extension
            # guide rather than claims about the running API.
            if "newclaw" in operation[1] or operation[1] == "/api/v1/{}":
                continue
            if operation not in operations:
                missing.append(
                    f"{document.relative_to(ROOT)}: {operation[0]} {operation[1]}"
                )
    assert missing == [], "Documented API operations missing from OpenAPI:\n" + "\n".join(missing)
