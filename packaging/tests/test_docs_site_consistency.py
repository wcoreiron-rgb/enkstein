"""The public site must behave the same on every page.

The site offers a light/dark toggle, but two of its four pages were authored
dark-only: they defined their palette under a bare ``:root``, shipped no
toggle, and hardcoded the navigation bar to near-black. A visitor who chose
light on the home page and clicked Changelog got a dark page, and once the
palette was made theme-aware the hardcoded navigation stayed dark with
unreadable links over it.

These checks pin the contract rather than any particular colour: every page
carries the toggle, resolves both themes, and derives chrome from theme
variables instead of literal colours.
"""

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
PAGES = ("index.html", "docs.html", "changelog.html", "owasp-agentic.html")

#: The shared preference key. A page using a different key would appear to work
#: in isolation while silently forgetting the choice made on another page.
THEME_KEY = "enkstein-theme"


@pytest.fixture(scope="module")
def sources() -> dict[str, str]:
    return {name: (DOCS / name).read_text(encoding="utf-8") for name in PAGES}


@pytest.mark.parametrize("page", PAGES)
def test_every_page_defines_both_themes(sources: dict[str, str], page: str) -> None:
    source = sources[page]
    assert 'html[data-theme="dark"]' in source, f"{page} has no dark palette"
    assert 'html[data-theme="light"]' in source, f"{page} has no light palette"


@pytest.mark.parametrize("page", PAGES)
def test_every_page_offers_the_toggle(sources: dict[str, str], page: str) -> None:
    assert 'id="theme-toggle"' in sources[page], f"{page} cannot switch theme"


@pytest.mark.parametrize("page", PAGES)
def test_every_page_shares_one_preference_key(sources: dict[str, str], page: str) -> None:
    source = sources[page]
    assert THEME_KEY in source, f"{page} does not read the shared theme preference"


@pytest.mark.parametrize("page", PAGES)
def test_navigation_is_not_pinned_to_a_single_theme(
    sources: dict[str, str], page: str
) -> None:
    """The sticky navigation must follow the palette.

    A literal dark background here survives a theme switch and leaves dark link
    text on a dark bar, which is how this regression presented.

    The bar is found by its behaviour -- a blurred, stuck-to-the-top surface --
    rather than by one selector name, since the pages call it ``nav`` and
    ``.topbar``.
    """
    source = sources[page]
    blocks = [
        block
        for block in re.findall(r"\{[^{}]*\}", source)
        if "backdrop-filter" in block and "position:" in block
    ]
    assert blocks, f"{page} has no sticky navigation surface to check"
    for block in blocks:
        assert "rgba(10,10,10" not in block, f"{page} pins its navigation to dark"
        assert "var(--bg)" in block, f"{page} navigation ignores the theme background"


class _LocalReferenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        wanted = "href" if tag in {"a", "link"} else "src" if tag in {"img", "script"} else ""
        if not wanted:
            return
        for key, value in attrs:
            if key == wanted and value:
                self.references.append(value)


@pytest.mark.parametrize("page", PAGES)
def test_local_html_references_exist(sources: dict[str, str], page: str) -> None:
    """A polished link is still broken if its target never shipped."""
    parser = _LocalReferenceParser()
    parser.feed(sources[page])
    missing: list[str] = []
    for reference in parser.references:
        parsed = urlsplit(reference)
        if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
            continue
        target = (DOCS / page).parent / unquote(parsed.path)
        if not target.exists():
            missing.append(reference)
    assert missing == [], f"{page} has missing local references: {missing}"


def test_local_markdown_links_exist() -> None:
    """README and documentation links resolve from the file that owns them."""
    documents = [ROOT / "README.md", *sorted(DOCS.glob("*.md"))]
    missing: list[str] = []
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for document in documents:
        source = document.read_text(encoding="utf-8")
        for raw in link_pattern.findall(source):
            reference = raw.split("#", 1)[0].strip().strip("<>")
            if (
                not reference
                or "://" in reference
                or reference.startswith(("/", "mailto:"))
            ):
                continue
            target = document.parent / unquote(reference)
            if not target.exists():
                missing.append(f"{document.relative_to(ROOT)} -> {reference}")
    assert missing == [], "Missing local Markdown links:\n" + "\n".join(missing)
