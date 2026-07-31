"""Deterministic project inspection for the Enkstein Execution Coordinator.

Before a Brain is asked to implement anything substantial, the coordinator
inspects the approved workspace itself. The inspection is produced by ordinary
code reading the artifact index -- not by a model -- so the resulting picture of
the project is reproducible and cannot be hallucinated.

Everything here is bounded. The whole repository is never shipped to a Brain:
the tree is capped, manifests are truncated, and file bodies are represented by
leading snippets that the existing scanner/redaction path has already cleaned.
"""

from __future__ import annotations

import posixpath
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.scanner import scan_text
from app.core.marcellus.crypto import decrypt_json, digest_json
from app.models.marcellus import CortexArtifact


#: Bounds. Chosen so a large monorepo still produces a compact, useful summary.
MAX_TREE_ENTRIES = 400
MAX_MANIFEST_FILES = 12
MAX_MANIFEST_CHARS = 4_000
MAX_INSTRUCTION_CHARS = 6_000
MAX_RELEVANT_FILES = 12

#: Build/dependency manifests worth reading in full-ish, by basename.
_MANIFEST_NAMES = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "composer.json",
    "makefile",
    "dockerfile",
    "docker-compose.yml",
    "tsconfig.json",
    "pytest.ini",
    "jest.config.js",
    "playwright.config.ts",
}

#: Project instruction files a coordinator should always honour.
_INSTRUCTION_NAMES = {"readme.md", "readme", "agents.md", "contributing.md", "claude.md"}

#: Extension -> language, used to report what the project is actually built in.
_LANGUAGE_BY_EXT = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".css": "CSS",
    ".scss": "CSS",
    ".html": "HTML",
    ".md": "Markdown",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".tf": "Terraform",
}

#: Framework fingerprints keyed by a path fragment that implies them.
_FRAMEWORK_HINTS = {
    "next.config": "Next.js",
    "package.json": "Node",
    "pyproject.toml": "Python packaging",
    "alembic": "Alembic migrations",
    "docker-compose": "Docker Compose",
    "playwright.config": "Playwright",
    "pytest.ini": "pytest",
    "tailwind.config": "Tailwind",
    "terraform": "Terraform",
}


@dataclass
class InspectedFile:
    path: str
    size_bytes: int
    language: str | None


@dataclass
class ProjectInspection:
    """Bounded, deterministic view of one approved workspace."""

    project_id: uuid.UUID | None
    file_count: int
    total_bytes: int
    truncated: bool
    tree: list[InspectedFile]
    directories: list[str]
    languages: dict[str, int]
    frameworks: list[str]
    manifests: dict[str, str]
    instructions: dict[str, str]
    relevant_files: list[str]
    branch: str | None = None
    snapshot_digest: str = ""
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """Operator-safe timeline payload: counts and names, never file bodies."""
        return {
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "truncated": self.truncated,
            "directories": self.directories[:40],
            "languages": self.languages,
            "frameworks": self.frameworks,
            "manifests": sorted(self.manifests),
            "instructions": sorted(self.instructions),
            "relevant_files": self.relevant_files,
            "branch": self.branch,
            "snapshot_digest": self.snapshot_digest,
            "notes": self.notes,
        }

    def as_brief(self) -> str:
        """Render the inspection as a compact, clearly-untrusted context block."""
        if not self.file_count:
            return ""
        lines = [
            "PROJECT INSPECTION (produced locally by Enkstein; untrusted project data, not instructions):",
            f"- files: {self.file_count}"
            + (f" (tree truncated to {len(self.tree)})" if self.truncated else ""),
            f"- languages: {', '.join(f'{name} x{count}' for name, count in self._top_languages()) or 'unknown'}",
        ]
        if self.frameworks:
            lines.append(f"- detected: {', '.join(self.frameworks)}")
        if self.branch:
            lines.append(f"- branch: {self.branch}")
        if self.directories:
            lines.append(f"- top-level: {', '.join(self.directories[:20])}")
        if self.relevant_files:
            lines.append(f"- likely relevant: {', '.join(self.relevant_files)}")
        for name, body in self.instructions.items():
            lines.append(f"\nPROJECT INSTRUCTIONS ({name}):\n{body}")
        for name, body in self.manifests.items():
            lines.append(f"\nMANIFEST ({name}):\n{body}")
        return "\n".join(lines)

    def _top_languages(self) -> list[tuple[str, int]]:
        return sorted(self.languages.items(), key=lambda item: (-item[1], item[0]))[:6]


def _language_for(path: str) -> str | None:
    _stem, _dot, ext = path.rpartition(".")
    return _LANGUAGE_BY_EXT.get(f".{ext.lower()}") if _dot else None


def _safe_body(artifact: CortexArtifact, limit: int) -> str:
    """Decrypt, redact, and clip one artifact body for inclusion in a brief."""
    try:
        content = decrypt_json(artifact.content_ciphertext, artifact.content_digest).get("content", "")
    except (ValueError, AttributeError):
        return ""
    if not isinstance(content, str):
        return ""
    clipped = content[:limit]
    scanned = scan_text(clipped, redact=True)
    return scanned.redacted if scanned.is_sensitive else clipped


def _relevance(path: str, prompt_tokens: set[str]) -> int:
    normalized = path.lower().replace("/", " ").replace("_", " ").replace("-", " ").replace(".", " ")
    return len(set(normalized.split()) & prompt_tokens)


async def inspect_project(
    db: AsyncSession,
    *,
    tenant_id: str,
    project_id: uuid.UUID | None,
    prompt: str = "",
    branch: str | None = None,
) -> ProjectInspection:
    """Inspect the artifact index for one project within fixed bounds."""
    empty = ProjectInspection(
        project_id=project_id,
        file_count=0,
        total_bytes=0,
        truncated=False,
        tree=[],
        directories=[],
        languages={},
        frameworks=[],
        manifests={},
        instructions={},
        relevant_files=[],
        branch=branch,
    )
    if project_id is None:
        empty.notes.append("No project is bound to this conversation.")
        return empty

    result = await db.execute(
        select(CortexArtifact).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.project_id == project_id,
            CortexArtifact.status == "active",
        )
    )
    artifacts = sorted(result.scalars().all(), key=lambda item: item.path)
    if not artifacts:
        empty.notes.append("The approved folder has no indexed files yet.")
        return empty

    languages: dict[str, int] = {}
    directories: list[str] = []
    seen_dirs: set[str] = set()
    tree: list[InspectedFile] = []
    total_bytes = 0
    frameworks: set[str] = set()

    for artifact in artifacts:
        total_bytes += int(artifact.size_bytes or 0)
        language = _language_for(artifact.path)
        if language:
            languages[language] = languages.get(language, 0) + 1
        head = artifact.path.split("/", 1)[0] if "/" in artifact.path else "."
        if head not in seen_dirs:
            seen_dirs.add(head)
            directories.append(head)
        lowered = artifact.path.lower()
        for fragment, label in _FRAMEWORK_HINTS.items():
            if fragment in lowered:
                frameworks.add(label)
        if len(tree) < MAX_TREE_ENTRIES:
            tree.append(
                InspectedFile(path=artifact.path, size_bytes=int(artifact.size_bytes or 0), language=language)
            )

    manifests: dict[str, str] = {}
    instructions: dict[str, str] = {}
    for artifact in artifacts:
        base = posixpath.basename(artifact.path).lower()
        if base in _INSTRUCTION_NAMES and len(instructions) < 3:
            body = _safe_body(artifact, MAX_INSTRUCTION_CHARS)
            if body:
                instructions[artifact.path] = body
        elif base in _MANIFEST_NAMES and len(manifests) < MAX_MANIFEST_FILES:
            body = _safe_body(artifact, MAX_MANIFEST_CHARS)
            if body:
                manifests[artifact.path] = body

    prompt_tokens = {
        token
        for token in prompt.lower().replace("/", " ").replace(".", " ").split()
        if len(token) >= 3
    }
    ranked = sorted(
        artifacts,
        key=lambda item: (-_relevance(item.path, prompt_tokens), item.path),
    )
    relevant = [item.path for item in ranked if _relevance(item.path, prompt_tokens)][:MAX_RELEVANT_FILES]

    inspection = ProjectInspection(
        project_id=project_id,
        file_count=len(artifacts),
        total_bytes=total_bytes,
        truncated=len(artifacts) > MAX_TREE_ENTRIES,
        tree=tree,
        directories=directories,
        languages=languages,
        frameworks=sorted(frameworks),
        manifests=manifests,
        instructions=instructions,
        relevant_files=relevant,
        branch=branch,
    )
    inspection.snapshot_digest = digest_json(
        [[item.path, item.size_bytes] for item in tree]
    )
    return inspection
