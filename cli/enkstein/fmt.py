"""
Enkstein CLI — Output formatters
Clean, consistent terminal output using ANSI colours and rich tables.
"""
import json
from typing import Any

# ANSI colour codes
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_CYAN   = "\033[36m"
C_GREEN  = "\033[32m"
C_YELLOW = "\033[33m"
C_RED    = "\033[31m"
C_ORANGE = "\033[38;5;208m"
C_GRAY   = "\033[90m"
C_WHITE  = "\033[97m"


def _risk_color(level: str) -> str:
    return {
        "critical": C_RED,
        "high":     C_ORANGE,
        "medium":   C_YELLOW,
        "low":      C_GREEN,
    }.get(level, C_GRAY)


def _status_color(status: str) -> str:
    return {
        "completed": C_GREEN,
        "failed":    C_RED,
        "running":   C_CYAN,
        "active":    C_GREEN,
        "approved":  C_GREEN,
        "healthy":   C_GREEN,
        "blocked":   C_RED,
        "pending":   C_YELLOW,
    }.get(status, C_GRAY)


def header(text: str):
    print(f"\n{C_BOLD}{C_CYAN}{text}{C_RESET}")
    print(C_GRAY + "─" * min(len(text) + 2, 80) + C_RESET)


def success(msg: str):
    print(f"{C_GREEN}✓ {msg}{C_RESET}")


def warn(msg: str):
    print(f"{C_YELLOW}⚠ {msg}{C_RESET}")


def error(msg: str):
    print(f"{C_RED}✗ {msg}{C_RESET}")


def kv(label: str, value: Any, color: str = C_WHITE):
    print(f"  {C_GRAY}{label:<22}{C_RESET}{color}{value}{C_RESET}")


def table(rows: list[dict], columns: list[tuple[str, str]], max_col_width: int = 40):
    """
    Print a simple column-aligned table.
    columns: list of (key, header_label)
    """
    if not rows:
        print(f"  {C_GRAY}(no data){C_RESET}")
        return

    # Compute widths
    widths = {}
    for key, label in columns:
        vals = [str(row.get(key, "—"))[:max_col_width] for row in rows]
        widths[key] = max(len(label), max(len(v) for v in vals))

    # Header row
    header_line = "  " + "  ".join(
        f"{C_BOLD}{C_GRAY}{label:<{widths[key]}}{C_RESET}"
        for key, label in columns
    )
    print(header_line)
    print("  " + C_GRAY + "  ".join("─" * widths[k] for k, _ in columns) + C_RESET)

    # Data rows
    for row in rows:
        parts = []
        for key, _ in columns:
            val = str(row.get(key, "—"))[:max_col_width]
            color = C_WHITE
            if key in ("status", "health"):
                color = _status_color(val)
            elif key in ("risk_level", "severity"):
                color = _risk_color(val)
            elif key == "id":
                color = C_GRAY
            parts.append(f"{color}{val:<{widths[key]}}{C_RESET}")
        print("  " + "  ".join(parts))


def json_out(data: Any):
    print(json.dumps(data, indent=2, default=str))
