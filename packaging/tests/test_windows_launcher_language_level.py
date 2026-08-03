"""The Windows launcher must compile with the .NET Framework 4 csc.exe.

The installer build uses the csc shipped in C:\\Windows\\Microsoft.NET, which
only understands C# 5. Constructs from later language versions compile fine
in a modern IDE and then fail the release workflow, so pin the ones that
have actually broken the build.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = (ROOT / "packaging" / "windows" / "MarcellusLauncher.cs").read_text(encoding="utf-8")


def test_no_dotnet_core_only_process_kill_overload():
    """Process.Kill(bool) does not exist in the .NET Framework."""
    assert not re.search(r"\.Kill\s*\(\s*(true|false)\s*\)", LAUNCHER)


def test_no_discard_assignments():
    """`_ = expr;` is C# 7 syntax."""
    assert not re.search(r"^\s*_\s*=\s", LAUNCHER, re.MULTILINE)


def test_no_interpolated_strings():
    """String interpolation is C# 6 syntax."""
    assert not re.search(r'\$"', LAUNCHER)


def test_no_out_variable_declarations():
    """Inline `out var x` is C# 7 syntax."""
    assert not re.search(r"\bout\s+(var|[A-Z]\w*)\s+\w+\s*[,)]", LAUNCHER)
