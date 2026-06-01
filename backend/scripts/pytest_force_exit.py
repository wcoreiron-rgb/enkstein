"""Run one pytest target and force process exit with pytest's return code.

GitHub hosted runners have occasionally kept backend shard processes alive after
the selected tests completed, likely because imported app modules left
non-daemon runtime threads behind. CI calls this wrapper per test file so the
result is still the pytest result, but process shutdown is deterministic.
"""
import os
import sys

import pytest


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python scripts/pytest_force_exit.py <test-file>", file=sys.stderr)
        os._exit(2)

    code = pytest.main(["-q", "--tb=short", sys.argv[1]])
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(int(code))


if __name__ == "__main__":
    main()
