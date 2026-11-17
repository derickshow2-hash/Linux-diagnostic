from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    argv: list[str]
    available: bool
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


def run(argv: list[str], timeout: float = 8, max_chars: int = 16000) -> CommandResult:
    """Run one executable without a shell, with a deadline and bounded output."""
    if not argv or not shutil.which(argv[0]):
        return CommandResult(argv, False, None, error=f"Утилита не найдена: {argv[0] if argv else '(пустая команда)'}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(argv, True, p.returncode, p.stdout[:max_chars], p.stderr[:max_chars])
    except subprocess.TimeoutExpired:
        return CommandResult(argv, True, None, error=f"Превышен таймаут {timeout:g} с")
    except OSError as exc:
        return CommandResult(argv, True, None, error=str(exc))


def output(argv: list[str], timeout: float = 8, max_chars: int = 16000) -> str:
    r = run(argv, timeout, max_chars)
    return r.stdout.strip() if r.available and r.returncode == 0 else ""
