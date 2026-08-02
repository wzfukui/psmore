#!/usr/bin/env python3
"""Exercise psmore's image, manager, and native-log workspaces in a real PTY."""

from __future__ import annotations

import fcntl
import os
import select
import struct
import subprocess
import sys
import termios
import time


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: scripts/smoke-tui.py PSMORE_BINARY PID", file=sys.stderr)
        return 2

    binary = os.path.abspath(sys.argv[1])
    pid = int(sys.argv[2])
    if pid <= 0 or not os.access(binary, os.X_OK):
        print("binary must be executable and PID must be greater than zero", file=sys.stderr)
        return 2

    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    environment = os.environ.copy()
    environment.setdefault("TERM", "xterm-256color")
    process = subprocess.Popen(
        [binary, "--no-tips"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=environment,
    )
    os.close(slave)
    output = bytearray()
    cursor = 0

    def read_until(needle: bytes, timeout: float) -> None:
        nonlocal cursor
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            match = output.find(needle, cursor)
            if match >= 0:
                cursor = match + len(needle)
                return
            if process.poll() is not None:
                fail(f"psmore exited before rendering {needle!r}: status {process.returncode}")
            readable, _, _ = select.select([master], [], [], 0.25)
            if not readable:
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError:
                chunk = b""
            if chunk:
                output.extend(chunk)
        fail(f"timed out waiting for {needle!r}")

    try:
        time.sleep(0.5)
        os.write(master, f"/pid:{pid}\r".encode())
        time.sleep(0.2)
        os.write(master, b"v")
        read_until(b"PSMORE EXECUTABLE IMAGE", 25.0)
        read_until(b"coverage ", 5.0)

        os.write(master, b"m")
        read_until(b"PSMORE SERVICE CONTEXT", 25.0)
        read_until(b"coverage ", 5.0)

        os.write(master, b"l")
        read_until(b"PSMORE PROCESS LOGS", 25.0)
        read_until(b"source ", 5.0)

        os.write(master, b"m")
        read_until(b"PSMORE SERVICE CONTEXT", 25.0)

        os.write(master, b"q")
        process.wait(timeout=5.0)
        if process.returncode != 0:
            fail(f"psmore exited with status {process.returncode}")
    except Exception as error:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        print(f"psmore TUI smoke failed: {error}", file=sys.stderr)
        return 1
    finally:
        os.close(master)

    print(f"Verified TUI image -> manager -> logs -> manager workflow for PID {pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
