#!/usr/bin/env python3
"""Exercise PID location, safe actions, and evidence workspaces in a real PTY."""

from __future__ import annotations

import fcntl
import os
import select
import struct
import subprocess
import sys
import termios
import tempfile
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
    config_directory = tempfile.TemporaryDirectory(prefix="psmore-tui-smoke-")
    environment["PSMORE_CONFIG_DIR"] = config_directory.name
    environment["PSMORE_LANG"] = "en_US.UTF-8"
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
        tail = bytes(output[-12000:]).decode("utf-8", errors="replace")
        fail(f"timed out waiting for {needle!r}; terminal tail:\n{tail}")

    try:
        read_until(b"digits PID", 10.0)
        os.write(master, b"F")
        read_until(b"process filters", 5.0)
        os.write(master, b"x")
        read_until(b"add DENY filter", 5.0)
        os.write(master, b"path~^/definitely-not-real$")
        os.write(master, b"\r")
        read_until(b"path~^/definitely-not-real$", 5.0)
        os.write(master, b"F")
        os.write(master, b"\x1b")
        time.sleep(0.2)
        if process.poll() is not None:
            fail("bare-tree Escape unexpectedly quit psmore")
        os.write(master, f"{pid}".encode())
        time.sleep(0.2)
        os.write(master, b"\r")
        read_until(f"[{pid}]".encode(), 5.0)
        os.write(master, b"/")
        os.write(master, f"pid:{pid}".encode())
        time.sleep(0.2)
        os.write(master, b"\r")
        time.sleep(0.2)
        os.write(master, b"\r")
        read_until(b"Overview", 5.0)
        os.write(master, b"\t")
        read_until(b"HOT THREADS", 30.0)
        os.write(master, b"\t")
        read_until(b"PORTS & CONNECTIONS", 5.0)
        os.write(master, b"\t")
        read_until(b"/dev/null", 5.0)
        os.write(master, b"\x1b")
        os.write(master, b"D")
        read_until(b"PSMORE PROCESS DOSSIER", 30.0)
        read_until(b"EVIDENCE OVERVIEW", 5.0)

        os.write(master, b"M")
        read_until(b"PSMORE PROCESS MEMORY", 30.0)
        read_until(b"sampled RSS", 5.0)
        read_until(b"MEMORY CATEGORIES", 5.0)

        os.write(master, b"D")
        read_until(b"PSMORE PROCESS DOSSIER", 30.0)

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

        os.write(master, b"m")
        time.sleep(0.2)
        os.write(master, b"k")
        read_until(f"[{pid}]".encode(), 5.0)
        read_until(b"No signal is sent here", 5.0)
        os.write(master, b"\r")
        read_until(b"Press y to send the signal", 5.0)
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
        config_directory.cleanup()

    print(
        "Verified TUI persistent filter -> safe bare-tree Escape -> PID locate -> delayed search apply -> tabbed inspection cards -> dossier -> memory -> dossier -> image -> "
        f"manager -> logs -> manager -> two-step end dialog for PID {pid}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
