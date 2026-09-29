"""Shared helpers for the infra script tests (no Docker required here)."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def free_port():
    """A currently unbound loopback TCP port (best effort)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class OneShotServer:
    """Accept a single loopback connection on a free port and hand it to ``handler``."""

    def __init__(self, handler, timeout=10.0):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(timeout)
        self.port = self.listener.getsockname()[1]
        self.error = None
        self.thread = threading.Thread(target=self._serve, args=(handler,), daemon=True)
        self.thread.start()

    def _serve(self, handler):
        try:
            conn, _ = self.listener.accept()
            with conn:
                conn.settimeout(10.0)
                handler(conn)
        except Exception as error:  # surfaced to the test through close()
            self.error = error

    def close(self):
        self.thread.join(timeout=10.0)
        self.listener.close()
        if self.error is not None:
            raise AssertionError(f"fake server failed: {self.error!r}")


def run_script(name, *args, env=None, timeout=300):
    """Run scripts/<name> in a subprocess with UTF-8 streams; returns CompletedProcess."""
    environment = dict(os.environ if env is None else env)
    environment.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"})
    return subprocess.run(
        [sys.executable, str(SCRIPTS / name), *map(str, args)], cwd=ROOT, env=environment,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )
