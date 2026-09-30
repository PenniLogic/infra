"""Idempotent local Postgres/Redis bootstrap with named-port conflict diagnostics.

Single documented command::

    python scripts/bootstrap.py

It creates ``.env`` from ``.env.example`` on first run (generating a development-only
Postgres password), refuses to start unless the publish address is loopback, exits within a
few seconds with the conflicting port named when another program already holds it, starts
the Compose project, waits for both container health checks and prints one JSON summary to
stdout::

    {"schema": "pennilogic.infra.bootstrap/1", "action": "up", "ok": true, "project": "pennilogic",
     "services": [{"service": "postgres", "healthy": true, "startup_ms": 2345, "startup_source": "health_log"},
                  {"service": "redis", "healthy": true, "startup_ms": 1102, "startup_source": "health_log"}],
     "checks": {...}, "warnings": [], "error": null}

Running it again leaves exactly one healthy stack. Other actions: ``--status`` (read-only),
``--down`` (remove containers and network, keep data) and ``--reset`` (also remove the
named volumes: the only destructive path, always explicit). ``--smoke`` additionally runs
``scripts/smoke_infra.py`` and embeds its separate ``{service, status, latency_ms}`` document
under ``"smoke"``. Human-readable progress goes to stderr; credentials never appear in
either stream. Only resources labelled with this Compose project are ever touched.

``startup_ms`` is the container's own start-to-first-healthy-probe time read from Docker's
health log (``startup_source: "health_log"``); a container that was already running and
healthy before this invocation reports ``0`` (``"already_running"``); when the health log
has rotated the value is ``null`` (``"unknown"``). It is never this script's own wait time.
"""

import argparse
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke_infra  # noqa: E402  (sibling module; shares the environment contract)


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker-compose.yml"
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
SCHEMA = "pennilogic.infra.bootstrap/1"
DEFAULT_PROJECT = "pennilogic"
SERVICES = smoke_infra.SERVICES
SERVICE_PORTS = {"postgres": "PENNILOGIC_POSTGRES_PORT", "redis": "PENNILOGIC_REDIS_PORT"}
VOLUMES = ("pgdata", "redisdata")
PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
PASSWORD_LINE = re.compile(r"^PENNILOGIC_POSTGRES_PASSWORD=[ \t]*$", re.MULTILINE)
# Daemon wording differs by platform and version. Each alternative captures the HOST port:
#  - Docker Engine 29.x on Linux (moby daemon/libnetwork/portallocator/osallocator_linux.go:222,
#    "failed to bind host port %s/%s: %w" with %s = netip.AddrPort, IPv6 in brackets; propagated unwrapped):
#    "failed to bind host port 127.0.0.1:57005/tcp: address already in use"
#  - Docker Engine 28.x on Linux (moby v28 libnetwork/drivers/bridge/port_mapping_linux.go, bindTCPOrUDP,
#    "failed to bind host port for %s: %w" with %s = host-ip:host-port:container-ip:container-port/proto):
#    "failed to bind host port for 127.0.0.1:57005:172.19.0.2:5432/tcp: address already in use";
#    its published-port-range sibling "failed to bind host port %d for %s: %w" names the port first
#  - Docker Engine < 28 on Linux/macOS: "listen tcp 127.0.0.1:6379: bind: address already in use"
#  - Docker Desktop for Windows: "bind: Only one usage of each socket address" (port held) or
#    "bind: An attempt was made to access a socket" (excluded port range)
#  - older daemons: "Bind for 127.0.0.1:5432 failed: port is already allocated"
PORT_IN_USE = re.compile(
    r"(?:failed to bind host port (?:\[[0-9A-Fa-f:.]*\]|[0-9.]+):(\d+)/(?:tcp|udp|sctp): address already in use|"
    r"failed to bind host port for (?:\[[0-9A-Fa-f:.]*\]|[0-9.]+):(\d+):\S+: address already in use|"
    r"failed to bind host port (\d+) for \S+: address already in use|"
    r"Bind for \S*?:(\d+) failed|"
    r":(\d+): bind: address already in use|"
    r":(\d+): bind: Only one usage of each socket address|"
    r":(\d+): bind: An attempt was made to access a socket)",
)
POLL_SECONDS = 0.5
DOCKER_TIMEOUT = 60
DOCKER_COMMAND = ("docker",)  # tests substitute a harmless stand-in; production always runs `docker`
TEARDOWN_SECONDS = 5  # after a timeout: bounded wait for the terminated command tree to exit and release its pipes
LOCK_WAIT_SECONDS = 600
NAME_CONFLICT = re.compile(r"The container name \"/?([^\"]+)\" is already in use")


class BootstrapError(Exception):
    def __init__(self, kind, message, **details):
        super().__init__(message)
        self.kind, self.details = kind, details


def log(message):
    print(f"bootstrap: {message}", file=sys.stderr, flush=True)


class ProjectLock:
    """Serialize bootstrap invocations per Compose project on this machine.

    Compose itself is not atomic: two simultaneous `up` runs of one project race on
    container names and both fail. The lock is an OS file lock (``flock`` on POSIX,
    ``msvcrt.locking`` on Windows) on a zero-byte per-project file in a per-user directory
    under the system temp directory. It is released automatically when the holding process
    exits, so it can never be stale.

    The lock file is deliberately **never unlinked**: on POSIX a waiter polls the inode it
    opened, so unlinking on release would let a newcomer lock a fresh inode while the waiter
    later succeeds on the old one, and two bootstraps would run at once. Independently of
    that, an acquirer re-checks that the inode it locked is still the one at the path.
    """

    def __init__(self, project, wait_seconds=LOCK_WAIT_SECONDS):
        # Per-user directory so another local account cannot pre-create the lock file (POSIX /tmp).
        owner = f"-{os.getuid()}" if hasattr(os, "getuid") else ""
        self.directory = Path(tempfile.gettempdir()) / f"pennilogic-bootstrap-locks{owner}"
        self.path = self.directory / f"{project}.lock"
        self.wait_seconds, self.handle = wait_seconds, None

    def _try_lock(self):
        """Return True when the lock on the currently opened file is held and still authoritative."""
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        import fcntl
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            current = os.stat(self.path)
        except FileNotFoundError:
            current = None
        held = os.fstat(self.handle.fileno())
        if current is None or (current.st_ino, current.st_dev) != (held.st_ino, held.st_dev):
            # The file was replaced or removed under us: this lock protects nothing. Reopen.
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = open(self.path, "a+", encoding="utf-8")
            return False
        return True

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if hasattr(os, "getuid"):
            info = os.stat(self.directory)
            if info.st_uid != os.getuid() or stat.S_ISLNK(os.lstat(self.directory).st_mode):
                raise BootstrapError(
                    "locked", f"Lock directory {self.directory} is not owned by this user or is a symlink;"
                    " refusing to use it. Remove it or set TMPDIR to a private directory.",
                )
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.chmod(self.directory, 0o700)
        self.handle = open(self.path, "a+", encoding="utf-8")
        deadline = time.monotonic() + self.wait_seconds
        announced = False
        while True:
            try:
                if self._try_lock():
                    return self
            except OSError:
                if time.monotonic() > deadline:
                    self.handle.close()
                    raise BootstrapError(
                        "locked", f"Another bootstrap of this project has been running for over"
                        f" {self.wait_seconds}s (lock {self.path}). Wait for it to finish, or find and"
                        " stop that bootstrap process; the lock is released when it exits.",
                    ) from None
                if not announced:
                    log("another bootstrap of this project is running; waiting for it to finish")
                    announced = True
                time.sleep(POLL_SECONDS)

    def __exit__(self, *exc_info):
        try:
            if os.name == "nt":
                import msvcrt
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
        return False


def parse_timestamp(value):
    """Parse the timestamp formats Docker emits: RFC 3339 (``StartedAt``) and Go's
    ``2006-01-02 15:04:05.999999999 -0700 MST`` (health-log entries), with nanoseconds."""
    value = value.strip()
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})(?:\s+\w+)?", value)
    if not match:
        raise ValueError(f"unrecognised timestamp {value!r}")
    date, clock, fraction, zone = match.groups()
    micro = (fraction or "0")[:6].ljust(6, "0")
    zone = "+00:00" if zone == "Z" else (zone if ":" in zone else zone[:3] + ":" + zone[3:])
    return datetime.fromisoformat(f"{date}T{clock}.{micro}{zone}")


def parse_json_records(text):
    """Accept both a JSON array and JSON Lines, as different Compose versions print them."""
    text = text.strip()
    if not text:
        return []
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, list) else [loaded]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


# --- environment file -------------------------------------------------------------------------

def ensure_env_file(env_file, example=ENV_EXAMPLE):
    """Create ``env_file`` from the example with a generated password. Returns True if created.

    The file is created exclusively (``O_EXCL``) with mode 0600 where the platform honours
    it (POSIX; on Windows the directory ACL applies). If another invocation created it in
    the meantime, that file is kept and False is returned.
    """
    env_file = Path(env_file)
    if env_file.exists():
        return False
    if not Path(example).is_file():
        raise BootstrapError("missing_example", f"{example} is missing; restore it from the repository.")
    template = Path(example).read_text(encoding="utf-8")
    if not PASSWORD_LINE.search(template):
        raise BootstrapError(
            "invalid_example", f"{example} has no blank PENNILOGIC_POSTGRES_PASSWORD= line to fill in.",
        )
    content = PASSWORD_LINE.sub(
        "PENNILOGIC_POSTGRES_PASSWORD=" + secrets.token_urlsafe(24), template, count=1,
    )
    env_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return True


def resolve_project(explicit, settings):
    project = explicit or settings.get("COMPOSE_PROJECT_NAME") or DEFAULT_PROJECT
    if not PROJECT_NAME.match(project):
        raise BootstrapError(
            "invalid_project",
            f"Compose project name {project!r} must be lowercase letters, digits, '-' or '_' and start"
            " with a letter or digit.",
        )
    return project


def validate_settings(settings, allow_non_loopback=False, require_password=True):
    """Check ports, publish address and credentials; return {service: port}.

    Returns the validated ports. Also used by ``--status`` (``require_password=False``).
    """
    ports = {}
    for service, key in SERVICE_PORTS.items():
        try:
            ports[service] = smoke_infra.port_of(settings, key)
        except ValueError as error:
            raise BootstrapError("invalid_port", str(error)) from error
    if ports["postgres"] == ports["redis"]:
        raise BootstrapError(
            "invalid_port",
            f"PENNILOGIC_POSTGRES_PORT and PENNILOGIC_REDIS_PORT are both {ports['postgres']};"
            " give each service its own port in .env.",
        )
    address = settings["PENNILOGIC_BIND_ADDRESS"]
    if address == "localhost":
        raise BootstrapError(
            "non_loopback_bind",
            "PENNILOGIC_BIND_ADDRESS=localhost is not accepted: Docker publishes to IP addresses only."
            " Use 127.0.0.1 (the default) or ::1.",
        )
    if not is_loopback(address):
        if not allow_non_loopback:
            raise BootstrapError(
                "non_loopback_bind",
                f"PENNILOGIC_BIND_ADDRESS={address} would publish the development services beyond this"
                " machine. The stack binds to the loopback interface only by default; keep 127.0.0.1, or"
                " pass --allow-non-loopback if you really intend to expose the development Postgres and"
                " Redis to your network (Redis then also needs PENNILOGIC_REDIS_PASSWORD set).",
            )
        if not settings["PENNILOGIC_REDIS_PASSWORD"]:
            raise BootstrapError(
                "non_loopback_bind",
                f"PENNILOGIC_BIND_ADDRESS={address} with --allow-non-loopback would expose Redis to your"
                " network with no authentication at all (PENNILOGIC_REDIS_PASSWORD is blank). Set a"
                " development-only PENNILOGIC_REDIS_PASSWORD in .env first, or keep the loopback default."
                " Nothing was started.",
            )
    if require_password and not settings["PENNILOGIC_POSTGRES_PASSWORD"]:
        raise BootstrapError(
            "missing_password",
            "PENNILOGIC_POSTGRES_PASSWORD is blank. Set any development-only value in .env, or delete"
            " .env and re-run so a random one is generated. Nothing was started.",
        )
    return ports


def is_loopback(address):
    """True for loopback IP literals (127.0.0.0/8, ::1, IPv4-mapped loopback); hostnames are not accepted."""
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


# --- process-tree ownership on Windows -----------------------------------------------------------

class TreeTimeoutExpired(subprocess.TimeoutExpired):
    """``TimeoutExpired`` plus a sentence saying what happened to the command's process tree."""

    def __init__(self, cmd, timeout, cleanup):
        super().__init__(cmd, timeout)
        self.cleanup = cleanup


class ProcessOwnershipError(OSError):
    """Windows refused to create the job object or to place the command in it (the run fails closed).

    ``command_started`` is False when the refusal came before the command was started (nothing ran)
    and True when the already started command was terminated because it could not be owned.
    """

    command_started = False


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation = 1, 3, 9
    PROCESS_TERMINATE, PROCESS_SET_QUOTA, PROCESS_QUERY_LIMITED_INFORMATION = 0x0001, 0x0100, 0x1000
    SYNCHRONIZE = 0x100000
    WAIT_OBJECT_0, WAIT_TIMEOUT, MAXIMUM_WAIT_OBJECTS = 0x0, 0x102, 64
    ERROR_INVALID_PARAMETER, ERROR_MORE_DATA = 87, 234

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]

    def _process_id_list(capacity):
        """JOBOBJECT_BASIC_PROCESS_ID_LIST with room for ``capacity`` PIDs (the SDK declares a flexible array)."""
        class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
            _fields_ = [("NumberOfAssignedProcesses", wintypes.DWORD), ("NumberOfProcessIdsInList", wintypes.DWORD),
                        ("ProcessIdList", ctypes.c_size_t * capacity)]
        return _JOBOBJECT_BASIC_PROCESS_ID_LIST()

    for _name, _restype, _argtypes in (
        ("CreateJobObjectW", wintypes.HANDLE, (wintypes.LPVOID, wintypes.LPCWSTR)),
        ("SetInformationJobObject", wintypes.BOOL, (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)),
        ("QueryInformationJobObject", wintypes.BOOL,
         (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)),
        ("AssignProcessToJobObject", wintypes.BOOL, (wintypes.HANDLE, wintypes.HANDLE)),
        ("TerminateJobObject", wintypes.BOOL, (wintypes.HANDLE, wintypes.UINT)),
        ("OpenProcess", wintypes.HANDLE, (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)),
        ("WaitForMultipleObjects", wintypes.DWORD, (wintypes.DWORD, wintypes.LPHANDLE, wintypes.BOOL, wintypes.DWORD)),
        ("CloseHandle", wintypes.BOOL, (wintypes.HANDLE,)),
    ):
        _function = getattr(_kernel32, _name)
        _function.restype, _function.argtypes = _restype, _argtypes


class WindowsJob:
    """Own a command's whole process tree on Windows through an unnamed Job Object.

    On Windows ``docker.exe`` runs ``docker compose`` as a child process (``docker-compose.exe``)
    that inherits the captured stdout/stderr pipes. ``subprocess.run(timeout=...)`` terminates
    only ``docker.exe`` itself and then blocks until every holder of those pipes has exited, so a
    timed-out Compose command returned only when the orphaned plugin had finished its work (or
    never, for a stuck one). Measured on Docker Desktop 29.7.2 / Compose v5.5.0 (infra#37): a
    `compose up` with a 2.5 s timeout returned at 2.9 s, once the plugin had created the containers;
    a `compose events` kept the pipes open for the whole observation window.

    The job is created before the child exists, with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and no
    breakaway right, so descendants cannot leave it and anything still alive dies when the handle
    is closed. The child is assigned immediately after ``CreateProcess`` returns. The unowned
    window between the two is a few hundred microseconds of Python (``OpenProcess`` plus
    ``AssignProcessToJobObject`` through ctypes; measured 0.17-0.71 ms, median 0.23 ms, over 50
    rounds, and up to a few milliseconds under scheduling pressure), two to three orders of
    magnitude shorter than ``docker.exe`` needs to start and spawn its plugin (measured
    0.13-0.39 s), and a process started inside the job is a member from birth. The stdlib offers
    nothing shorter: ``Popen`` closes the thread handle right after ``CreateProcess`` (so no
    suspended start) and ``_winapi.CreateProcess`` has no ``PROC_THREAD_ATTRIBUTE_JOB_LIST``. An
    interrupt landing inside that window kills the just-started command before it propagates.
    Nested jobs are used when this process already runs inside a job (Windows 8+). The job handle
    is never inheritable. On a timeout :func:`terminate_tree` terminates the job and then awaits
    the members' process objects, so "has exited" is only claimed once Windows has finished
    tearing them down. A failure to establish ownership fails closed: a refusal before the command
    exists means nothing is started; a refusal after it was started terminates it at once. Both
    raise :class:`ProcessOwnershipError`; nothing runs unowned. A command that has already exited
    by the time it would be assigned is reported with its own result.
    """

    def __init__(self):
        self.handle = _kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise self._failure("CreateJobObject", ctypes.get_last_error())
        limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            self.handle, JobObjectExtendedLimitInformation, ctypes.byref(limits), ctypes.sizeof(limits),
        ):
            code = ctypes.get_last_error()
            self.close()
            raise self._failure("SetInformationJobObject", code)

    @staticmethod
    def _failure(what, code):
        error = ctypes.WinError(code)
        return ProcessOwnershipError(error.errno, f"{what} failed: {error.strerror}", None, error.winerror)

    def assign(self, pid):
        """Put the process (and, from then on, everything it starts) into the job."""
        process = _kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not process:
            raise self._failure("OpenProcess", ctypes.get_last_error())
        try:
            if not _kernel32.AssignProcessToJobObject(self.handle, process):
                raise self._failure("AssignProcessToJobObject", ctypes.get_last_error())
        finally:
            _kernel32.CloseHandle(process)

    def terminate(self):
        """Terminate every process in the job (and in nested jobs); True when Windows accepted it."""
        return bool(_kernel32.TerminateJobObject(self.handle, 1))

    def active_processes(self):
        """Number of processes still alive in the job, or None when Windows will not say."""
        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        if not _kernel32.QueryInformationJobObject(
            self.handle, JobObjectBasicAccountingInformation, ctypes.byref(info), ctypes.sizeof(info), None,
        ):
            return None
        return info.ActiveProcesses

    def process_ids(self):
        """PIDs of the processes in this job right now (job-scoped, no global enumeration), or None."""
        for capacity in (64, 4096):
            info = _process_id_list(capacity)
            if _kernel32.QueryInformationJobObject(
                self.handle, JobObjectBasicProcessIdList, ctypes.byref(info), ctypes.sizeof(info), None,
            ):
                return list(info.ProcessIdList[:info.NumberOfProcessIdsInList])
            if ctypes.get_last_error() != ERROR_MORE_DATA:
                return None
        return None

    def close(self):
        if self.handle:
            _kernel32.CloseHandle(self.handle)  # kill-on-close: anything still in the job dies now
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


class ProcessExits:
    """Await the exit of specific processes by PID through their process objects.

    A process object is signaled only when Windows has finished tearing the process down,
    including the rundown of its handles; the job's ``ActiveProcesses`` counter and PID list drop
    a terminated process milliseconds earlier (measured: counter 0.04-0.34 ms, PID list 0.4-1.5 ms,
    process object 3.7-38 ms after ``TerminateJobObject``; a file the process held was still
    undeletable at the first two points in 30/30 rounds and deletable at the third in 30/30).
    ``add`` pins the objects with SYNCHRONIZE handles; a PID that no longer exists at that moment
    (ERROR_INVALID_PARAMETER) had already been torn down completely and counts as exited.
    """

    def __init__(self):
        self.handles, self.gone, self.unopenable = {}, set(), set()

    def add(self, pids):
        for pid in pids:
            if pid in self.handles or pid in self.gone or pid in self.unopenable:
                continue
            handle = _kernel32.OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                self.handles[pid] = handle
            elif ctypes.get_last_error() == ERROR_INVALID_PARAMETER:
                self.gone.add(pid)
            else:
                self.unopenable.add(pid)

    @property
    def seen(self):
        return len(self.handles) + len(self.gone) + len(self.unopenable)

    def wait(self, timeout):
        """Wait up to ``timeout`` seconds for every pinned process object; returns how many are signaled."""
        handles, deadline = list(self.handles.values()), time.monotonic() + timeout
        for start in range(0, len(handles), MAXIMUM_WAIT_OBJECTS):
            batch = handles[start:start + MAXIMUM_WAIT_OBJECTS]
            array = (wintypes.HANDLE * len(batch))(*batch)
            remaining = max(0, int((deadline - time.monotonic()) * 1000))
            _kernel32.WaitForMultipleObjects(len(batch), array, True, remaining)
        signaled = 0
        for handle in handles:
            array = (wintypes.HANDLE * 1)(handle)
            signaled += _kernel32.WaitForMultipleObjects(1, array, True, 0) == WAIT_OBJECT_0
        return signaled + len(self.gone)

    def close(self):
        for handle in self.handles.values():
            _kernel32.CloseHandle(handle)
        self.handles = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()  # every pinned handle is released whatever raised inside the block
        return False


def release_pipes(process, timeout):
    """Collect the output threads and reap the child within ``timeout``.

    True when every holder of the output pipes has exited. On a timeout the pipes are deliberately
    left open: closing a pipe that a reader thread is blocked on would block this thread as well,
    and the bootstrap exits shortly after reporting the error anyway.
    """
    try:
        process.communicate(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def terminate_tree(job, process, deadline):
    """After a timeout: terminate the whole tree, then wait until ``deadline`` (TEARDOWN_SECONDS after the
    timeout) for every process that was in the job to exit (its process object is signaled, see
    :class:`ProcessExits`) and for the output pipes to be released. Returns a sentence for the error
    message saying exactly what was confirmed. The teardown wait only observes the exit; it is never
    extra command time (the return lands a fraction of a second after the deadline: process start-up,
    the ``communicate`` join and the wait granularity)."""
    with ProcessExits() as exits:  # the pins are released on every exit from this block, including a failing kill
        exits.add(job.process_ids() or [])  # pin the members before the kill so their exit can be awaited
        terminated = job.terminate()
        if not terminated:
            process.kill()  # at least docker itself, as `subprocess.run` would
        # A process created in the microseconds between the snapshot and the kill was terminated too;
        # await it as well while the job still lists it.
        while time.monotonic() < deadline:
            late = [pid for pid in job.process_ids() or [] if pid not in exits.handles and pid not in exits.gone
                    and pid not in exits.unopenable]
            if not late:
                break
            exits.add(late)
        released = release_pipes(process, max(0.0, deadline - time.monotonic()))
        seen = exits.seen
        exited = exits.wait(max(0.0, deadline - time.monotonic()))
    active = job.active_processes()
    if terminated and released and seen and exited == seen and active == 0:
        return (f"Its whole process tree was terminated and has exited ({seen} process{'' if seen == 1 else 'es'},"
                " output released).")
    if terminated and released and not seen and active == 0:
        # Only possible when the last member exited in the moment between the timeout and the snapshot.
        return ("Its whole process tree was terminated; the job listed no process any more at the timeout,"
                " nothing is active and the output was released.")
    awaited = f"{exited} of {seen}" if seen else "none awaited (the job listed no process at the timeout)"
    return (
        f"Warning: docker was terminated, but its process tree could not be confirmed gone within {TEARDOWN_SECONDS}s"
        f" (job termination {'accepted' if terminated else 'refused'}; output released: {released};"
        f" processes exited: {awaited}; processes still active: {'unknown' if active is None else active});"
        " a descendant may still be running."
    )


def run_docker(command, cwd, env, timeout):
    """``subprocess.run`` with captured UTF-8 output; on Windows the command's process tree is owned.

    POSIX keeps the plain ``subprocess.run`` call, unchanged. On Windows the command starts inside
    a :class:`WindowsJob`; on timeout the whole tree is terminated and :class:`TreeTimeoutExpired`
    is raised about ``timeout + TEARDOWN_SECONDS`` after the start (measured up to ~0.15 s past that
    when the tree does not exit).
    """
    options = dict(cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace")
    if os.name != "nt":
        return subprocess.run(command, capture_output=True, timeout=timeout, check=False, **options)
    with WindowsJob() as job:  # a refusal here raises before anything is started (command_started stays False)
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
            job.assign(process.pid)
        except ProcessOwnershipError as error:
            if process is not None and process.poll() is None:  # still running, unowned: fail closed
                process.kill()
                release_pipes(process, TEARDOWN_SECONDS)
                error.command_started = True
                raise
            if process is None:
                raise
            # Windows also refuses to assign a process that has already exited. Only a command failing
            # within microseconds of its creation can get here; its own result is what to report.
        except BaseException:
            # An interrupt inside the unowned window (Popen returned, assignment not yet done) must not
            # leave the just-started command behind; an interrupt inside Popen itself is the stdlib's own
            # window, the same one `subprocess.run` has.
            if process is not None:
                process.kill()
                release_pipes(process, TEARDOWN_SECONDS)
            raise
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            deadline = time.monotonic() + TEARDOWN_SECONDS
            try:
                cleanup = terminate_tree(job, process, deadline)
            except Exception as error:  # cleanup must never mask the timeout; the tree is still terminated
                job.terminate()
                release_pipes(process, max(0.0, deadline - time.monotonic()))
                cleanup = (f"Warning: the process tree could not be cleaned up ({type(error).__name__}: {error});"
                           " it was terminated without confirmation, and closing the job object with this run"
                           " terminates whatever is still in it.")
            raise TreeTimeoutExpired(command, timeout, cleanup) from None
        except BaseException:
            job.terminate()  # e.g. Ctrl-C: the tree goes down with the bootstrap, as `subprocess.run` kills its child
            raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


# --- docker wrappers ----------------------------------------------------------------------------

class Compose:
    def __init__(self, project, env_file, environ, secret_values, verbose=False, compose_file=COMPOSE_FILE,
                 docker_command=DOCKER_COMMAND):
        self.project, self.env_file, self.environ = project, Path(env_file), dict(environ)
        self.secret_values, self.verbose, self.compose_file = tuple(secret_values), verbose, compose_file
        self.docker_command = tuple(docker_command)

    def redact(self, text):
        return smoke_infra.redact(text, self.secret_values)

    def docker(self, *args, timeout=DOCKER_TIMEOUT):
        command = [*self.docker_command, *args]
        label = " ".join(command[:3])
        try:
            result = run_docker(command, cwd=ROOT, env=self.environ, timeout=timeout)
        except FileNotFoundError as error:
            raise BootstrapError("docker_missing", "The `docker` command is not installed or not on PATH.") from error
        except ProcessOwnershipError as error:
            fate = ("The command had already been started and was terminated immediately." if error.command_started
                    else "The command was not started.")
            raise BootstrapError(
                "io_error",
                f"Windows refused to own the process tree of `{label}` ({error}). {fate} Typically the bootstrap"
                " itself is running inside a job object that forbids nested jobs (an old-style sandbox); re-run it"
                " from a plain terminal.",
            ) from error
        except subprocess.TimeoutExpired as error:
            message = f"`{label}` did not finish within {timeout}s."
            if isinstance(error, TreeTimeoutExpired):  # Windows: the tree was owned; say what became of it
                raise BootstrapError("docker_timeout", f"{message} {error.cleanup}", cleanup=error.cleanup) from error
            raise BootstrapError("docker_timeout", message) from error
        if self.verbose and result.stderr.strip():
            log(self.redact(result.stderr.rstrip()))
        return result

    def compose(self, *args, timeout=DOCKER_TIMEOUT, check=True):
        base = ["compose", "--project-name", self.project, "-f", str(self.compose_file)]
        if self.env_file.is_file():
            base += ["--env-file", str(self.env_file)]
        result = self.docker(*base, *args, timeout=timeout)
        if check and result.returncode:
            raise BootstrapError(
                "compose_failed",
                f"`docker compose {args[0]}` failed (exit {result.returncode}):\n{self.redact(result.stderr.strip())}",
                stderr=self.redact(result.stderr),
            )
        return result

    def engine_version(self):
        result = self.docker("version", "--format", "{{.Server.Version}}", timeout=30)
        if result.returncode or not result.stdout.strip():
            raise BootstrapError(
                "docker_unavailable",
                "Docker Engine is not reachable. Start Docker Desktop (or the docker service) and re-run.\n"
                + self.redact(result.stderr.strip()),
            )
        return result.stdout.strip()

    def ps(self, all_states=False):
        args = ["ps", "--format", "json"] + (["--all"] if all_states else [])
        return parse_json_records(self.compose(*args).stdout)

    def inspect(self, container_ids):
        if not container_ids:
            return []
        result = self.docker("inspect", *container_ids)
        if result.returncode:
            return []
        return json.loads(result.stdout)

    def volumes(self):
        result = self.docker(
            "volume", "ls", "--filter", f"label=com.docker.compose.project={self.project}",
            "--format", "{{.Name}}",
        )
        return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())

    def logs(self):
        return self.compose("logs", "--no-color", check=False).stdout

    def published_ports(self):
        """Map host port -> description for every running container on this engine."""
        result = self.docker(
            "ps", "--format", '{{.Names}}\t{{.Label "com.docker.compose.project"}}\t{{.Ports}}',
        )
        holders = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            name, project, ports = parts
            for match in re.finditer(r":(\d+)->", ports):
                where = f" of compose project '{project}'" if project else ""
                holders[int(match.group(1))] = f"Docker container '{name}'{where}"
        return holders


# --- preflight -----------------------------------------------------------------------------------

def is_listening(address, port, timeout=1.0):
    target = {"0.0.0.0": "127.0.0.1", "::": "::1", "": "127.0.0.1"}.get(address, address)
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except OSError:
        return False


def suggest_port(address, port):
    for candidate in (port + 10000, port + 20000, port + 30000):
        if candidate <= 65535 and not is_listening(address, candidate):
            return candidate
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def owned_ports(records):
    """Service -> published host port for this project's running containers."""
    owned = {}
    for record in records:
        if record.get("State") != "running":
            continue
        for publisher in record.get("Publishers") or []:
            if publisher.get("PublishedPort"):
                owned.setdefault(record.get("Service"), set()).add(int(publisher["PublishedPort"]))
    return owned


def find_port_conflicts(settings, ports, own_records, holders=None):
    """Return conflicts for ports needed by services that are not already ours."""
    address, owned, conflicts = settings["PENNILOGIC_BIND_ADDRESS"], owned_ports(own_records), []
    for service, port in ports.items():
        if port in owned.get(service, set()) or not is_listening(address, port):
            continue
        holder = (holders or {}).get(port) or (
            "a process outside Docker (Windows: `netstat -ano | findstr :%d` then `tasklist /FI \"PID eq <pid>\"`;"
            " Linux/macOS: `ss -ltnp 'sport = :%d'` or `lsof -iTCP:%d -sTCP:LISTEN`)" % (port, port, port)
        )
        conflicts.append({
            "service": service, "port": port, "address": address, "holder": holder,
            "variable": SERVICE_PORTS[service], "suggested_port": suggest_port(address, port),
        })
    return conflicts


def conflict_error(conflicts, warnings=()):
    lines = []
    for item in conflicts:
        lines.append(
            f"Port conflict: service \"{item['service']}\" needs {item['address']}:{item['port']}, but port"
            f" {item['port']} is already in use by {item['holder']}.\n"
            f"  Fix: set {item['variable']}={item['suggested_port']} in .env (a verified free port) and"
            " re-run, or stop the conflicting service."
        )
    lines.append("Nothing was started.")
    return BootstrapError(
        "port_conflict", "\n".join(lines), ports=[item["port"] for item in conflicts], conflicts=conflicts,
        summary={"warnings": list(warnings)},
    )


def compose_port_failure(stderr):
    ports = sorted({int(p) for match in PORT_IN_USE.finditer(stderr) for p in match.groups() if p})
    if not ports:
        return None
    named = ", ".join(str(p) for p in ports)
    return BootstrapError(
        "port_conflict",
        f"Port conflict: Docker could not bind host port(s) {named}. Another program holds the port"
        " (it may only be bound, not listening, so the preflight check could not see it) or it is in"
        " a reserved range. Set the matching PENNILOGIC_*_PORT in .env to a free port and re-run."
        f"\n{stderr.strip()}",
        ports=ports,
    )


def rollback_partial_start(compose, had_containers_before):
    """After a failed `up`, undo what this run created; data volumes are always kept.

    Only a stack that did not exist before this run is removed. If the project already had
    containers (a failed re-run, or a concurrent run's stack), nothing is touched and the
    message says so. Returns a sentence for the error message. Never raises: the original
    failure must not be masked by a follow-up error.
    """
    try:
        volumes = compose.volumes()
    except BootstrapError:
        volumes = []
    kept = f" Data volumes {', '.join(volumes)} were kept." if volumes else ""
    if had_containers_before:
        return (
            "This run's rollback did not touch the project's containers because some already existed before"
            " it started (Compose itself may have recreated a container whose configuration changed). Run"
            " `python scripts/bootstrap.py --status` to inspect them and re-run once the cause is fixed;"
            " the re-run converges to one healthy stack." + kept
        )
    try:
        result = compose.compose("down", "--remove-orphans", timeout=180, check=False)
        remaining = compose.ps(all_states=True) if result.returncode == 0 else None
    except BootstrapError:
        result, remaining = None, None
    if result is not None and result.returncode == 0 and not remaining:
        return "The partially created containers and network were removed again; nothing is running." + kept
    return (
        "Warning: the partially created stack could not be fully removed; run `python scripts/bootstrap.py"
        " --down` (or re-run after fixing the cause) to converge." + kept
    )


# --- readiness ------------------------------------------------------------------------------------

HEALTH_LOG_CAPACITY = 5  # Docker keeps only the most recent health probes per container
SOURCE_HEALTH_LOG, SOURCE_ALREADY_RUNNING, SOURCE_UNKNOWN = "health_log", "already_running", "unknown"


def derive_startup_ms(state):
    """Milliseconds from container start to its first successful health probe, if still logged."""
    health = state.get("Health") or {}
    entries = sorted(health.get("Log") or [], key=lambda entry: entry.get("Start", ""))
    successes = [entry for entry in entries if entry.get("ExitCode") == 0]
    if not successes or not state.get("StartedAt"):
        return None
    if entries[0].get("ExitCode") == 0 and len(entries) >= HEALTH_LOG_CAPACITY:
        return None  # the first success may have rotated out of the log; unknown rather than wrong
    try:
        delta = parse_timestamp(successes[0]["End"]) - parse_timestamp(state["StartedAt"])
    except (KeyError, ValueError):
        return None
    return max(0, int(delta.total_seconds() * 1000))


def service_records(compose, records, already_running=()):
    """One contract record per service: {service, healthy, startup_ms, startup_source}.

    ``startup_ms`` is the container's own start-to-first-healthy-probe time from Docker's
    health log (``health_log``). A container that was already running and healthy before this
    invocation (its ID is in ``already_running``) reports ``0`` (``already_running``). When the
    health log has rotated past the first success the value is ``None`` (``unknown``). This
    script's own polling latency is never reported as startup time.
    """
    by_service = {record.get("Service"): record for record in records}
    # `compose ps` prints short (12-char) IDs while `docker inspect` returns full IDs.
    inspected = compose.inspect([record["ID"] for record in records if record.get("ID")])
    states = {}
    for record in records:
        short = record.get("ID") or "\0"
        states[short] = next((item["State"] for item in inspected if item.get("Id", "").startswith(short)), {})
    output = []
    for service in SERVICES:
        record = by_service.get(service) or {}
        healthy = record.get("State") == "running" and record.get("Health") == "healthy"
        startup_ms, source = None, SOURCE_UNKNOWN
        if healthy and record.get("ID") in already_running:
            startup_ms, source = 0, SOURCE_ALREADY_RUNNING
        elif healthy:
            startup_ms = derive_startup_ms(states.get(record.get("ID"), {}))
            source = SOURCE_HEALTH_LOG if startup_ms is not None else SOURCE_UNKNOWN
        output.append({"service": service, "healthy": healthy, "startup_ms": startup_ms, "startup_source": source})
    return output


def healthy_ids(records):
    return {r.get("ID") for r in records if r.get("State") == "running" and r.get("Health") == "healthy"}


def wait_healthy(compose, deadline):
    """Poll until both services report healthy; raise on exit/unhealthy or when ``deadline`` passes."""
    while True:
        records = compose.ps()
        by_service = {record.get("Service"): record for record in records}
        problems, healthy = [], set()
        for service in SERVICES:
            record = by_service.get(service)
            if record is None:
                continue
            if record.get("State") in ("exited", "dead") or record.get("Health") == "unhealthy":
                problems.append(f"{service}: state={record.get('State')} health={record.get('Health') or 'n/a'}")
            elif record.get("Health") == "healthy":
                healthy.add(service)
        if problems:
            raise BootstrapError(
                "unhealthy", "The stack did not become healthy:\n  " + "\n  ".join(problems)
                + "\n" + diagnostics(compose, records),
            )
        if len(healthy) == len(SERVICES):
            return records
        if time.monotonic() > deadline:
            waiting = ", ".join(f"{s}: {by_service.get(s, {}).get('Health') or by_service.get(s, {}).get('State') or 'absent'}"
                                for s in SERVICES if s not in healthy)
            raise BootstrapError(
                "timeout", f"Timed out waiting for health checks ({waiting}).\n" + diagnostics(compose, records),
            )
        time.sleep(POLL_SECONDS)


def diagnostics(compose, records):
    lines = []
    for item in compose.inspect([record["ID"] for record in records if record.get("ID")]):
        health = (item.get("State") or {}).get("Health") or {}
        last = (health.get("Log") or [{}])[-1]
        name = item.get("Name", "").lstrip("/")
        lines.append(f"{name}: status={item['State'].get('Status')} health={health.get('Status', 'n/a')}"
                     f" last_probe={compose.redact((last.get('Output') or '').strip())[:200]!r}")
    tail = compose.redact(compose.logs()).splitlines()[-15:]
    return "Container state:\n  " + "\n  ".join(lines) + "\nLast log lines:\n  " + "\n  ".join(tail)


def stack_checks(compose):
    containers = compose.ps(all_states=True)
    counts = {service: sum(1 for r in containers if r.get("Service") == service) for service in SERVICES}
    volumes = compose.volumes()
    expected = sorted(f"{compose.project}_{name}" for name in VOLUMES)
    return {
        "single_stack": all(count == 1 for count in counts.values()) and len(containers) == len(SERVICES)
        and volumes == expected,
        "containers": counts,
        "orphan_containers": len(containers) - sum(counts.values()),
        "volumes": volumes,
    }


MIN_SCANNED_SECRET_LENGTH = 8


def logs_free_of_credentials(compose):
    """False if any configured secret appears verbatim in the container logs.

    Values shorter than MIN_SCANNED_SECRET_LENGTH are not scanned: they would match
    ordinary log text by chance, and the generated development password is far longer.
    """
    text = compose.logs()
    return not any(len(value) >= MIN_SCANNED_SECRET_LENGTH and value in text for value in compose.secret_values)


# --- actions -----------------------------------------------------------------------------------------

def stale_volume_warning(compose, env_created):
    """Warn when a freshly generated password cannot match data already in this project's volumes."""
    volumes = compose.volumes()
    if not (env_created and volumes):
        return None
    return (
        f"Data volumes {', '.join(volumes)} already existed before this first start, so the freshly"
        " generated PENNILOGIC_POSTGRES_PASSWORD will not match the password stored in that Postgres"
        " data. If connections fail with authentication errors, run `python scripts/bootstrap.py --reset`"
        " (destroys that development data) and start again."
    )


def action_up(compose, settings, ports, args):
    warnings = []
    stale = stale_volume_warning(compose, args.env_created)
    if stale:
        warnings.append(stale)
        log("warning: " + stale)
    before = compose.ps(all_states=True)
    conflicts = find_port_conflicts(settings, ports, before, compose.published_ports())
    if conflicts:
        raise conflict_error(conflicts, warnings)
    already_running = healthy_ids(before)
    log(f"starting compose project '{compose.project}' on {settings['PENNILOGIC_BIND_ADDRESS']}"
        f" (postgres:{ports['postgres']}, redis:{ports['redis']})")
    started = time.monotonic()
    # `up` may pull both images on a clean machine; that time is not counted against --timeout.
    result = compose.compose("up", "--detach", "--remove-orphans", timeout=max(args.timeout, 600), check=False)
    if result.returncode:
        stderr = compose.redact(result.stderr)
        name_conflict = bool(NAME_CONFLICT.search(stderr))
        error = compose_port_failure(stderr)
        if error is None and name_conflict:
            error = BootstrapError(
                "compose_failed",
                "Docker reports a container-name conflict for this project, which happens when another"
                " `docker compose up` of the same project ran at the same time. Re-run `python scripts/bootstrap.py`"
                f" once the other run has finished.\n{stderr.strip()}",
            )
        if error is None:
            error = BootstrapError(
                "compose_failed", f"`docker compose up` failed (exit {result.returncode}):\n{stderr.strip()}",
            )
        # Compose may already have created a network, volumes and some containers (Redis can even be
        # running). Leave no half-started stack behind when the project was empty before this run;
        # an existing stack (failed re-run) or another run's containers (name conflict) are left alone.
        # Volumes are never removed.
        outcome = rollback_partial_start(compose, had_containers_before=bool(before) or name_conflict)
        error.args = (f"{error.args[0]}\n{outcome}",)
        error.details["rollback"] = outcome
        error.details["summary"] = {"warnings": warnings}
        raise error
    health_deadline = time.monotonic() + args.timeout
    try:
        records = wait_healthy(compose, health_deadline)
    except BootstrapError as error:
        error.details.setdefault("summary", {})["warnings"] = warnings
        raise
    services = service_records(compose, records, already_running)
    checks = stack_checks(compose)
    checks["logs_free_of_credentials"] = logs_free_of_credentials(compose)
    summary = {"services": services, "checks": checks, "warnings": warnings,
               "elapsed_ms": int((time.monotonic() - started) * 1000)}
    if not checks["single_stack"]:
        raise BootstrapError(
            "not_single_stack", f"Expected exactly one container per service and volumes {VOLUMES}; found {checks}.",
            summary=summary,
        )
    if not checks["logs_free_of_credentials"]:
        raise BootstrapError(
            "credential_in_logs", "A configured credential value appears in the container logs (value withheld).",
            summary=summary,
        )
    for record in services:
        log(f"{record['service']}: " + describe_startup(record))
    return summary


def describe_startup(record):
    if record["startup_source"] == SOURCE_ALREADY_RUNNING:
        return "healthy (already running before this run)"
    if record["startup_ms"] is None:
        return "healthy (startup time no longer in Docker's health log)"
    return f"healthy in {record['startup_ms']} ms (from Docker's health log)"


def action_status(compose):
    records = compose.ps(all_states=True)
    services = service_records(compose, records)
    checks = stack_checks(compose)
    ok = all(record["healthy"] for record in services) and checks["single_stack"]
    for record in services:
        log(f"{record['service']}: " + (describe_startup(record) if record["healthy"] else "not healthy"))
    return {"services": services, "checks": checks, "warnings": [], "ok": ok}


def action_down(compose, destroy_volumes):
    if destroy_volumes:
        log(f"DESTROYING containers, network and data volumes of compose project '{compose.project}'")
    else:
        log(f"removing containers and network of compose project '{compose.project}'; data volumes are kept")
    args = ["down", "--remove-orphans"] + (["--volumes"] if destroy_volumes else [])
    compose.compose(*args, timeout=180)
    remaining_containers = compose.ps(all_states=True)
    remaining_volumes = compose.volumes()
    ok = not remaining_containers and (not remaining_volumes if destroy_volumes else True)
    services = empty_services()
    checks = {"containers_remaining": len(remaining_containers), "volumes_remaining": remaining_volumes}
    if not ok:
        raise BootstrapError(
            "teardown_incomplete", f"Teardown left resources behind: {checks}",
            summary={"services": services, "checks": checks, "warnings": []},
        )
    log("done" + ("" if destroy_volumes else f"; kept volumes {', '.join(remaining_volumes) or '(none)'}"))
    return {"services": services, "checks": checks, "warnings": [], "ok": True}


def empty_services():
    return [{"service": s, "healthy": False, "startup_ms": None, "startup_source": SOURCE_UNKNOWN} for s in SERVICES]


# --- entry point ---------------------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--status", action="store_true", help="report health without starting anything")
    action.add_argument("--down", action="store_true", help="remove containers and network; keep data volumes")
    action.add_argument("--reset", action="store_true",
                        help="remove containers, network AND named volumes (destroys development data)")
    parser.add_argument("--smoke", action="store_true",
                        help="after the stack is healthy, run scripts/smoke_infra.py and embed its result")
    parser.add_argument("--project", help="Compose project name (default: COMPOSE_PROJECT_NAME or 'pennilogic')")
    parser.add_argument("--env-file", type=Path, default=ENV_FILE, help="environment file (default: .env)")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="seconds to wait for both health checks after `docker compose up` returns;"
                             " image pulls are not counted (default 120)")
    parser.add_argument("--summary-file", type=Path, help="also write the JSON summary to this file")
    parser.add_argument("--allow-non-loopback", action="store_true",
                        help="permit a PENNILOGIC_BIND_ADDRESS that is not a loopback address")
    parser.add_argument("--verbose", action="store_true", help="show docker/compose stderr while running")
    return parser


def emit(summary, summary_file):
    text = json.dumps(summary, indent=2)
    if summary_file:
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_file.write_text(text + "\n", encoding="utf-8")
    print(text, flush=True)


def run_up(compose, settings, ports, args, summary):
    summary.update(action_up(compose, settings, ports, args))
    summary["ok"] = True
    if args.smoke:
        smoke = smoke_infra.run(settings, timeout=min(args.timeout, 10.0))
        for record in smoke["services"]:
            note = "" if record["detail"] is None else f" - {record['detail']}"
            log(f"smoke {record['service']}: {record['status']} ({record['latency_ms']} ms){note}")
        summary["smoke"] = smoke
        if not smoke["ok"]:
            raise BootstrapError("smoke_failed", "The smoke probe failed; see the smoke records.")


def main(argv=None):
    args = build_parser().parse_args(argv)
    action = "status" if args.status else "down" if args.down else "reset" if args.reset else "up"
    summary = {"schema": SCHEMA, "action": action, "ok": False, "project": None,
               "services": empty_services(), "checks": {}, "warnings": [], "error": None}
    compose = None
    try:
        args.env_file = Path(args.env_file).expanduser().resolve()
        if args.summary_file:
            args.summary_file = Path(args.summary_file).expanduser().resolve()
        args.env_created = False
        # Settings are read once before the lock so the project name is known; `up` re-reads them
        # under the lock after possibly creating .env, so concurrent first runs share one file.
        settings = smoke_infra.load_settings(args.env_file)
        project = resolve_project(args.project, settings)
        summary["project"] = project
        if action == "status":
            ports = validate_settings(settings, args.allow_non_loopback, require_password=False)
            compose = Compose(project, args.env_file, os.environ, smoke_infra.secret_values(settings), args.verbose)
            compose.engine_version()
            summary.update(action_status(compose))
        else:
            with ProjectLock(project):
                if action == "up":
                    args.env_created = ensure_env_file(args.env_file)
                    if args.env_created:
                        log(f"created {args.env_file} from {ENV_EXAMPLE.name} with a generated development password")
                    settings = smoke_infra.load_settings(args.env_file)
                ports = validate_settings(settings, args.allow_non_loopback, require_password=action == "up")
                compose = Compose(project, args.env_file, os.environ, smoke_infra.secret_values(settings), args.verbose)
                compose.engine_version()
                if action == "up":
                    run_up(compose, settings, ports, args, summary)
                else:
                    summary.update(action_down(compose, destroy_volumes=action == "reset"))
    except BootstrapError as error:
        summary.update(error.details.pop("summary", {}))
        message = compose.redact(str(error)) if compose else str(error)
        summary["ok"] = False
        summary["error"] = {"kind": error.kind, "message": message, **error.details}
        log(message)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        message = compose.redact(str(error)) if compose else str(error)
        summary["ok"] = False
        summary["error"] = {"kind": "io_error", "message": f"{type(error).__name__}: {message}"}
        log(message)
    except KeyboardInterrupt:
        summary["error"] = {"kind": "interrupted", "message": "Interrupted."}
        emit(summary, args.summary_file)
        return 130
    emit(summary, args.summary_file)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
