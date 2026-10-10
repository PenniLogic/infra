"""Planted-defect harness: plant one defect in a scratch checkout, run the profile's real command,
restore the tree byte for byte, and record whether the command refused the defect.

The acceptance this proves is "a repository whose test step is removed or stubbed fails the
conformance job": every fixture states which language it covers, which toolchain it needs and
which probes must exit non-zero. A fixture whose toolchain is not exercised in this run is
recorded as ``not_exercised`` with the reason; nothing is inferred. Precedents: the android
``quality_gates.py self-test`` and the contracts planted lint probes.

Safety: the harness refuses to plant into a tree that ``git status`` does not report clean,
restores every changed path in reverse order, and reports ``error`` (which fails the job) when
the tree is not clean again afterwards. Every probe, and every git command on a scratch checkout,
runs with ``probe_environment()``: an explicit deny-list of credential-bearing and runner-state
variables (plus a name heuristic behind it) is removed, git sees an empty global config and no
system config, ``gh`` sees an empty config directory, and cmd.exe does not resolve commands from
the consumer's working directory. File-based credentials outside those locations (SSH keys, OS
keyrings, package-manager rc files) are not covered; see CI_CONFORMANCE.md. Nothing here writes
to a remote.
"""

import atexit
import dataclasses
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from conformance import generator as generator_module, report, steps


LANGUAGES = ("workflow", "python", "documentation", "typescript", "kotlin")
TOOLCHAINS = ("python", "node", "uv", "java", "android")
DEFAULT_EXERCISE = ("python",)
COMMAND_TIMEOUT_SECONDS = 900
OUTPUT_TAIL = 3000
RECORDED_TAIL = 400
POSIX_TEARDOWN_SECONDS = 5
UNITTEST_COMMAND = re.compile(r"python -m unittest discover -s (\S+)")
UNITTEST_FAILURE = re.compile(
    r"(?m)^FAIL: test_planted_defect_must_fail "
    r"\(test_planted_conformance_defect_[0-9]+\.PlantedConformanceDefect\.test_planted_defect_must_fail\)\r?$"
)
# Removed from every child environment (names compared upper-case, as Windows does). The names and
# prefixes carry credentials, point git/ssh/gh at credential sources, or let a child write state the
# Actions runner reads in later steps (GITHUB_ENV, GITHUB_PATH, ACTIONS_RUNTIME_TOKEN).
DENIED_VARIABLES = frozenset({
    "GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND", "GIT_TERMINAL_PROMPT",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "NODE_AUTH_TOKEN", "NPM_TOKEN", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL",
    "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_GITHUB_TOKEN", "UV_PUBLISH_TOKEN", "UV_PUBLISH_PASSWORD",
    "UV_PUBLISH_USERNAME", "DOCKER_AUTH_CONFIG", "KUBECONFIG", "VAULT_TOKEN", "CARGO_REGISTRY_TOKEN", "HF_TOKEN",
})
DENIED_PREFIXES = (
    "GH_", "GITHUB_", "ACTIONS_", "GIT_CONFIG_", "SSH_", "AWS_", "AZURE_", "GOOGLE_", "DOCKER_", "NUGET_",
    "TWINE_", "PYPI_", "NPM_CONFIG_", "ORG_GRADLE_PROJECT_", "OPENAI_", "ANTHROPIC_",
)
# Tripwire behind the deny-list: a name that looks like a credential is removed even when unlisted.
CREDENTIAL_VARIABLE = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|PRIVATE_KEY|_KEY$", re.IGNORECASE)
_ISOLATION = None
_WINDOWS_HELPERS = None
_UNCONFIRMED_PROCESS = False
WINDOWS_GATE = """import json
import subprocess
import sys

if sys.stdin.buffer.read(1) != b"1":
    sys.exit(2)
command = json.loads(sys.argv[1])
try:
    result = subprocess.run(command, shell=isinstance(command, str), check=False,
                            stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stdout)
except OSError as error:
    json.dump({"error": error.__class__.__name__}, sys.stderr)
else:
    json.dump({"exit_code": result.returncode}, sys.stderr)
"""
PLANTED_PYTHON_TEST = '''"""Planted by the PenniLogic conformance job; never committed."""

import json
import os
import stat
import unittest


class PlantedConformanceDefect(unittest.TestCase):
    def run(self, result=None):
        result = super().run(result)
        # Observe the recorded TestResult, not an assertion message or an attempted self.fail.
        failed = any(test is self for test, _ in result.failures)
        document = {"nonce": __WITNESS_NONCE__, "test": self.id(), "failed": failed}
        with open(__WITNESS_PATH__, "r+b") as witness:
            info = os.fstat(witness.fileno())
            if ((info.st_dev, info.st_ino) != __WITNESS_ID__ or not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1):
                raise RuntimeError("unittest witness ownership changed")
            if witness.read(1):
                raise RuntimeError("unittest witness was already populated")
            witness.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii"))
        return result

    def test_planted_defect_must_fail(self):
        self.fail("planted defect")
'''
PLANTED_PYTEST = '''"""Planted by the PenniLogic conformance job; never committed."""


def test_planted_defect_must_fail() -> None:
    raise AssertionError("planted defect")
'''
PLANTED_VITEST = """// Planted by the PenniLogic conformance job; never committed.
import { expect, test } from 'vitest';

test('planted defect must fail', () => {
  expect('planted defect').toBe('refused');
});
"""
PLANTED_JUNIT = """// Planted by the PenniLogic conformance job; never committed.
package com.pennilogic

import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class PlantedConformanceDefectTest {
    @Test
    fun `planted defect must fail`() {
        fail<Unit>("planted defect")
    }
}
"""


@dataclasses.dataclass
class Result:
    exit_code: object
    output: str
    timed_out: bool = False
    error: str = None
    restoration_safe: bool = True
    failure_evidence: str = ""
    elapsed_seconds: float | None = None
    process_cleanup: dict | None = None


class UnsafeProcessTreeError(RuntimeError):
    """The caller must retain the planted tree because process exit could not be confirmed."""

    def __init__(self, message, result=None, command=None):
        super().__init__(message)
        self.result = result
        self.command = command


@dataclasses.dataclass
class Probe:
    """One command run against the planted tree.

    ``expect`` is ``fail`` (the command must exit non-zero, with ``expect_text`` in its output when
    given), ``consumer`` (a consumer-owned self-test that must exit 0; its success is recorded as the
    consumer's evidence, never as a defect this job proved) or ``observe`` (recorded, never required).
    ``expect_exit_code`` additionally pins the failure code when the fixture requires one.
    Indexed unittest failure headings require validated TestResult evidence, never an output substring.
    ``detail_text`` is recorded when present in the output but never required: the checker template
    surfaces its rule text only since PR E (#50), and a consumer that has not regenerated still
    refuses correctly.
    """
    label: str
    command: object          # argv list (run directly) or one shell line (the profile's own wording)
    expect: str = "fail"
    expect_text: str = None
    detail_text: str = None
    note: str = None
    expect_exit_code: int | None = None


@dataclasses.dataclass
class Fixture:
    id: str
    language: str
    toolchain: str
    description: str
    applies: object          # callable(context) -> bool
    plant: object            # callable(context, planter) -> None
    probes: object           # callable(context) -> list[Probe]
    prepare: object = None   # callable(context) -> list[command] run before planting (installs)


@dataclasses.dataclass
class Context:
    name: str
    profile: dict
    root: object             # Path of the scratch checkout
    infra_root: object       # Path of the PenniLogic/infra checkout running the job


def denied_variable(name):
    upper = name.upper()
    return (upper in DENIED_VARIABLES or upper.startswith(DENIED_PREFIXES)
            or CREDENTIAL_VARIABLE.search(name) is not None)


def _cleanup_isolation(directory):
    if not _UNCONFIRMED_PROCESS:
        try:
            shutil.rmtree(directory)
        except OSError as error:
            print(f"Conformance isolated configuration cleanup failed ({error.__class__.__name__}); "
                  "remaining configuration retained", file=sys.stderr)


def isolation_directory():
    """A process-wide temporary directory with an empty git config file and an empty gh config dir."""
    global _ISOLATION
    if _ISOLATION is None or not os.path.isdir(_ISOLATION):
        _ISOLATION = tempfile.mkdtemp(prefix="pennilogic-conformance-env-")
        with open(os.path.join(_ISOLATION, "gitconfig"), "wb"):
            pass
        os.mkdir(os.path.join(_ISOLATION, "gh"))
        atexit.register(_cleanup_isolation, _ISOLATION)
    return _ISOLATION


def probe_environment(environ=None):
    """The environment every probe and scratch git command receives.

    The deny-list and the credential-name tripwire are removed; git reads an empty global config and
    no system config, so no credential helper, askpass program or URL rewrite from the operator's
    files applies; ``gh`` reads an empty config directory, so its stored hosts file is unreachable;
    cmd.exe does not resolve a bare command name from the consumer's working directory.
    """
    environ = os.environ if environ is None else environ
    cleaned = {key: value for key, value in environ.items() if not denied_variable(key)}
    isolation = isolation_directory()
    cleaned.update(
        PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", CI="1",
        GIT_CONFIG_GLOBAL=os.path.join(isolation, "gitconfig"), GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0", GH_CONFIG_DIR=os.path.join(isolation, "gh"),
        NoDefaultCurrentDirectoryInExePath="1",
    )
    return cleaned


def windows_helpers():
    """Load only infra's process-lifetime helpers, never a module from the consumer checkout."""
    global _WINDOWS_HELPERS
    if _WINDOWS_HELPERS is None:
        path = Path(__file__).resolve().parents[2] / "scripts" / "bootstrap.py"
        spec = importlib.util.spec_from_file_location("conformance_bootstrap", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _WINDOWS_HELPERS = module
    return _WINDOWS_HELPERS


def _stop_unowned_gate(helpers, process):
    deadline = time.monotonic() + helpers.TEARDOWN_SECONDS
    try:
        process.kill()
        released = helpers.release_pipes(process, max(0.0, deadline - time.monotonic()))
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
        return released
    except (OSError, subprocess.TimeoutExpired):
        return False


def _finish_windows_tree(helpers, job, process):
    deadline = time.monotonic() + helpers.TEARDOWN_SECONDS
    fallback_seconds = min(0.25, helpers.TEARDOWN_SECONDS / 2)
    try:
        helpers.terminate_tree(job, process, deadline - fallback_seconds,
                               require_exit=True, label="probe")
    except helpers.ProcessTeardownError as error:
        detail = str(error)
    except (OSError, RuntimeError) as error:
        detail = f"Windows process-tree teardown failed: {error.__class__.__name__}"
    else:
        return None
    # Kill-on-close is the last resort, not confirmation; reserve time to reap the launcher without
    # extending the same teardown deadline or blocking on a reader whose pipe was not released.
    job.close()
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
        helpers.release_pipes(process, max(0.0, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        detail += "; launcher exit or pipe release still unconfirmed"
    return detail


def _capture_redactor(cwd, replacements=None, credentials=None):
    replacements = (report.path_replacements(cwd, Path(__file__).resolve().parents[2])
                    if replacements is None else replacements)
    credentials = report.credential_values() if credentials is None else credentials
    return lambda text: report.redact_text(text, replacements, credentials)


class _UnittestWitness:
    """One private, single-use result record for one indexed discovery command."""

    def __init__(self, directory, case_id):
        self.directory = Path(directory)
        self.directory_id = self._identity(self.directory.lstat())
        self.nonce = uuid.uuid4().hex
        self.path = self.directory / f"{self.nonce}.json"
        self.case_id = case_id
        self.heading = f"FAIL: test_planted_defect_must_fail ({case_id})"
        self.responses = {
            json.dumps({"nonce": self.nonce, "test": case_id, "failed": failed},
                       sort_keys=True, separators=(",", ":")).encode("ascii"): failed
            for failed in (False, True)
        }
        self.limit = max(map(len, self.responses))
        self.armed = False
        self.consumed = False
        with self.path.open("xb") as stream:
            self.file_id = self._identity(os.fstat(stream.fileno()))

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino

    def _check(self, info, identity, directory=False):
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (self._identity(info) != identity or not kind(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
                or (not directory and info.st_nlink != 1)):
            raise ValueError("unsafe unittest witness path")

    def _read(self):
        self._check(self.directory.lstat(), self.directory_id, directory=True)
        info = self.path.lstat()
        self._check(info, self.file_id)
        if info.st_size > self.limit:
            raise ValueError("oversized unittest witness")
        with self.path.open("rb") as stream:
            self._check(os.fstat(stream.fileno()), self.file_id)
            data = stream.read(self.limit + 1)
        self._check(self.path.lstat(), self.file_id)
        if len(data) > self.limit or len(data) != info.st_size:
            raise ValueError("unittest witness changed during capture")
        return data

    def arm(self):
        if self.armed or self.consumed or self._read():
            raise ValueError("stale unittest witness")
        self.armed = True

    def consume(self, result, cwd):
        result = dataclasses.replace(result, failure_evidence="")
        if (result.error or result.timed_out or not result.restoration_safe
                or result.exit_code != 1):
            return result
        try:
            if not self.armed or self.consumed:
                raise ValueError("unarmed or consumed unittest witness")
            self.consumed = True
            data = self._read()
            if data not in self.responses:
                raise ValueError("missing, malformed or mismatched unittest witness")
            heading = _capture_redactor(cwd)(self.heading) if self.responses[data] else ""
            evidence = heading[:RECORDED_TAIL] if heading == self.heading else ""
            return dataclasses.replace(result, failure_evidence=evidence)
        except (OSError, ValueError) as error:
            detail = str(error) if isinstance(error, ValueError) else error.__class__.__name__
            return dataclasses.replace(result, error=f"unittest witness refused: {detail}")


def _captured_output(output, redact_output):
    # Printed diagnostics, including complete quoted reports, are never unittest attribution.
    text = redact_output(output.decode("utf-8", errors="replace"))
    return {"output": text[-OUTPUT_TAIL:], "failure_evidence": ""}


def _windows_runner(command, cwd, environ, timeout, redact_output=None):
    redact_output = _capture_redactor(cwd) if redact_output is None else redact_output
    helpers = windows_helpers()
    try:
        job = helpers.WindowsJob()
    except helpers.ProcessOwnershipError as error:
        detail = f"Windows process ownership failed: {error}; no consumer was started"
        return Result(None, detail, error=detail)
    with job:
        process, owned = None, False
        try:
            # Isolated trusted Python waits for input; consumer code cannot start until job assignment.
            process = subprocess.Popen([sys.executable, "-I", "-S", "-u", "-c", WINDOWS_GATE, json.dumps(command)],
                                       cwd=str(cwd), env=environ, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            job.assign(process.pid)
            owned = True
            output, control = process.communicate(b"1", timeout=timeout)
        except helpers.ProcessOwnershipError as error:
            stopped = process is None or _stop_unowned_gate(helpers, process)
            detail = f"Windows process ownership failed: {error}"
            if not stopped:
                detail += "; idle launcher exit or pipe release not confirmed"
            return Result(None, detail, error=detail, restoration_safe=stopped)
        except subprocess.TimeoutExpired as expired:
            detail = _finish_windows_tree(helpers, job, process)
            # Windows reader threads populate their buffers only at EOF; after confirmed release,
            # collect the cached output without an additional drain wait.
            output = process.communicate(timeout=0)[0] if detail is None else expired.output or b""
            return Result(None, **_captured_output(output, redact_output), timed_out=True, error=detail,
                          restoration_safe=detail is None)
        except OSError as error:
            stopped = (_finish_windows_tree(helpers, job, process) is None if owned else
                       process is None or _stop_unowned_gate(helpers, process))
            detail = f"{error.__class__.__name__}: command could not start"
            if not stopped:
                detail += "; process-tree teardown not confirmed"
            return Result(None, detail, error=detail, restoration_safe=stopped)
        except BaseException:
            stopped = (_finish_windows_tree(helpers, job, process) is None if owned else
                       process is None or _stop_unowned_gate(helpers, process))
            if not stopped:
                raise UnsafeProcessTreeError("interrupted probe process-tree exit not confirmed") from None
            raise
        detail = _finish_windows_tree(helpers, job, process)
        output = _captured_output(output, redact_output)
        if detail is not None:
            return Result(None, **output, error=detail, restoration_safe=False)
        try:
            status = json.loads(control.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return Result(None, **output, error="isolated probe gate returned an invalid status")
        if not isinstance(status, dict) or ("error" not in status and type(status.get("exit_code")) is not int):
            return Result(None, **output, error="isolated probe gate returned an invalid status")
        if "error" in status:
            detail = f"{status['error']}: command could not start"
            return Result(None, detail, error=detail)
        return Result(status["exit_code"], **output)


def _finish_posix_group(process, output=b""):
    """Signal only the new session's unreaped leader group; this cannot contain detached descendants."""
    deadline = time.monotonic() + POSIX_TEARDOWN_SECONDS
    cleanup = {"process_group_signal": "not attempted",
               "leader_exit_confirmed": False, "pipes_released": False, "descendant_exit_confirmed": False}
    # Before reaping, our child reserves its PID/PGID. Afterwards it could belong to an unrelated
    # process: never signal a group identifier after communicate()/wait() has reaped its leader.
    try:
        if process.returncode is None:
            cleanup["process_group_signal"] = "attempted: result unconfirmed"
            try:
                os.killpg(process.pid, signal.SIGKILL)
                cleanup["process_group_signal"] = "sent"
            except OSError as error:
                cleanup["process_group_signal"] = f"failed: {error.__class__.__name__}"
                try:
                    process.kill()
                except OSError as stopped:
                    cleanup["leader_signal_error"] = stopped.__class__.__name__
        else:
            cleanup["process_group_signal"] = "not sent: leader already reaped"
        try:
            output = process.communicate(timeout=max(0.0, deadline - time.monotonic()))[0]
            cleanup["pipes_released"] = True
        except subprocess.TimeoutExpired as expired:
            output = expired.output or output
        except OSError as error:
            cleanup["pipe_error"] = error.__class__.__name__
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired) as error:
            cleanup["leader_wait_error"] = error.__class__.__name__
    except BaseException as error:
        cleanup["teardown_interrupted"] = error.__class__.__name__
    cleanup["leader_exit_confirmed"] = process.returncode is not None
    return output, cleanup


def _posix_runner(command, cwd, environ, timeout, redact_output):
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        detail = "POSIX ownership requires the default SIGCHLD handler; no consumer was started"
        return Result(None, detail, error=detail)
    process = None
    try:
        process = subprocess.Popen(
            command, cwd=str(cwd), shell=isinstance(command, str), env=environ, start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        output = process.communicate(timeout=timeout)[0]
    except BaseException as error:
        if process is None and isinstance(error, OSError):
            raise
        timed_out = isinstance(error, subprocess.TimeoutExpired)
        output = (error.output or b"") if timed_out else b""
        cleanup = None
        if process is not None:
            output, cleanup = _finish_posix_group(process, output)
        reason = "timeout" if timed_out else f"interrupted ({error.__class__.__name__})"
        detail = f"POSIX {reason}: descendant exit is not confirmed; scratch restoration is unsafe"
        result = Result(None, **_captured_output(output, redact_output), timed_out=timed_out, error=detail,
                        restoration_safe=False, process_cleanup=cleanup)
        raise UnsafeProcessTreeError(detail, result, command) from None
    return Result(process.returncode, **_captured_output(output, redact_output))


def subprocess_runner(command, cwd, timeout=COMMAND_TIMEOUT_SECONDS, *, replacements=None, credentials=None):
    """Redact before the first capture tail; on Windows own the lifetime before releasing consumer code."""
    global _UNCONFIRMED_PROCESS
    started = time.monotonic()
    redact_output = _capture_redactor(cwd, replacements, credentials)
    try:
        if os.name == "nt":
            result = _windows_runner(command, cwd, probe_environment(), timeout, redact_output)
        else:
            result = _posix_runner(command, cwd, probe_environment(), timeout, redact_output)
    except subprocess.TimeoutExpired as expired:
        detail = "probe timed out outside confirmed teardown; scratch restoration is unsafe"
        result = Result(None, **_captured_output(expired.output or b"", redact_output), timed_out=True,
                        error=detail, restoration_safe=False)
    except UnsafeProcessTreeError as error:
        result = error.result or Result(None, "", error=str(error), restoration_safe=False)
    except OSError as error:
        detail = f"{error.__class__.__name__}: command could not start"
        result = Result(None, detail, error=detail)
    except BaseException:
        _UNCONFIRMED_PROCESS = True
        raise
    result = dataclasses.replace(result, elapsed_seconds=time.monotonic() - started)
    if not result.restoration_safe:
        _UNCONFIRMED_PROCESS = True
        raise UnsafeProcessTreeError(result.error or "probe process-tree exit not confirmed", result, command)
    return result


def git_status(root, run=subprocess.run):
    result = run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
                 capture_output=True, check=False, env=probe_environment(), timeout=120)
    if result.returncode:
        raise RuntimeError("git status failed in the scratch checkout")
    return sorted(line for line in result.stdout.decode("utf-8", errors="replace").splitlines() if line)


class Planter:
    """Records every change made while planting so ``restore`` can undo it in reverse order."""

    def __init__(self, root):
        self.root = root
        self._undo = []
        self._aside = None
        self._backups = {}
        self._unittest_witnesses = {}
        self.cleanup_error = None

    def _path(self, relative):
        path = self.root / relative
        if self.root.resolve() not in path.resolve().parents:
            raise ValueError("planted path escapes the scratch checkout")
        return path

    def write(self, relative, content):
        path = self._path(relative)
        if path.exists():
            original = path.read_bytes()
            self._undo.append(lambda: path.write_bytes(original))
        else:
            self._undo.append(lambda: path.unlink(missing_ok=True))
            created = []
            parent = path.parent
            while not parent.exists():
                created.append(parent)
                parent = parent.parent
            for directory in reversed(created):
                directory.mkdir()
                self._undo.append(lambda d=directory: shutil.rmtree(d))
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    def create(self, relative, content):
        if self._path(relative).exists():
            raise FileExistsError("refusing to overwrite an existing file for a planted defect")
        self.write(relative, content)

    def edit_text(self, relative, transform):
        path = self._path(relative)
        text = path.read_text(encoding="utf-8")
        changed = transform(text)
        if changed == text:
            raise ValueError("planted edit changed nothing")
        self.write(relative, changed)

    def edit_json(self, relative, transform):
        path = self._path(relative)
        document = json.loads(path.read_text(encoding="utf-8"))
        transform(document)
        self.write(relative, json.dumps(document, indent=2) + "\n")

    def move_aside(self, relative):
        path = self._path(relative)
        if not path.exists():
            raise FileNotFoundError("planted removal of a path that does not exist")
        if self._aside is None:
            self._aside = tempfile.mkdtemp(prefix="pennilogic-conformance-aside-")
        target = os.path.join(self._aside, uuid.uuid4().hex)
        shutil.move(str(path), target)
        self._backups[target] = relative

        def undo():
            shutil.move(target, str(path))
            del self._backups[target]

        self._undo.append(undo)

    def cleanup_state(self, error):
        state = {"directory": self._aside, "error": error}
        if self._backups:
            state["backups"] = [{"file": Path(path).name, "restore_to": str(relative)}
                                for path, relative in self._backups.items()]
        return state

    def restore(self):
        """Undo every recorded change in reverse order; a step that raises does not stop the others,
        backup cleanup is attempted without suppressing errors, and the first error is re-raised.
        A failed cleanup retains its location and error independently of consumer-file restoration."""
        first = None
        self.cleanup_error = None
        while self._undo:
            step = self._undo.pop()
            try:
                step()
            except OSError as error:
                first = first if first is not None else error
        if self._aside is not None:
            try:
                if self._backups:
                    os.rmdir(self._aside)  # never delete the only copy of a file whose undo failed
                else:
                    shutil.rmtree(self._aside)
            except OSError as error:
                self.cleanup_error = error
                first = first if first is not None else error
            else:
                self._aside = None
        if first is not None:
            raise first


def unittest_directories(profile):
    return [match.group(1) for command in profile["commands"]
            for match in [UNITTEST_COMMAND.search(command)] if match]


def unittest_commands(profile):
    return [command for command in profile["commands"] if UNITTEST_COMMAND.search(command)]


def has_command(profile, pattern):
    return any(re.search(pattern, command) for command in profile["commands"])


def run_checks_step(document):
    for job in document["jobs"].values():
        for step in job["steps"]:
            if step.get("name") == "Run checks":
                return step
    raise ValueError("the workflow has no Run checks step")


def drift_probe(context):
    command = [sys.executable, str(context.infra_root / "governance" / "generate.py"),
               "--repository", context.name, "--root", str(context.root), "--check"]
    return Probe("generator drift check: generate.py --repository <profile> --root <scratch> --check",
                 command, expect="fail", expect_text=".github/workflows/ci.yml")


def checker_probe(label="consumer scripts/check_repository.py", expect="fail", rule=None, note=None):
    """The consumer's own checker must refuse (exit 1 with its refusal line); the rule text is recorded."""
    return Probe(label, [sys.executable, "scripts/check_repository.py"], expect=expect,
                 expect_text="Invalid or unsafe workflow" if expect == "fail" else None, detail_text=rule, note=note)


def workflow_fixture(fixture_id, description, transform, extra_probes):
    def plant(context, planter):
        planter.edit_json(".github/workflows/ci.yml", lambda document: transform(context, document))

    def probes(context):
        return [drift_probe(context), *extra_probes(context)]

    return Fixture(fixture_id, "workflow", "python", description, lambda context: True, plant, probes)


def _remove_test_lines(context, document):
    step = run_checks_step(document)
    lines = step["run"].split("\n")
    kept = [line for line in lines if "test" not in steps.classify(line)]
    if kept == lines:
        raise ValueError("the profile has no test command to remove")
    step["run"] = "\n".join(kept)


def _stub_run_checks(context, document):
    run_checks_step(document)["run"] = "echo tests skipped"


def _condition_on_run_checks(context, document):
    run_checks_step(document)["if"] = "false"


def _unpin_checkout(context, document):
    for job in document["jobs"].values():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                step["uses"] = "actions/checkout@v4"
                return
    raise ValueError("the workflow has no checkout step")


def _reusable_workflow_job(context, document):
    document["jobs"]["reuse"] = {"uses": "PenniLogic/infra/.github/workflows/ci.yml@" + "0" * 40}


def _continue_on_error(context, document):
    run_checks_step(document)["continue-on-error"] = True


def _plant_continue_on_error(context, planter):
    generator = generator_module.load(context.infra_root / "governance" / "generate.py")
    checker = generator.checker(context.name)
    namespace = {"__name__": "conformance_current_checker",
                 "__file__": str(context.root / "scripts" / "check_repository.py")}
    exec(compile(checker, "<current rendered checker>", "exec"), namespace)
    try:
        namespace["validate_workflow"](
            ".github/workflows/ci.yml", (context.root / ".github" / "workflows" / "ci.yml").read_bytes(),
        )
    except ValueError as error:
        raise ValueError("current rendered checker refuses the unmodified workflow") from error
    planter.edit_json(".github/workflows/ci.yml", lambda document: _continue_on_error(context, document))
    planter.write("scripts/check_repository.py", checker)


def _continue_on_error_probe(context):
    rule = "step-level key outside the generated step keys"
    if context.name in ("api", "infra"):
        name = "API" if context.name == "api" else "Infra"
        rule = f"{name} CI must match its generated qualification jobs and required result"
    return Probe(
        "current rendered check_repository.py over the scratch tree",
        [sys.executable, "scripts/check_repository.py"], expect="fail", expect_text=rule, expect_exit_code=1,
        note="the current generator renders this profile's checker, including its exact workflow bindings",
    )


def _plant_python_removed(context, planter):
    for directory in unittest_directories(context.profile):
        files = sorted((context.root / directory).glob("test*.py"))
        if not files:
            raise ValueError("no test modules to remove")
        for path in files:
            planter.move_aside(path.relative_to(context.root).as_posix())


def _plant_python_failing(context, planter):
    if planter._aside is None:
        planter._aside = tempfile.mkdtemp(prefix="pennilogic-conformance-aside-")
    for index, (directory, command) in enumerate(zip(
            unittest_directories(context.profile), unittest_commands(context.profile))):
        module = f"test_planted_conformance_defect_{index}"
        witness = _UnittestWitness(
            planter._aside, f"{module}.PlantedConformanceDefect.test_planted_defect_must_fail",
        )
        planter._unittest_witnesses[command] = witness
        source = (PLANTED_PYTHON_TEST
                  .replace("__WITNESS_NONCE__", repr(witness.nonce))
                  .replace("__WITNESS_PATH__", repr(str(witness.path)))
                  .replace("__WITNESS_ID__", repr(witness.file_id)))
        planter.create(f"{directory}/{module}.py", source)


def _unittest_probes(expect_text, expect_exit_code):
    def probes(context):
        return [Probe(f"profile command: {command}", command, expect="fail", expect_text=expect_text,
                      expect_exit_code=expect_exit_code)
                for command in unittest_commands(context.profile)]
    return probes


def _unittest_failing_probes(context):
    return [
        Probe(f"profile command: {command}", command, expect="fail", expect_exit_code=1,
              expect_text="FAIL: test_planted_defect_must_fail "
                          f"(test_planted_conformance_defect_{index}.PlantedConformanceDefect.test_planted_defect_must_fail)")
        for index, command in enumerate(unittest_commands(context.profile))
    ]


def _unittest_prepare(context):
    # Contracts' unittest suite invokes the npm-backed lint and pinned generator/diff tools.
    if has_command(context.profile, r"\bpython scripts/lint_spec\.py\b"):
        return context.profile.get("install", [])
    return []


def _pytest_command(profile):
    return next(command for command in profile["commands"] if re.search(r"\bpytest\b", command))


def _pytest_prepare(context):
    return [command for command in context.profile.get("install", []) if "uv sync" in command]


def _pytest_probe(context, expect_text):
    command = _pytest_command(context.profile)
    return [Probe(f"profile command: {command}", command, expect="fail", expect_text=expect_text)]


def _plant_pytest_failing(context, planter):
    planter.create("tests/test_planted_conformance_defect.py", PLANTED_PYTEST)


def _plant_pytest_removed(context, planter):
    files = sorted((context.root / "tests").rglob("test_*.py"))
    if not files:
        raise ValueError("no pytest modules to remove")
    for path in files:
        planter.move_aside(path.relative_to(context.root).as_posix())


def _vitest_directory(context):
    return "tests/unit" if (context.root / "tests" / "unit").is_dir() else "tests"


def _plant_vitest_failing(context, planter):
    planter.create(f"{_vitest_directory(context)}/planted-conformance-defect.test.ts", PLANTED_VITEST)


def _plant_vitest_removed(context, planter):
    files = sorted(path for suffix in ("*.test.ts", "*.test.tsx") for path in (context.root / "tests").rglob(suffix))
    if not files:
        raise ValueError("no vitest modules to remove")
    for path in files:
        planter.move_aside(path.relative_to(context.root).as_posix())


def _npm_prepare(context):
    return [command for command in context.profile.get("install", []) if command.startswith("npm ci")]


def _plant_junit_failing(context, planter):
    planter.create("src/test/kotlin/com/pennilogic/PlantedConformanceDefectTest.kt", PLANTED_JUNIT)


def _plant_docs_index_link(context, planter):
    planter.edit_text("adr/README.md",
                      lambda text: text.replace("[ADR-001.md](ADR-001.md)", "[ADR-001.md](ADR-001-missing.md)", 1))


def _plant_docs_dangling_supersedes(context, planter):
    planter.edit_text("adr/ADR-015.md", lambda text: text.replace("supersedes: null", "supersedes: ADR-099", 1))


def _plant_docs_body_link(context, planter):
    planter.edit_text("README.md", lambda text: text + "\n[planted broken link](planted-missing-target.md)\n")


def _docs_probe(expect="fail", expect_text="Documentation check failed", note=None):
    return Probe("profile command: python scripts/check_docs.py", "python scripts/check_docs.py",
                 expect=expect, expect_text=expect_text, note=note)


FIXTURES = (
    workflow_fixture(
        "workflow-test-step-removed",
        "every test command is deleted from the Run checks step of the rendered ci.yml",
        _remove_test_lines,
        lambda context: [checker_probe(expect="observe", note="the checker validates shape and token boundaries, not which commands run; the drift check is the tripwire for a removed command")],
    ),
    workflow_fixture(
        "workflow-test-step-stubbed",
        "the Run checks step is replaced by an echo that always succeeds",
        _stub_run_checks,
        lambda context: [checker_probe(expect="observe", note="a stubbed command is caught by the drift check, not by the checker")],
    ),
    workflow_fixture(
        "workflow-step-skipped-by-condition",
        "an `if: false` condition is added to the Run checks step",
        _condition_on_run_checks,
        lambda context: [checker_probe(rule="conditions are not part of the generated workflows")],
    ),
    workflow_fixture(
        "workflow-unpinned-action",
        "actions/checkout is referenced by the moving tag v4 instead of a commit",
        _unpin_checkout,
        lambda context: [checker_probe(rule="action must be immutable")],
    ),
    workflow_fixture(
        "workflow-reusable-workflow-job",
        "a job consumes a reusable workflow through jobs.<id>.uses (the adoption model PR D refused)",
        _reusable_workflow_job,
        lambda context: [checker_probe(rule="action must be immutable")],
    ),
    Fixture(
        "workflow-step-continue-on-error", "workflow", "python",
        "continue-on-error: true is added to the Run checks step; refused by the current rendered checker and by the drift check",
        lambda context: True, _plant_continue_on_error,
        lambda context: [drift_probe(context), _continue_on_error_probe(context)],
    ),
    Fixture(
        "python-tests-removed", "python", "python",
        "every test module of each unittest start directory is removed; unittest exits 5 (NO TESTS RAN)",
        lambda context: bool(unittest_directories(context.profile)), _plant_python_removed,
        _unittest_probes("NO TESTS RAN", 5),
    ),
    Fixture(
        "python-test-failing", "python", "python",
        "a distinct failing unittest module is planted in each start directory and each unchanged command must report its own failure",
        lambda context: bool(unittest_directories(context.profile)), _plant_python_failing,
        _unittest_failing_probes, prepare=_unittest_prepare,
    ),
    Fixture(
        "python-pytest-failing", "python", "uv",
        "a failing pytest module is planted under tests/ and the locked uv pytest command must fail",
        lambda context: has_command(context.profile, r"\bpytest\b"), _plant_pytest_failing,
        lambda context: _pytest_probe(context, "test_planted_defect_must_fail"),
        prepare=_pytest_prepare,
    ),
    Fixture(
        "python-pytest-removed", "python", "uv",
        "every pytest module under tests/ is removed; pytest exits 5 (no tests collected)",
        lambda context: has_command(context.profile, r"\bpytest\b"), _plant_pytest_removed,
        lambda context: _pytest_probe(context, "no tests ran"),
        prepare=_pytest_prepare,
    ),
    Fixture(
        "documentation-index-link-broken", "documentation", "python",
        "an ADR index link in adr/README.md points at a file that does not exist",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_index_link,
        lambda context: [_docs_probe(expect_text="generated slot ADR-001 differs")],
    ),
    Fixture(
        "documentation-dangling-supersedes", "documentation", "python",
        "ADR-015 claims to supersede ADR-099, a record that does not exist",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_dangling_supersedes,
        lambda context: [_docs_probe(expect_text="supersedes ADR-099, which has no source record")],
    ),
    Fixture(
        "documentation-body-link-broken", "documentation", "python",
        "a relative Markdown link outside the ADR graph points at a missing file; recorded to show what check_docs.py does not cover",
        lambda context: has_command(context.profile, r"\bcheck_docs\.py\b"), _plant_docs_body_link,
        lambda context: [_docs_probe(expect="observe", expect_text=None,
                                     note="check_docs.py validates the ADR graph, index and inventories, not arbitrary Markdown links; a general link checker is a separate docs decision")],
    ),
    Fixture(
        "typescript-test-failing", "typescript", "node",
        "a failing vitest module is planted under the tests directory and npm test must fail",
        lambda context: has_command(context.profile, r"^npm test\b"), _plant_vitest_failing,
        lambda context: [Probe("profile command: npm test", "npm test", expect="fail", expect_text="planted defect")],
        prepare=_npm_prepare,
    ),
    Fixture(
        "typescript-tests-removed", "typescript", "node",
        "every vitest module under tests/ is removed; vitest exits non-zero with no test files",
        lambda context: has_command(context.profile, r"^npm test\b"), _plant_vitest_removed,
        lambda context: [Probe("profile command: npm test", "npm test", expect="fail", expect_text="No test files found")],
        prepare=_npm_prepare,
    ),
    Fixture(
        "kotlin-test-failing", "kotlin", "java",
        "a failing JUnit 5 test is planted under src/test/kotlin and the Gradle test gate must fail",
        lambda context: has_command(context.profile, r"\bquality\.py build\b"), _plant_junit_failing,
        lambda context: [Probe("profile gate: python scripts/quality.py test", "python scripts/quality.py test",
                               expect="fail", expect_text="planted defect")],
    ),
    Fixture(
        "kotlin-android-self-test", "kotlin", "android",
        "consumer evidence: the consumer-owned quality_gates.py self-test plants a failing test, spotless and lint defects and reused results on every CI run",
        lambda context: has_command(context.profile, r"\bquality_gates\.py self-test\b"),
        lambda context, planter: None,
        lambda context: [Probe("consumer command: python scripts/quality_gates.py self-test",
                               "python scripts/quality_gates.py self-test", expect="consumer",
                               note="exit 0 is the consumer's own claim that its planted defects were refused; nothing here is planted by this job; needs the Android SDK")],
    ),
)


def applicable_fixtures(context, fixtures=FIXTURES):
    return [fixture for fixture in fixtures if fixture.applies(context)]


def probe_outcome(probe, result):
    """``as_expected``/``unexpected`` for a required probe, ``detected``/``not_detected`` for an observation."""
    if result.error or not result.restoration_safe or result.timed_out or result.exit_code is None:
        return "error"
    failed = result.exit_code != 0
    if probe.expect_text is not None and UNITTEST_FAILURE.fullmatch(probe.expect_text):
        matched = result.failure_evidence == probe.expect_text
    else:
        matched = (probe.expect_text is None or probe.expect_text in result.output
                   or probe.expect_text in result.failure_evidence)
    if probe.expect == "fail":
        code_matches = probe.expect_exit_code is None or result.exit_code == probe.expect_exit_code
        return "as_expected" if failed and code_matches and matched else "unexpected"
    if probe.expect in ("pass", "consumer"):
        return "as_expected" if not failed else "unexpected"
    return "detected" if failed else "not_detected"


def _probe_record(probe, result):
    record = {
        "label": probe.label, "command": probe.command, "expect": probe.expect,
        "expect_text": probe.expect_text, "detail_text": probe.detail_text, "note": probe.note,
        "exit_code": result.exit_code, "timed_out": result.timed_out, "outcome": probe_outcome(probe, result),
        "elapsed_seconds": result.elapsed_seconds,
        "detail_surfaced": None if probe.detail_text is None else probe.detail_text in result.output,
        "output_tail": result.output[-RECORDED_TAIL:],
    }
    if result.error:
        record["error"] = result.error
    if probe.expect_exit_code is not None:
        record["expect_exit_code"] = probe.expect_exit_code
    if result.failure_evidence:
        record["failure_evidence"] = result.failure_evidence
    if not result.restoration_safe:
        record["restoration_safe"] = False
    if result.process_cleanup is not None:
        record["process_cleanup"] = result.process_cleanup
    return record


def _run_probe(probe, root, runner):
    global _UNCONFIRMED_PROCESS
    result = None
    try:
        result = runner(probe.command, root)
    except UnsafeProcessTreeError as error:
        result = error.result or Result(None, "", error=str(error), restoration_safe=False)
    finally:
        if result is None or not result.restoration_safe:
            _UNCONFIRMED_PROCESS = True
    return result


def run_fixture(fixture, context, runner=subprocess_runner, exercise=DEFAULT_EXERCISE, status=git_status):
    """Plant, probe and restore one fixture; the returned record is what the report publishes.

    Outcomes: ``proved`` (every probe this job planted for behaved as required), ``consumer_evidence``
    (a consumer-owned self-test exited 0; recorded as the consumer's claim, not as proof by this job),
    ``not_proved``, ``recorded`` (only observations), ``not_exercised`` (toolchain excluded from this
    run) or ``error``.
    """
    record = {
        "id": fixture.id, "language": fixture.language, "toolchain": fixture.toolchain,
        "description": fixture.description, "outcome": None, "reason": None, "probes": [],
    }
    if fixture.toolchain not in exercise:
        record["outcome"] = "not_exercised"
        record["reason"] = f"toolchain {fixture.toolchain} not exercised in this run"
        return record
    try:
        before = status(context.root)
    except RuntimeError as error:
        record["outcome"], record["reason"] = "error", str(error)
        return record
    if before:
        record["outcome"], record["reason"] = "error", "scratch checkout is not clean before planting"
        return record
    for command in (fixture.prepare(context) if fixture.prepare else []):
        probe = Probe(f"prepare: {command}", command, expect="pass")
        result = _run_probe(probe, context.root, runner)
        record["probes"].append(_probe_record(probe, result))
        if result.error or not result.restoration_safe or result.exit_code != 0:
            record["outcome"], record["reason"] = "error", result.error or "prepare command failed"
            if not result.restoration_safe:
                record["restoration_deferred"] = True
            return record
    planter = Planter(context.root)
    restoration_safe = True
    try:
        fixture.plant(context, planter)
        for probe in fixture.probes(context):
            witness = planter._unittest_witnesses.get(probe.command) if isinstance(probe.command, str) else None
            if witness is not None:
                witness.arm()
            restoration_safe = False
            result = _run_probe(probe, context.root, runner)
            restoration_safe = result.restoration_safe
            if witness is not None:
                result = witness.consume(result, context.root)
            record["probes"].append(_probe_record(probe, result))
            if not restoration_safe or result.error or result.exit_code is None:
                break
    except UnsafeProcessTreeError as error:
        restoration_safe = False
        record["outcome"], record["reason"] = "error", str(error)
    except Exception as error:  # noqa: BLE001 - preserve fixture failures without assuming a crashed runner exited
        record["outcome"], record["reason"] = "error", f"planting failed: {error.__class__.__name__}: {error}"
    finally:
        if restoration_safe:
            try:
                planter.restore()
            except OSError as error:
                record["outcome"], record["reason"] = "error", f"restore failed: {error.__class__.__name__}"
                if planter.cleanup_error is not None:
                    record["reason"] += f"; backup cleanup failed: {planter.cleanup_error.__class__.__name__}"
                    record["cleanup"] = planter.cleanup_state(planter.cleanup_error.__class__.__name__)
        else:
            errors = [probe["error"] for probe in record["probes"] if probe.get("error")]
            detail = record["reason"] or "; ".join(errors) or "probe process-tree exit not confirmed"
            record["outcome"], record["reason"] = "error", detail + "; scratch restoration deferred"
            record["restoration_deferred"] = True
            if planter._aside is not None:
                record["cleanup"] = planter.cleanup_state("restoration deferred")
    if record.get("restoration_deferred"):
        return record
    try:
        after = status(context.root)
    except RuntimeError as error:
        record["outcome"], record["reason"] = "error", str(error)
        return record
    if after:
        detail = "scratch checkout was not restored after planting"
        record["reason"] = f"{record['reason']}; {detail}" if record["outcome"] == "error" and record["reason"] else detail
        record["outcome"] = "error"
        record["unrestored_paths"] = after
        return record
    if record["outcome"] == "error":
        return record
    required = [probe for probe in record["probes"] if probe["expect"] in ("fail", "pass", "consumer")]
    if any(probe["outcome"] == "error" for probe in record["probes"]):
        errors = [probe["error"] for probe in record["probes"] if probe.get("error")]
        record["outcome"], record["reason"] = "error", "; ".join(errors) or "a probe timed out or could not start"
    elif required and all(probe["outcome"] == "as_expected" for probe in required):
        # A fixture whose only required probes are consumer-owned commands proves nothing by itself.
        planted = any(probe["expect"] in ("fail", "pass") for probe in required)
        record["outcome"] = "proved" if planted else "consumer_evidence"
    elif required:
        record["outcome"] = "not_proved"
        record["reason"] = "a required probe did not behave as the fixture requires"
    else:
        record["outcome"] = "recorded"
    return record


def run_fixtures(context, runner=subprocess_runner, exercise=DEFAULT_EXERCISE, fixtures=FIXTURES, status=git_status):
    records = []
    for fixture in applicable_fixtures(context, fixtures):
        record = run_fixture(fixture, context, runner, exercise, status)
        records.append(record)
        if record.get("unrestored_paths") or record.get("cleanup") or record.get("restoration_deferred"):
            break
    return records


def language_coverage(records):
    """Per language: ``proved`` when at least one fixture was proved, else the weakest outcome seen."""
    rank = {"proved": 0, "recorded": 1, "consumer_evidence": 1, "not_exercised": 2, "not_proved": 3, "error": 4}
    coverage = {}
    for record in records:
        language, outcome = record["language"], record["outcome"]
        current = coverage.get(language)
        if current == "proved":
            continue
        if outcome == "proved" or current is None or rank[outcome] > rank[current]:
            coverage[language] = outcome
    return coverage
