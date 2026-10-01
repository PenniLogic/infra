"""Finite Windows process-tree regressions; every synthetic worker exits on its own as a fallback."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import conformance_support as support
from conformance import defects


WORKER = """import os
from pathlib import Path
import subprocess
import sys
import time

state = Path(sys.argv[1])
mode = sys.argv[2]
(state / (mode + '.pid')).write_text(str(os.getpid()), encoding='ascii')
print('WORKER_STARTED=' + str(os.getpid()), flush=True)
if mode == 'child':
    held = (state / 'held.txt').open('w')
    time.sleep(4)
    held.close()
    print('CHILD_COMPLETED', flush=True)
else:
    child = subprocess.Popen([sys.executable, __file__, str(state), 'child'],
                             stdout=subprocess.DEVNULL if mode == 'background' else sys.stdout,
                             stderr=subprocess.DEVNULL if mode == 'background' else sys.stderr)
    if mode == 'background':
        deadline = time.monotonic() + 2
        while not (state / 'held.txt').exists() and time.monotonic() < deadline:
            time.sleep(0.01)
    else:
        child.wait(timeout=8)
    print('PARENT_COMPLETED', flush=True)
"""


def exited(pid, timeout=0):
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
    kernel.WaitForSingleObject.restype = ctypes.c_ulong
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel.CloseHandle.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x00100000, False, pid)
    if not handle:
        return ctypes.get_last_error() == 87
    try:
        return kernel.WaitForSingleObject(handle, int(timeout * 1000)) == 0
    finally:
        kernel.CloseHandle(handle)


@unittest.skipUnless(os.name == "nt", "Windows process-tree ownership")
class WindowsProcessTests(unittest.TestCase):
    def test_finite_shell_and_argv_descendants_are_terminated_before_the_runner_returns(self):
        for shell in (False, True):
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
                root = Path(scratch)
                worker = root / "worker.py"
                worker.write_text(WORKER, encoding="utf-8")
                argv = [sys.executable, str(worker), str(root), "parent"]
                started = time.monotonic()
                result = defects.subprocess_runner(subprocess.list2cmdline(argv) if shell else argv, root, timeout=0.8)
                elapsed = time.monotonic() - started
                pids = [int(path.read_text(encoding="ascii")) for path in root.glob("*.pid")]
                try:
                    self.assertEqual(2, len(pids), "both finite workers must have started within the deadline")
                    self.assertTrue(result.timed_out)
                    self.assertIsNone(result.exit_code)
                    self.assertLess(elapsed, 2.5, "the four-second sleeper must not drain the captured pipes naturally")
                    self.assertTrue(all(exited(pid) for pid in pids), "every owned worker must already have exited")
                    self.assertIn("WORKER_STARTED=", result.output, "retain captured output after bounded termination")
                    self.assertNotIn("CHILD_COMPLETED", result.output)
                    self.assertNotIn("PARENT_COMPLETED", result.output)
                    (root / "held.txt").unlink()
                finally:
                    self.assertTrue(all(exited(pid, 6) for pid in pids), "finite test workers must not survive cleanup")

    def test_successful_command_does_not_leave_a_redirected_descendant_running_during_restore(self):
        with tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
            root = Path(scratch)
            worker = root / "worker.py"
            worker.write_text(WORKER, encoding="utf-8")
            result = defects.subprocess_runner([sys.executable, str(worker), str(root), "background"], root, timeout=2)
            pids = [int(path.read_text(encoding="ascii")) for path in root.glob("*.pid")]
            try:
                self.assertEqual(0, result.exit_code, result.output)
                self.assertFalse(result.timed_out)
                self.assertTrue(pids)
                self.assertEqual(2, len(pids))
                self.assertTrue(all(exited(pid) for pid in pids), "success also ends the owned process lifetime")
            finally:
                self.assertTrue(all(exited(pid, 6) for pid in pids))

    def test_consumer_code_is_not_released_until_process_ownership_is_established(self):
        helpers = defects.windows_helpers()
        assign = helpers.WindowsJob.assign
        with tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
            marker = Path(scratch) / "consumer-ran"

            def delayed(job, pid):
                time.sleep(0.2)
                self.assertFalse(marker.exists(), "the launcher must still be waiting for its command")
                assign(job, pid)
                self.assertFalse(marker.exists())

            command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
            with mock.patch.object(helpers.WindowsJob, "assign", delayed):
                result = defects.subprocess_runner(command, scratch, timeout=2)
            self.assertEqual(0, result.exit_code, result.output)
            self.assertTrue(marker.exists())

    def test_job_creation_refusal_starts_nothing_and_reports_the_ownership_failure(self):
        helpers = defects.windows_helpers()
        refusal = helpers.ProcessOwnershipError(13, "CreateJobObject refused")
        with mock.patch.object(helpers, "WindowsJob", side_effect=refusal), \
                mock.patch.object(defects.subprocess, "Popen") as popen:
            result = defects.subprocess_runner([sys.executable, "-c", "print(42)"], ".", timeout=1)
        popen.assert_not_called()
        self.assertIsNone(result.exit_code)
        self.assertIn("CreateJobObject refused", result.error)
        self.assertTrue(result.restoration_safe, "no consumer was started")

    def test_assignment_refusal_kills_only_the_idle_gate_and_never_executes_the_consumer(self):
        helpers = defects.windows_helpers()
        popen = subprocess.Popen
        processes = []

        def spy(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        with tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
            marker = Path(scratch) / "consumer-ran"
            command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
            refusal = helpers.ProcessOwnershipError(13, "AssignProcessToJobObject refused")
            with mock.patch.object(helpers.WindowsJob, "assign", side_effect=refusal), \
                    mock.patch.object(defects.subprocess, "Popen", spy):
                result = defects.subprocess_runner(command, scratch, timeout=1)
            self.assertIsNone(result.exit_code)
            self.assertIn("AssignProcessToJobObject refused", result.error)
            self.assertTrue(result.restoration_safe)
            self.assertFalse(marker.exists())
            self.assertEqual(1, len(processes))
            self.assertTrue(exited(processes[0].pid))

    def test_interrupt_during_gate_assignment_cannot_start_or_leave_a_consumer(self):
        helpers = defects.windows_helpers()
        popen = subprocess.Popen
        processes = []

        def spy(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(helpers.WindowsJob, "assign", side_effect=KeyboardInterrupt), \
                mock.patch.object(defects.subprocess, "Popen", spy):
            with self.assertRaises(KeyboardInterrupt):
                defects.subprocess_runner([sys.executable, "-c", "print(42)"], ".", timeout=1)
        self.assertEqual(1, len(processes))
        self.assertTrue(exited(processes[0].pid))

    def test_unreleased_pipes_have_a_bounded_teardown_and_cannot_be_claimed_safe(self):
        helpers = defects.windows_helpers()
        command = [sys.executable, "-c", "import time; time.sleep(4)"]
        calls = []

        def unavailable(process, timeout):
            calls.append(timeout)
            return False

        started = time.monotonic()
        with mock.patch.object(helpers, "TEARDOWN_SECONDS", 0.2), \
                mock.patch.object(helpers, "release_pipes", unavailable):
            with self.assertRaisesRegex(defects.UnsafeProcessTreeError, "output released: False"):
                defects.subprocess_runner(command, ".", timeout=0.3)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertTrue(calls)
        self.assertTrue(all(0 <= timeout <= 0.2 for timeout in calls))

    def test_unreadable_job_membership_cannot_be_claimed_safe(self):
        helpers = defects.windows_helpers()
        with mock.patch.object(helpers.WindowsJob, "process_ids", return_value=None):
            with self.assertRaisesRegex(defects.UnsafeProcessTreeError, "process list unavailable"):
                defects.subprocess_runner([sys.executable, "-c", "print(42)"], ".", timeout=2)

    def test_refused_tree_termination_is_bounded_and_reported_before_kill_on_close(self):
        helpers = defects.windows_helpers()
        started = time.monotonic()
        with mock.patch.object(helpers, "TEARDOWN_SECONDS", 0.2), \
                mock.patch.object(helpers.WindowsJob, "terminate", return_value=False):
            with self.assertRaisesRegex(defects.UnsafeProcessTreeError, "job termination refused"):
                defects.subprocess_runner([sys.executable, "-c", "import time; time.sleep(4)"], ".", timeout=0.3)
        self.assertLess(time.monotonic() - started, 1.5)


class RunnerContractTests(unittest.TestCase):
    def test_missing_release_byte_never_executes_the_consumer(self):
        with tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
            marker = Path(scratch) / "consumer-ran"
            command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
            result = subprocess.run([sys.executable, "-I", "-S", "-u", "-c", defects.WINDOWS_GATE, json.dumps(command)],
                                    input=b"", capture_output=True, check=False, env=defects.probe_environment(), timeout=2)
            self.assertEqual(2, result.returncode)
            self.assertFalse(marker.exists())

    def test_posix_keeps_the_existing_subprocess_call_and_isolated_environment(self):
        completed = subprocess.CompletedProcess("echo ok", 0, b"ok\n")
        with mock.patch.object(defects.os, "name", "posix"), \
                mock.patch.object(defects.subprocess, "run", return_value=completed) as run:
            result = defects.subprocess_runner("echo ok", ".", timeout=2, replacements=(), credentials=())
        self.assertEqual((0, "ok\n", False), (result.exit_code, result.output, result.timed_out))
        options = run.call_args.kwargs
        self.assertTrue(options["shell"])
        self.assertEqual(2, options["timeout"])
        self.assertEqual(subprocess.PIPE, options["stdout"])
        self.assertEqual(subprocess.STDOUT, options["stderr"])
        self.assertNotIn("GIT_CONFIG_PARAMETERS", options["env"])
        self.assertEqual("1", options["env"]["GIT_CONFIG_NOSYSTEM"])


if __name__ == "__main__":
    unittest.main()
