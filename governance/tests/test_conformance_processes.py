"""Finite process-lifetime regressions; native platform checks never stand in for the other OS."""

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
                             start_new_session=mode == 'detached',
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
    def setUp(self):
        retained = mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False)
        retained.start()
        self.addCleanup(retained.stop)

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
                receipts = list(root.glob("*.pid"))
                pids = [int(path.read_text(encoding="ascii")) for path in receipts]
                try:
                    self.assertEqual(
                        2, len(pids), "both finite workers must have started within the deadline; "
                        f"receipts={sorted(path.name for path in receipts)!r}; elapsed={elapsed:.3f}s; result={result!r}",
                    )
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
    def setUp(self):
        sigchld = mock.patch.object(defects.signal, "SIGCHLD", getattr(defects.signal, "SIGCHLD", 17), create=True)
        disposition = mock.patch.object(defects.signal, "getsignal", return_value=defects.signal.SIG_DFL)
        sigchld.start()
        disposition.start()
        self.addCleanup(sigchld.stop)
        self.addCleanup(disposition.stop)

    def test_missing_release_byte_never_executes_the_consumer(self):
        with tempfile.TemporaryDirectory(prefix="conformance-process-test-") as scratch:
            marker = Path(scratch) / "consumer-ran"
            command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
            result = subprocess.run([sys.executable, "-I", "-S", "-u", "-c", defects.WINDOWS_GATE, json.dumps(command)],
                                    input=b"", capture_output=True, check=False, env=defects.probe_environment(), timeout=2)
            self.assertEqual(2, result.returncode)
            self.assertFalse(marker.exists())

    def test_posix_uses_an_owned_session_and_the_existing_isolated_environment(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"ok\n", None)
        with mock.patch.object(defects.subprocess, "Popen", return_value=process) as popen:
            result = defects._posix_runner("echo ok", ".", defects.probe_environment(), 2, lambda value: value)
        self.assertEqual((0, "ok\n", False), (result.exit_code, result.output, result.timed_out))
        options = popen.call_args.kwargs
        self.assertTrue(options["shell"])
        self.assertTrue(options["start_new_session"])
        self.assertEqual(subprocess.DEVNULL, options["stdin"])
        process.communicate.assert_called_once_with(timeout=2)
        self.assertEqual(subprocess.PIPE, options["stdout"])
        self.assertEqual(subprocess.STDOUT, options["stderr"])
        self.assertNotIn("GIT_CONFIG_PARAMETERS", options["env"])
        self.assertEqual("1", options["env"]["GIT_CONFIG_NOSYSTEM"])

    def test_teardown_diagnostics_do_not_make_an_unconfirmed_result_safe(self):
        detail = "processes exited: 1 of 2; processes still active: 0; OpenProcess errors=[(2, 5)]"
        cleanup = {"pipes_released": True, "descendant_exit_confirmed": False}
        result = defects.Result(None, "WORKER_STARTED=101\n", timed_out=True, error=detail, restoration_safe=False,
                                failure_evidence="synthetic witness", process_cleanup=cleanup)
        command = ["synthetic-command"]
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(defects.os, "name", "nt"), \
                mock.patch.object(defects, "_windows_runner", return_value=result) as runner, \
                mock.patch.object(defects.time, "monotonic", side_effect=[10.0, 10.8]):
            with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                defects.subprocess_runner(command, ".", timeout=0.8, replacements=(), credentials=())
            self.assertTrue(defects._UNCONFIRMED_PROCESS)
        self.assertEqual(detail, str(caught.exception))
        retained = caught.exception.result
        self.assertEqual(command, caught.exception.command)
        self.assertEqual(result.output, retained.output)
        self.assertEqual(result.failure_evidence, retained.failure_evidence)
        self.assertEqual(cleanup, retained.process_cleanup)
        self.assertAlmostEqual(0.8, retained.elapsed_seconds)
        self.assertTrue(retained.timed_out)
        self.assertIsNone(retained.exit_code)
        self.assertEqual(detail, retained.error)
        self.assertFalse(retained.restoration_safe)
        self.assertEqual(0.8, runner.call_args.args[3])
        self.assertFalse(result.restoration_safe)

    def test_unexpected_outer_timeout_retains_unsafe_result_and_configuration(self):
        command = ["synthetic-command"]
        marker = "synthetic-outer-timeout-secret"
        failure = subprocess.TimeoutExpired(
            command, 0.8, output=("x" * (defects.OUTPUT_TAIL + 1) + marker).encode(),
        )
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(defects, "_windows_runner", side_effect=failure), \
                mock.patch.object(defects, "_posix_runner", side_effect=failure), \
                mock.patch.object(defects.time, "monotonic", side_effect=[10.0, 10.8]), \
                mock.patch.object(defects.shutil, "rmtree") as remove:
            with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                defects.subprocess_runner(command, ".", timeout=0.8, replacements=(), credentials=(marker,))
            self.assertTrue(defects._UNCONFIRMED_PROCESS)
            defects._cleanup_isolation("synthetic-owned-config")
        remove.assert_not_called()
        self.assertEqual(command, caught.exception.command)
        result = caught.exception.result
        self.assertTrue(result.timed_out)
        self.assertFalse(result.restoration_safe)
        self.assertIsNone(result.exit_code)
        self.assertIn("outside confirmed teardown", result.error)
        self.assertAlmostEqual(0.8, result.elapsed_seconds)
        self.assertEqual("", result.failure_evidence)
        self.assertIsNone(result.process_cleanup, "an outer timeout has no confirmed teardown facts")
        self.assertIn("[redacted]", result.output)
        self.assertNotIn(marker, result.output)
        self.assertLessEqual(len(result.output), defects.OUTPUT_TAIL)

    def test_measured_result_includes_launch_failure_and_unconfirmed_timeout_time(self):
        for outcome in (defects.Result(0, "ok"), OSError("synthetic launch refusal"),
                        defects.Result(None, "captured", timed_out=True, restoration_safe=False,
                                       error="synthetic teardown unconfirmed")):
            options = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with self.subTest(outcome=outcome), \
                    mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                    mock.patch.object(defects, "_windows_runner", **options), \
                    mock.patch.object(defects, "_posix_runner", **options), \
                    mock.patch.object(defects.time, "monotonic", side_effect=[10.0, 12.75]):
                if isinstance(outcome, defects.Result) and not outcome.restoration_safe:
                    with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                        defects.subprocess_runner("unused", ".", replacements=(), credentials=())
                    result = caught.exception.result
                    self.assertTrue(result.timed_out)
                    self.assertFalse(result.restoration_safe)
                    self.assertEqual("captured", result.output)
                else:
                    result = defects.subprocess_runner("unused", ".", replacements=(), credentials=())
                self.assertEqual(2.75, result.elapsed_seconds)
        self.assertIsNone(defects.Result(0, "").elapsed_seconds, "unmeasured is not a fabricated zero")

    def test_posix_timeout_preserves_partial_output_even_when_group_cleanup_finishes(self):
        process = mock.Mock(returncode=None)
        process.communicate.side_effect = subprocess.TimeoutExpired("synthetic", 2, output=b"partial secret")
        cleanup = {"process_group_signal": "sent", "leader_exit_confirmed": True, "pipes_released": True,
                   "descendant_exit_confirmed": False}
        with mock.patch.object(defects.subprocess, "Popen", return_value=process), \
                mock.patch.object(defects, "_finish_posix_group", return_value=(b"partial secret", cleanup)) as finish:
            with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                defects._posix_runner("synthetic", ".", {}, 2, lambda value: value.replace("secret", "[redacted]"))
        result = caught.exception.result
        finish.assert_called_once_with(process, b"partial secret")
        self.assertEqual("partial [redacted]", result.output)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.restoration_safe, "a process group is not complete descendant containment")
        self.assertIsNone(result.exit_code)
        self.assertEqual(cleanup, result.process_cleanup)

    def test_posix_refuses_external_child_reapers_before_starting_a_consumer(self):
        for handler in (defects.signal.SIG_IGN, lambda *args: None):
            with self.subTest(handler=handler), \
                    mock.patch.object(defects.signal, "getsignal", return_value=handler), \
                    mock.patch.object(defects.subprocess, "Popen") as popen:
                result = defects._posix_runner("unused", ".", {}, 2, lambda value: value)
            popen.assert_not_called()
            self.assertIn("default SIGCHLD handler", result.error)
            self.assertTrue(result.restoration_safe, "no consumer was started")

    def test_posix_launch_and_capture_interruptions_cannot_restore_an_unconfirmed_tree(self):
        for launch in (True, False):
            process = mock.Mock(returncode=None)
            process.communicate.side_effect = KeyboardInterrupt
            options = {"side_effect": KeyboardInterrupt} if launch else {"return_value": process}
            with self.subTest(launch=launch), \
                    mock.patch.object(defects.subprocess, "Popen", **options), \
                    mock.patch.object(defects, "_finish_posix_group", return_value=(b"partial", {})) as finish:
                with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                    defects._posix_runner("synthetic", ".", {}, 2, lambda value: value)
            self.assertEqual(0 if launch else 1, finish.call_count)
            result = caught.exception.result
            self.assertIn("KeyboardInterrupt", result.error)
            self.assertFalse(result.restoration_safe)
            self.assertFalse(result.timed_out)
            self.assertEqual("" if launch else "partial", result.output)

    def test_posix_never_signals_a_group_after_its_leader_was_reaped(self):
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"done", None)
        with mock.patch.object(defects.os, "killpg", create=True) as killpg:
            output, cleanup = defects._finish_posix_group(process)
        killpg.assert_not_called()
        self.assertEqual(b"done", output)
        self.assertIn("already reaped", cleanup["process_group_signal"])
        self.assertTrue(cleanup["leader_exit_confirmed"])
        self.assertFalse(cleanup["descendant_exit_confirmed"])

    def test_posix_unreleased_pipes_and_leader_wait_share_one_teardown_deadline(self):
        process = mock.Mock(pid=123, returncode=None)
        process.communicate.side_effect = subprocess.TimeoutExpired("synthetic", 5, output=b"retained partial")
        process.wait.side_effect = subprocess.TimeoutExpired("synthetic", 0)
        with mock.patch.object(defects.os, "killpg", create=True) as killpg, \
                mock.patch.object(defects.signal, "SIGKILL", 9, create=True), \
                mock.patch.object(defects.time, "monotonic", side_effect=[10.0, 10.0, 15.0]):
            output, cleanup = defects._finish_posix_group(process, b"earlier partial")
        killpg.assert_called_once_with(123, 9)
        process.communicate.assert_called_once_with(timeout=5.0)
        process.wait.assert_called_once_with(timeout=0.0)
        self.assertEqual(b"retained partial", output)
        self.assertFalse(cleanup["leader_exit_confirmed"])
        self.assertFalse(cleanup["pipes_released"])
        self.assertFalse(cleanup["descendant_exit_confirmed"])

    def test_posix_refused_group_signal_is_explicit_and_only_the_owned_leader_is_retried(self):
        process = mock.Mock(pid=123, returncode=None)

        def communicate(**kwargs):
            process.returncode = -9
            return b"retained", None

        process.communicate.side_effect = communicate
        with mock.patch.object(defects.os, "killpg", side_effect=PermissionError("synthetic refusal"), create=True), \
                mock.patch.object(defects.signal, "SIGKILL", 9, create=True):
            _, cleanup = defects._finish_posix_group(process)
        process.kill.assert_called_once_with()
        self.assertEqual("failed: PermissionError", cleanup["process_group_signal"])
        self.assertTrue(cleanup["leader_exit_confirmed"])
        self.assertFalse(cleanup["descendant_exit_confirmed"])

    def test_posix_interrupted_teardown_keeps_partial_output_and_unknown_exit(self):
        process = mock.Mock(pid=123, returncode=None)
        with mock.patch.object(defects.os, "killpg", side_effect=KeyboardInterrupt, create=True), \
                mock.patch.object(defects.signal, "SIGKILL", 9, create=True):
            output, cleanup = defects._finish_posix_group(process, b"original timeout output")
        self.assertEqual(b"original timeout output", output)
        self.assertEqual("KeyboardInterrupt", cleanup["teardown_interrupted"])
        self.assertEqual("attempted: result unconfirmed", cleanup["process_group_signal"])
        self.assertFalse(cleanup["leader_exit_confirmed"])
        self.assertFalse(cleanup["pipes_released"])
        self.assertFalse(cleanup["descendant_exit_confirmed"])

    def test_unconfirmed_process_lifetime_retains_isolated_configuration(self):
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", True), \
                mock.patch.object(defects.shutil, "rmtree") as remove:
            defects._cleanup_isolation("synthetic-owned-config")
        remove.assert_not_called()

    def test_configuration_cleanup_failure_is_explicit_without_echoing_a_path(self):
        with mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False), \
                mock.patch.object(defects.shutil, "rmtree", side_effect=PermissionError("private/path")), \
                mock.patch("builtins.print") as output:
            defects._cleanup_isolation("synthetic-owned-config")
        message = output.call_args.args[0]
        self.assertIn("cleanup failed (PermissionError)", message)
        self.assertNotIn("private/path", message)


def posix_exited(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
    except FileNotFoundError:
        return True
    return state in ("Z", "X")


@unittest.skipUnless(sys.platform.startswith("linux"), "native Linux owned-group/escaped-descendant evidence")
class LinuxProcessTests(unittest.TestCase):
    def finish_finite_workers(self, pids):
        deadline = time.monotonic() + 6
        while not all(posix_exited(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(all(posix_exited(pid) for pid in pids), "finite owned workers must finish before fixture cleanup")

    def test_timeout_stops_shell_and_argv_group_members_but_keeps_restoration_fail_closed(self):
        import shlex
        for shell in (False, True):
            temporary = tempfile.TemporaryDirectory(prefix="conformance-posix-test-", delete=False)
            with self.subTest(shell=shell), temporary as scratch, \
                    mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False):
                root = Path(scratch)
                worker = root / "worker.py"
                worker.write_text(WORKER, encoding="utf-8")
                argv = [sys.executable, str(worker), str(root), "parent"]
                started = time.monotonic()
                with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                    defects.subprocess_runner(shlex.join(argv) if shell else argv, root, timeout=0.8)
                result = caught.exception.result
                pids = [int(path.read_text()) for path in root.glob("*.pid")]
                try:
                    self.assertEqual(2, len(pids), "both finite workers must have started")
                    self.assertLess(time.monotonic() - started, 0.8 + defects.POSIX_TEARDOWN_SECONDS + 1)
                    self.assertTrue(result.timed_out)
                    self.assertFalse(result.restoration_safe)
                    self.assertEqual("sent", result.process_cleanup["process_group_signal"])
                    self.assertTrue(result.process_cleanup["leader_exit_confirmed"])
                    self.assertTrue(result.process_cleanup["pipes_released"])
                    self.assertFalse(result.process_cleanup["descendant_exit_confirmed"])
                    self.assertTrue(all(posix_exited(pid) for pid in pids))
                    self.assertIn("WORKER_STARTED=", result.output)
                finally:
                    self.finish_finite_workers(pids)
                    if len(pids) == 2:
                        temporary.cleanup()

    def test_an_escaped_descendant_is_not_mistaken_for_a_terminated_owned_tree(self):
        temporary = tempfile.TemporaryDirectory(prefix="conformance-posix-test-", delete=False)
        with temporary as scratch, \
                mock.patch.object(defects, "_UNCONFIRMED_PROCESS", False):
            root = Path(scratch)
            worker = root / "worker.py"
            worker.write_text(WORKER, encoding="utf-8")
            with mock.patch.object(defects, "POSIX_TEARDOWN_SECONDS", 0.2):
                with self.assertRaises(defects.UnsafeProcessTreeError) as caught:
                    defects.subprocess_runner([sys.executable, str(worker), str(root), "detached"], root, timeout=0.8)
            result = caught.exception.result
            pids = [int(path.read_text()) for path in root.glob("*.pid")]
            try:
                child = int((root / "child.pid").read_text())
                self.assertFalse(posix_exited(child), "the detached finite child is outside the killed group")
                self.assertFalse(result.restoration_safe)
                self.assertFalse(result.process_cleanup["pipes_released"])
                self.assertFalse(result.process_cleanup["descendant_exit_confirmed"])
                self.assertTrue(result.process_cleanup["leader_exit_confirmed"])
                self.assertEqual("sent", result.process_cleanup["process_group_signal"])
            finally:
                self.finish_finite_workers(pids)
                if len(pids) == 2:
                    temporary.cleanup()


class ReceiptDiagnosticTests(unittest.TestCase):
    def receipt_failure(self, result, shell):
        method = "test_finite_shell_and_argv_descendants_are_terminated_before_the_runner_returns"
        fixture = WindowsProcessTests(method)

        def finished(command, root, timeout):
            self.assertEqual(0.8, timeout)
            (root / "parent.pid").write_text("101", encoding="ascii")
            if isinstance(command, str) == shell:
                return result
            (root / "child.pid").write_text("202", encoding="ascii")
            (root / "held.txt").touch()
            return defects.Result(None, "WORKER_STARTED=101\nWORKER_STARTED=202\n", timed_out=True)

        with mock.patch.object(defects, "subprocess_runner", side_effect=finished) as runner, \
                mock.patch(f"{__name__}.exited", return_value=True) as confirm_exit, \
                mock.patch.object(time, "monotonic", side_effect=[10.0, 10.8] * (1 + shell)):
            with self.assertRaisesRegex(AssertionError, "both finite workers must have started") as caught:
                getattr(fixture, method)()
        self.assertEqual(1 + shell, runner.call_count)
        self.assertEqual(mock.call(101, 6), confirm_exit.call_args)
        return str(caught.exception)

    def test_missing_receipt_retains_timeout_result_and_redacted_bounded_output(self):
        marker = "synthetic-receipt-secret"
        captured = defects._captured_output(
            ("x" * (defects.OUTPUT_TAIL + 1) + "\n" + marker).encode(),
            defects._capture_redactor(".", replacements=(), credentials=(marker,)),
        )
        result = defects.Result(None, **captured, timed_out=True)
        for shell in (False, True):
            with self.subTest(shell=shell):
                message = self.receipt_failure(result, shell)
                self.assertIn("receipts=['parent.pid']", message)
                self.assertIn("elapsed=0.800s", message)
                self.assertIn("timed_out=True", message)
                self.assertIn("exit_code=None", message)
                self.assertIn("error=None", message)
                self.assertIn("restoration_safe=True", message)
                self.assertIn("failure_evidence=''", message)
                self.assertIn("elapsed_seconds=None", message)
                self.assertIn("process_cleanup=None", message)
                self.assertIn(repr(result.output), message)
                self.assertIn("[redacted]", message)
                self.assertNotIn(marker, message)
                self.assertLess(len(message), defects.OUTPUT_TAIL + 400)

    def test_missing_receipt_retains_early_failure_instead_of_implying_timeout(self):
        result = defects.Result(7, "finite synthetic worker failed\n", error="synthetic start failure")
        for shell in (False, True):
            with self.subTest(shell=shell):
                message = self.receipt_failure(result, shell)
                self.assertIn("receipts=['parent.pid']", message)
                self.assertIn("elapsed=0.800s", message)
                self.assertIn("timed_out=False", message)
                self.assertIn("exit_code=7", message)
                self.assertIn("error='synthetic start failure'", message)
                self.assertIn(repr(result.output), message)


if __name__ == "__main__":
    unittest.main()
