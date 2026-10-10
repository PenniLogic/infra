"""Run the CI conformance job against every generator profile and write the report.

    python governance/conformance/run.py --scratch <dir> --output <dir> [--repository NAME ...]
        [--github-client auto|gh|anonymous] [--exercise python,node,uv,java,android]
        [--command-timeout SECONDS] [--generated-at ISO-8601]

For each profile the job clones (or reuses) a read-only shallow checkout of ``main`` under the
scratch directory, asserts the repository id through the read-only API, compares the generated
baseline byte for byte, runs the consumer's own checker, plants defects, checks the required
check names against the rendered workflow and the branch ruleset, records bounded ``main`` CI
history, and writes ``conformance-report.json`` and ``conformance-summary.md`` with every local path
redacted. Exit status 0 means every repository passed, 1 means at least one failed, 2 means the job
itself could not run. Nothing is ever pushed, commented or written to a repository.
"""

import argparse
from contextlib import contextmanager
import datetime
import os
import subprocess
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance import defects, generator as generator_module, github_api, registry as registry_module  # noqa: E402
from conformance import report as report_module, steps  # noqa: E402


CLONE_TIMEOUT_SECONDS = 600
WORKFLOW_PREFIX = ".github/workflows/"
DISABLED_PUSH_URL = "DISABLED"
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024
OWNERSHIP_MARKER = ".conformance-owner"


class OwnershipError(RuntimeError):
    """No work may start against an ambiguous or already-owned scratch/output location."""


def validate_layout(names, scratch, output, infra_root):
    """Refuse repeated work, aliases and overlap before creating directories or inspecting consumers."""
    scratch, output, infra_root = (Path(path).resolve() for path in (scratch, output, infra_root))
    if output == infra_root or output in infra_root.parents or infra_root in output.parents:
        raise OwnershipError("report output overlaps the executing infra checkout")
    roots = []
    for name in names:
        path = scratch / name
        root = path.resolve()
        if path.is_symlink() or path.is_junction() or root.parent != scratch:
            raise OwnershipError(f"scratch root for {name} is not a direct, unlinked child")
        if root == infra_root or root in infra_root.parents or infra_root in root.parents:
            raise OwnershipError(f"scratch root for {name} overlaps the executing infra checkout")
        if root == output or root in output.parents or output in root.parents:
            raise OwnershipError(f"report output overlaps the scratch root for {name}")
        if any(root == other or root in other.parents or other in root.parents for other in roots):
            raise OwnershipError(f"repeated or overlapping scratch root requested for {name}; no work was deduplicated")
        roots.append(root)


@contextmanager
def own_directories(scratch, output, execution):
    """Exclusive invocation/publication markers; an unsafe scratch is retained, never auto-recovered."""
    scratch, output = Path(scratch).resolve(), Path(output).resolve()
    owned = []
    try:
        for directory in dict.fromkeys((scratch, output)):
            directory.mkdir(parents=True, exist_ok=True)
            marker = directory / OWNERSHIP_MARKER
            try:
                marker.mkdir()
            except FileExistsError:
                raise OwnershipError("scratch or output is already owned; verify the prior invocation before recovery") from None
            info = marker.lstat()
            owned.append((directory, marker, (info.st_dev, info.st_ino)))
        try:
            yield
        except BaseException:
            execution["unsafe_process_lifetime"] = (
                execution["unsafe_process_lifetime"] or "invocation aborted; process exit not confirmed")
            defects._UNCONFIRMED_PROCESS = True
            raise
    finally:
        for directory, marker, identity in reversed(owned):
            if directory == scratch and execution["unsafe_process_lifetime"] is not None:
                continue
            info = marker.lstat()
            if marker.is_symlink() or marker.is_junction() or (info.st_dev, info.st_ino) != identity:
                raise OwnershipError("conformance ownership marker changed; refusing cleanup")
            marker.rmdir()


def git(root, *args, timeout=60):
    """Run git on a scratch checkout with the isolated probe environment (no operator git/gh config)."""
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False, timeout=timeout,
                          env=defects.probe_environment())


def clone_url(organization, name):
    return f"https://github.com/{organization}/{name}.git"


def prepare_checkout(scratch, organization, name, refresh=False):
    """Clone ``main`` shallowly into ``scratch/<name>`` or reuse a clean existing clone of the same origin.

    With ``refresh`` an existing clone is advanced to the current remote ``main`` (a shallow fetch
    followed by a hard reset of the already-clean tree); without it the clone is used as found. The
    clone's push URL is set to an invalid value so that no command run inside it can push anywhere.
    """
    root = Path(scratch) / name
    url = clone_url(organization, name)
    if root.is_symlink() or root.is_junction():
        return None, None, False, "scratch checkout is a link or junction"
    reused = root.exists()
    if reused:
        git_dir = root / ".git"
        if (not git_dir.is_dir() or git_dir.is_symlink() or git_dir.is_junction()
                or (git_dir / "commondir").exists()):
            return None, None, False, "scratch checkout must have its own unlinked Git directory"
        locations = git(root, "rev-parse", "--show-toplevel", "--path-format=absolute", "--git-common-dir")
        actual = locations.stdout.decode("utf-8", errors="replace").splitlines()
        if (locations.returncode or len(actual) != 2
                or [Path(path).resolve() for path in actual] != [root.resolve(), git_dir.resolve()]):
            return None, None, False, "scratch checkout does not own its Git root and common directory"
        remote = git(root, "remote", "get-url", "origin")
        if remote.returncode or remote.stdout.decode("utf-8", errors="replace").strip().removesuffix(".git") != url.removesuffix(".git"):
            return None, None, False, "existing scratch directory is not a clone of the expected repository"
    else:
        result = subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--branch", "main", "--single-branch", url, str(root)],
            capture_output=True, check=False, timeout=CLONE_TIMEOUT_SECONDS, env=defects.probe_environment(),
        )
        if result.returncode:
            return None, None, False, "git clone failed"
    if git(root, "remote", "set-url", "--push", "origin", DISABLED_PUSH_URL).returncode:
        return root, None, reused, "disabling the scratch push URL failed"
    if defects.git_status(root):
        return root, None, reused, "scratch checkout is not clean"
    if reused and refresh:
        fetched = git(root, "fetch", "--quiet", "--depth", "1", "origin", "main", timeout=CLONE_TIMEOUT_SECONDS)
        if fetched.returncode or git(root, "reset", "--quiet", "--hard", "FETCH_HEAD").returncode:
            return root, None, reused, "refreshing the scratch checkout failed"
    head = git(root, "rev-parse", "HEAD")
    if head.returncode:
        return root, None, reused, "git rev-parse failed"
    return root, head.stdout.decode("utf-8").strip(), reused, None


def generated_baseline(generator, name, root, infra_root, runner):
    """Per-file comparison of the generated artifacts plus the generator's own --check verdict."""
    workflow_differences, stale = [], []
    for relative, content in generator.artifacts(name).items():
        path = root / relative
        identical = path.is_file() and not path.is_symlink() and path.read_bytes() == content.encode("utf-8")
        if not identical:
            (workflow_differences if relative.startswith(WORKFLOW_PREFIX) else stale).append(relative)
    check = runner([sys.executable, str(infra_root / "governance" / "generate.py"),
                    "--repository", name, "--root", str(root), "--check"], root)
    return {
        "command": "python governance/generate.py --repository <profile> --root <scratch>/<profile> --check",
        "exit_code": check.exit_code,
        "elapsed_seconds": check.elapsed_seconds,
        "timed_out": check.timed_out,
        "error": check.error,
        "output_tail": check.output[-300:],
        "workflow_files_identical": not workflow_differences,
        "workflow_differences": workflow_differences,
        "stale_files": stale,
    }


def required_checks(client, full_name, produced):
    rulesets = github_api.rulesets(client, full_name)
    rules = github_api.branch_rules(client, full_name)
    required = rules["required_status_checks"]
    return {
        "produced": sorted(produced),
        "required": required,
        "missing": github_api.missing_required_checks(required, produced),
        "strict_up_to_date": rules["strict_required_status_checks_policy"],
        "branch_rules": rules,
        "rulesets": rulesets,
    }


def registry_status(document, infra_root, name, full_name, produced, workflow_bytes, gate_bytes=None):
    entry = next((item for item in document["entries"] if item["repo"] == full_name), None)
    status = {"entry": entry, "check_name_produced": None, "workflow_ref_renders_current_workflow": None}
    if entry is None:
        return status
    status["check_name_produced"] = entry["check_name"] in produced
    if workflow_bytes is None:
        status["workflow_ref_renders_current_workflow"] = "unverifiable"
        status["note"] = "no scratch checkout of main to compare against"
        return status
    rendered = registry_module.render_workflow_at(infra_root, entry["workflow_ref"], name)
    if rendered is None:
        status["workflow_ref_renders_current_workflow"] = "unverifiable"
        status["note"] = "workflow_ref is not in the local infra history (shallow clone) or predates the profile"
    else:
        status["workflow_ref_renders_current_workflow"] = rendered == workflow_bytes
    gate = entry.get("pr_gate")
    if gate is not None:
        binding = {"check_name_produced": gate["check_name"] in produced,
                   "workflow_ref_renders_current_workflow": False}
        status["pr_gate"] = binding
        status["check_name_produced"] = status["check_name_produced"] and binding["check_name_produced"]
        if gate_bytes is not None:
            try:
                rendered_gate = registry_module.render_workflow_at(
                    infra_root, gate["workflow_ref"], name, workflow_file=registry_module.PR_GATE_WORKFLOW,
                )
            except registry_module.RegistryError:
                rendered_gate = None
            binding["workflow_ref_renders_current_workflow"] = rendered_gate is not None and rendered_gate == gate_bytes
        if not binding["workflow_ref_renders_current_workflow"]:
            status["workflow_ref_renders_current_workflow"] = False
            status["note"] = "native PR gate source binding missing, unavailable or different"
    return status


def repository_record(name, profile, generator):
    return {
        "repository": f"{generator.PROFILES['organization']}/{name}", "profile": name, "repository_id": profile["id"],
        "language": registry_module.expected_language(name, profile),
        "profile_timeout_minutes": profile.get("timeout_minutes", generator.DEFAULT_TIMEOUT_MINUTES),
        "identity": None, "api_error": None, "clone_error": None, "reused_existing_clone": None, "main_sha": None,
        "generated_baseline": None, "repository_check": None,
        "detected_steps": steps.detect_steps(profile["commands"]),
        "required_checks": None, "registry": None, "last_main_run": None, "main_run_history": None,
        "planted_defects": [], "language_coverage": {},
        "timings": {"elapsed_seconds": None, "checkout_seconds": None},
    }


def inspection_error(record, error, scratch, infra_root):
    record["job_error"] = f"{error.__class__.__name__}: {error}"
    if isinstance(error, (defects.UnsafeProcessTreeError, subprocess.TimeoutExpired)) or defects._UNCONFIRMED_PROCESS:
        defects._UNCONFIRMED_PROCESS = True
        record["restoration_deferred"] = True
        if isinstance(error, defects.UnsafeProcessTreeError) and error.result is not None:
            record["interrupted_probe"] = defects._probe_record(
                defects.Probe("interrupted repository command", error.command, expect="observe"), error.result)
        elif isinstance(error, subprocess.TimeoutExpired):
            redact_output = defects._capture_redactor(
                scratch, report_module.path_replacements(scratch, infra_root))
            record["interrupted_checkout"] = {
                "command": error.cmd, "timed_out": True, "timeout_seconds": error.timeout,
                "restoration_safe": False,
            }
            for key, captured in (("output_tail", error.output), ("stderr_tail", error.stderr)):
                captured = captured or b""
                text = captured.decode("utf-8", errors="replace") if isinstance(captured, bytes) else captured
                record["interrupted_checkout"][key] = redact_output(text)[-defects.RECORDED_TAIL:]


def inspect_repository(name, profile, generator, client, registry_document, scratch, infra_root, runner, exercise,
                       refresh=False, budget_minutes=github_api.BUDGET_MINUTES):
    record = repository_record(name, profile, generator)
    started = time.monotonic()
    try:
        organization, full_name = generator.PROFILES["organization"], record["repository"]
        rendered_workflow = generator.artifacts(name)[".github/workflows/ci.yml"].encode("utf-8")
        try:
            identity = github_api.repository_identity(client, full_name)
            identity["expected_id"] = profile["id"]
            identity["verified"] = identity["id"] == profile["id"]
            record["identity"] = identity
        except github_api.ApiError as error:
            record["api_error"] = str(error)
            record["identity"] = {"expected_id": profile["id"], "verified": None}
        root, main_sha, reused, clone_error = None, None, None, None
        if record["identity"].get("verified") is True:
            checkout_started = time.monotonic()
            try:
                root, main_sha, reused, clone_error = prepare_checkout(scratch, organization, name, refresh)
            finally:
                record["timings"]["checkout_seconds"] = time.monotonic() - checkout_started
        else:
            clone_error = "repository identity not verified; nothing from the repository was executed"
        record["reused_existing_clone"] = reused
        record["main_sha"] = main_sha
        record["clone_error"] = clone_error
        workflow_on_main, gate_on_main = None, None
        if root is not None and clone_error is None:
            workflow_path = root / ".github/workflows/ci.yml"
            workflow_on_main = workflow_path.read_bytes() if workflow_path.is_file() else b"{}"
            if profile.get("pr_workflow_integrity", False):
                gate_path = root / registry_module.PR_GATE_WORKFLOW
                if gate_path.is_file() and not gate_path.is_symlink():
                    gate_on_main = gate_path.read_bytes()
            record["generated_baseline"] = generated_baseline(generator, name, root, infra_root, runner)
            check = runner([sys.executable, "scripts/check_repository.py"], root)
            record["repository_check"] = {
                "command": "python scripts/check_repository.py", "exit_code": check.exit_code,
                "output_tail": check.output[-300:], "elapsed_seconds": check.elapsed_seconds,
                "timed_out": check.timed_out, "error": check.error,
            }
            context = defects.Context(name, profile, root, infra_root)
            record["planted_defects"] = defects.run_fixtures(context, runner, exercise)
            record["language_coverage"] = defects.language_coverage(record["planted_defects"])
            if any(item.get("restoration_deferred") for item in record["planted_defects"]):
                record["restoration_deferred"] = True
        try:
            # Without a checkout this is the rendering; the row already fails on clone_error.
            workflows = {registry_module.CI_WORKFLOW: workflow_on_main if workflow_on_main is not None else rendered_workflow}
            if gate_on_main is not None:
                workflows[registry_module.PR_GATE_WORKFLOW] = gate_on_main
            produced = steps.produced_pr_check_names(workflows)
        except (ValueError, UnicodeDecodeError):
            produced = set()
        record["produced_check_names"] = sorted(produced)
        record["registry"] = registry_status(registry_document, infra_root, name, full_name, produced,
                                             workflow_on_main, gate_on_main)
        if record["api_error"] is None:
            try:
                record["required_checks"] = required_checks(client, full_name, produced)
                history = github_api.main_run_history(client, full_name, workflow_name="CI", budget_minutes=budget_minutes)
                record["main_run_history"] = history
                record["last_main_run"] = history["runs"][0] if history["runs"] else None
            except github_api.ApiError as error:
                record["api_error"] = str(error)
    except Exception as error:  # noqa: BLE001 - keep partial facts and the original failure for this row
        inspection_error(record, error, scratch, infra_root)
    finally:
        record["timings"]["elapsed_seconds"] = time.monotonic() - started
    return record


def redacting_runner(timeout, replacements, credentials=None):
    """Supply the report's exact scope to capture-time redaction, before either retained tail."""
    def runner(command, cwd):
        return defects.subprocess_runner(command, cwd, timeout, replacements=replacements, credentials=credentials)
    return runner


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scratch", type=Path, required=True, help="directory for the read-only scratch clones")
    parser.add_argument("--output", type=Path, required=True, help="directory for the report and summary")
    parser.add_argument("--repository", action="append", help="limit the run to these profiles (repeatable)")
    parser.add_argument("--github-client", choices=("auto", "gh", "anonymous"), default="auto")
    parser.add_argument("--exercise", default=",".join(defects.DEFAULT_EXERCISE),
                        help="comma-separated toolchains whose planted defects run: " + ",".join(defects.TOOLCHAINS))
    parser.add_argument("--command-timeout", type=int, default=defects.COMMAND_TIMEOUT_SECONDS)
    parser.add_argument("--budget-minutes", type=int, default=github_api.BUDGET_MINUTES)
    parser.add_argument("--generated-at", help="ISO-8601 timestamp to record instead of the current time")
    parser.add_argument("--refresh", action="store_true", help="advance reused scratch clones to the current remote main")
    args = parser.parse_args(argv)
    if args.budget_minutes <= 0:
        parser.error("--budget-minutes must be positive")
    if args.command_timeout <= 0:
        parser.error("--command-timeout must be positive")
    exercise = tuple(item for item in args.exercise.split(",") if item)
    unknown = sorted(set(exercise) - set(defects.TOOLCHAINS))
    if unknown:
        parser.error(f"unknown toolchain(s) {', '.join(unknown)}")
    args.exercise = exercise
    return args


def publish_actions_summary(markdown):
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        print("Conformance publication failed: GITHUB_STEP_SUMMARY is unavailable; full report retained in artifacts",
              file=sys.stderr)
        return False
    try:
        with Path(target).open("ab") as summary:
            content = (("\n" if summary.tell() else "") + markdown).encode("utf-8")
            if summary.tell() + len(content) > STEP_SUMMARY_LIMIT_BYTES:
                print("Conformance publication failed: job summary exceeds the runner's 1 MiB limit; "
                      "full report retained in artifacts", file=sys.stderr)
                return False
            summary.write(content)
    except (OSError, ValueError) as error:
        print(f"Conformance publication failed: GITHUB_STEP_SUMMARY could not be written ({error.__class__.__name__}); "
              "full report retained in artifacts", file=sys.stderr)
        return False
    return True


def main(argv=None):
    args = parse_arguments(argv)
    generator = generator_module.load()
    infra_root = generator_module.INFRA_ROOT
    names = args.repository or list(generator.PROFILES["repositories"])
    unknown = sorted(set(names) - set(generator.PROFILES["repositories"]))
    if unknown:
        print(f"Unknown profile(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        registry_document = registry_module.load_registry()
        registry_errors = registry_module.validate_registry(registry_document) or registry_module.cross_check(registry_document, generator)
    except (OSError, ValueError) as error:
        print(f"Check-name registry unreadable: {error}", file=sys.stderr)
        return 2
    if registry_errors:
        for error in registry_errors:
            print(f"Check-name registry: {error}", file=sys.stderr)
        return 2
    try:
        client = github_api.choose_client(args.github_client)
    except github_api.ApiError as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        validate_layout(names, args.scratch, args.output, infra_root)
    except (OwnershipError, OSError, ValueError) as error:
        detail = str(error) if isinstance(error, OwnershipError) else error.__class__.__name__
        print(f"Conformance ownership refused: {detail}", file=sys.stderr)
        return 2
    execution = {"repository_workers": 1, "elapsed_seconds": None, "unsafe_process_lifetime": None}
    try:
        with own_directories(args.scratch, args.output, execution):
            return run_owned(args, names, generator, client, registry_document, infra_root, execution)
    except (OwnershipError, OSError) as error:
        detail = str(error) if isinstance(error, OwnershipError) else error.__class__.__name__
        print(f"Conformance ownership/publication failed: {detail}", file=sys.stderr)
        return 2


def run_owned(args, names, generator, client, registry_document, infra_root, execution):
    defects.isolation_directory()
    replacements = report_module.path_replacements(args.scratch, infra_root)
    credentials = report_module.credential_values()
    runner = redacting_runner(args.command_timeout, replacements, credentials)
    head = git(infra_root, "rev-parse", "HEAD")
    generator_commit = head.stdout.decode("utf-8").strip() if head.returncode == 0 else None
    records = []
    started = time.monotonic()
    for name in names:
        print(f"conformance: {name}", file=sys.stderr)
        profile = generator.PROFILES["repositories"][name]
        if execution["unsafe_process_lifetime"] is not None:
            record = repository_record(name, profile, generator)
            record["job_error"] = "not inspected after an earlier unconfirmed process lifetime; scratch retained"
        else:
            inspection_started = time.monotonic()
            try:
                record = inspect_repository(name, profile, generator, client, registry_document,
                                            args.scratch, infra_root, runner, args.exercise, args.refresh,
                                            args.budget_minutes)
            except Exception as error:  # noqa: BLE001 - keep every requested row and explicit failures
                record = repository_record(name, profile, generator)
                inspection_error(record, error, args.scratch, infra_root)
                record["timings"]["elapsed_seconds"] = time.monotonic() - inspection_started
            if record.get("restoration_deferred"):
                execution["unsafe_process_lifetime"] = f"{name}: process-tree exit not confirmed"
        records.append(record)
    execution["elapsed_seconds"] = time.monotonic() - started
    not_run = []
    for toolchain in defects.TOOLCHAINS:
        if toolchain in args.exercise:
            continue
        affected = sorted({record["profile"] for record in records
                           for defect in record["planted_defects"] if defect["toolchain"] == toolchain})
        if affected:
            not_run.append(f"{toolchain} planted defects not exercised for: {', '.join(affected)}")
    generated_at = args.generated_at or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    document = report_module.build_report(
        records, generator_commit, client.name, args.exercise, args.budget_minutes, generated_at,
        api_requests=client.requests, rate_limit_remaining=client.rate_limit_remaining, not_run=not_run,
        execution=execution,
    )
    document = report_module.redact(document, replacements, credentials)
    survivors = report_module.redaction_survivors(document, replacements, credentials)
    if survivors:
        # Fail closed without echoing what survived: the kinds are named, the text is not written anywhere.
        print(f"Redaction incomplete ({', '.join(survivors)}); nothing written", file=sys.stderr)
        return 2
    markdown = report_module.render_markdown(document)
    (args.output / "conformance-report.json").write_text(report_module.to_json(document), encoding="utf-8", newline="\n")
    (args.output / "conformance-summary.md").write_text(markdown, encoding="utf-8", newline="\n")
    hosted = os.environ.get("GITHUB_ACTIONS") == "true"
    if hosted and not publish_actions_summary(markdown):
        return 2
    print(f"Conformance {document['result'].upper()}: {document['repository_count']} repositories, "
          f"{len(document['failures'])} failure(s); report written to {args.output.name}/conformance-report.json")
    for failure in document["failures"]:
        print(f"  FAIL {failure}")
    if hosted:
        warning_count = sum(len(record["warnings"]) for record in document["repositories"])
        if warning_count:
            print(f"::warning::Conformance reported {warning_count} warning(s); "
                  "see the job summary and conformance-report artifacts for every warning and full CI duration history.")
    else:
        for record in document["repositories"]:
            for warning in record["warnings"]:
                print(f"  warning {record['repository']}: {warning}")
    return 0 if document["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
