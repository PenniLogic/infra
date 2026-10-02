"""The required check-name registry (``check-names.json``): loading, schema validation and the
cross-check against the profiles the generator renders.

Every PenniLogic repository has exactly one entry naming the status-check context its generated
workflow produces (``check_name``), the ``PenniLogic/infra`` commit whose generator rendered the
workflow on its ``main`` (``workflow_ref``) and the stack the workflow exercises (``language``).
The registry is data for the conformance job and for the owner-administered rulesets; it grants
nothing by itself.

    python governance/conformance/registry.py            # validate the registry against schema and profiles
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from conformance import defects, generator as generator_module  # noqa: E402
from conformance import schema as schema_module  # noqa: E402
from conformance import steps  # noqa: E402


HERE = Path(__file__).resolve().parent
REGISTRY_PATH = HERE / "check-names.json"
SCHEMA_PATH = HERE / "check-names.schema.json"
REGISTRY_SCHEMA_ID = "pennilogic.infra.check-names/1"
REQUIRED_FIELDS = ("repo", "check_name", "workflow_ref", "language")
CI_WORKFLOW = ".github/workflows/ci.yml"
PR_GATE_WORKFLOW = ".github/workflows/pr-workflow-integrity.yml"
# Primary native-CI stacks not inferred from every declared report toolchain.
LANGUAGE_OVERRIDES = {"docs": "documentation", "contracts": "openapi", "infra": "python"}


class RegistryError(ValueError):
    """The registry document is invalid; the message lists every violation."""


def json_document(content):
    """Strict JSON: UTF-8 without a byte order mark and without duplicate keys (as the checker reads it)."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise RegistryError(f"duplicate JSON key {key!r}")
            value[key] = item
        return value
    text = content.decode("utf-8")
    if text.startswith("\ufeff"):
        raise RegistryError("byte order mark before the JSON document")
    return json.loads(text, object_pairs_hook=unique)


def load_schema(path=SCHEMA_PATH):
    schema = json_document(Path(path).read_bytes())
    schema_module.check_schema(schema)
    return schema


def load_registry(path=REGISTRY_PATH):
    return json_document(Path(path).read_bytes())


def expected_language(name, profile):
    """The primary native-CI stack; infra's optional report toolchain does not change its language."""
    if name in LANGUAGE_OVERRIDES:
        return LANGUAGE_OVERRIDES[name]
    if "java" in profile:
        return "kotlin"
    if "node" in profile:
        return "typescript"
    return "python"


def profile_name(repo, generator=None):
    generator = generator or generator_module.load()
    owner = generator.PROFILES["organization"] + "/"
    return repo[len(owner):] if repo.startswith(owner) else None


def validate_registry(document, schema=None):
    """Return every schema and uniqueness violation of a registry document."""
    schema = schema or load_schema()
    errors = schema_module.validate(document, schema)
    if errors:
        return errors
    seen = set()
    for index, entry in enumerate(document["entries"]):
        if entry["repo"] in seen:
            errors.append(f"/entries/{index}/repo: repository listed twice")
        seen.add(entry["repo"])
    return errors


def cross_check(document, generator=None):
    """Return the mismatches between the registry and the profiles the generator renders.

    Each profile needs exactly one entry; the entry's check name must be produced by the rendered
    ``ci.yml`` (a job name) and equal the policy's required native check; the language must match
    the profile toolchain.
    """
    generator = generator or generator_module.load()
    errors = []
    by_name = {}
    for index, entry in enumerate(document["entries"]):
        name = profile_name(entry["repo"], generator)
        if name is None or name not in generator.PROFILES["repositories"]:
            errors.append(f"/entries/{index}/repo: no generator profile for {entry['repo']}")
            continue
        by_name.setdefault(name, []).append((index, entry))
    for name, profile in generator.PROFILES["repositories"].items():
        entries = by_name.get(name, [])
        if len(entries) != 1:
            errors.append(f"profile {name}: expected exactly one registry entry, found {len(entries)}")
            continue
        index, entry = entries[0]
        artifacts = generator.artifacts(name)
        produced = steps.produced_check_names(artifacts[".github/workflows/ci.yml"].encode("utf-8"))
        if entry["check_name"] not in produced:
            errors.append(f"/entries/{index}/check_name: not produced by the rendered ci.yml jobs {sorted(produced)}")
        policy = json.loads(artifacts[".github/agent-policy.json"])
        if entry["check_name"] != policy["required_native_check"]:
            errors.append(f"/entries/{index}/check_name: differs from the policy's required native check")
        if entry["language"] != expected_language(name, profile):
            errors.append(f"/entries/{index}/language: expected {expected_language(name, profile)} for profile {name}")
        gate = entry.get("pr_gate")
        if profile.get("pr_workflow_integrity", False):
            if gate is None:
                errors.append(f"/entries/{index}/pr_gate: opted-in profile needs its source binding")
            else:
                produced_gate = steps.produced_check_names(artifacts[PR_GATE_WORKFLOW].encode("utf-8"))
                if gate["check_name"] not in produced_gate or gate["check_name"] != generator.PR_GATE_NAME:
                    errors.append(f"/entries/{index}/pr_gate/check_name: not the native PR gate producer")
        elif gate is not None:
            errors.append(f"/entries/{index}/pr_gate: profile has not opted in")
    return errors


def render_workflow_at(infra_root, ref, name, run=subprocess.run, workflow_file=CI_WORKFLOW):
    """Render ``.github/workflows/ci.yml`` for profile ``name`` with the generator as of commit ``ref``.

    Reads ``generate.py`` and ``repository-profiles.json`` from Git history (no checkout) into a
    temporary directory and calls that generator's ``workflow``; returns ``None`` when the commit is
    not present in the local history (a shallow clone) or the profile did not exist at that commit.
    """
    def show(path):
        result = run(["git", "-C", str(infra_root), "show", f"{ref}:{path}"], capture_output=True, check=False,
                     env=defects.probe_environment(), timeout=60)
        return None if result.returncode else result.stdout
    if workflow_file not in (CI_WORKFLOW, PR_GATE_WORKFLOW):
        raise RegistryError("historical rendering supports only the two native PR producers")
    source = show("governance/generate.py")
    profiles = show("governance/repository-profiles.json")
    if source is None or profiles is None:
        return None
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / "generate.py").write_bytes(source)
        (root / "repository-profiles.json").write_bytes(profiles)
        if workflow_file == PR_GATE_WORKFLOW:
            template = show("governance/templates/pr_workflow_integrity.py")
            if template is None:
                return None
            (root / "templates").mkdir()
            (root / "templates" / "pr_workflow_integrity.py").write_bytes(template)
        historical = generator_module.load(root / "generate.py", name=f"generator_at_{ref}")
        if name not in historical.PROFILES["repositories"]:
            return None
        if workflow_file == PR_GATE_WORKFLOW:
            if not hasattr(historical, "pr_integrity_workflow"):
                return None
            rendered = historical.pr_integrity_workflow(name).encode("utf-8")
            committed = show(workflow_file)
            if committed != rendered:
                raise RegistryError("PR gate source commit does not contain its rendered native workflow")
            return rendered
        return historical.workflow(name).encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--schema", type=Path, default=SCHEMA_PATH)
    args = parser.parse_args(argv)
    try:
        schema = load_schema(args.schema)
        document = load_registry(args.registry)
    except (OSError, ValueError, UnicodeDecodeError, schema_module.SchemaError) as error:
        print(f"Check-name registry unreadable: {error}", file=sys.stderr)
        return 1
    errors = validate_registry(document, schema)
    if not errors:
        errors = cross_check(document)
    for error in errors:
        print(f"Check-name registry: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"Check-name registry valid: {len(document['entries'])} repositories, each producing its required check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
