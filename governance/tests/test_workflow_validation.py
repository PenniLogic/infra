"""Workflow validation of the generated repository checker: the secret tripwire runs
over decoded strings, `if` is refused at any nesting level and only the actions and
inputs the generator emits are accepted (PenniLogic/infra#46, findings S1/S2 of PR #45)."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parents[1]
SHA = "0123456789abcdef0123456789abcdef01234567"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("workflow_generator", HERE / "generate.py")
checker = load("workflow_checker", HERE / "templates/check_repository.py")

# Whitespace GitHub's expression lexer skips (Char.IsWhiteSpace) between the tokens of a
# secret read. json.dumps escapes each of these, so a regex over the serialized document
# cannot span them; the decoded strings must be searched instead.
WHITESPACE = ("\n", "\t", "\r\n", "\r", "\x0b", "\x0c", "\u00a0", "\u0085", "\u1680", "\u2028", "\u2029", "\u3000",
              " \n\t ")
SPLIT_TOKEN_READS = tuple(f"github{space}.token" for space in WHITESPACE) + (
    "github.\ntoken", "github\n.\ttoken", "github\n[ 'token' ]", "github\u00a0['token']",
    "toJSON(\ngithub)", "toJSON(\tgithub)", "toJSON\n(github)", "toJSON(\u00a0github\u00a0)",
    "fromJSON(toJSON(\ngithub)).token", "format('{0}', github\n.token)", "startsWith(github\n.token, 'ghs_')",
    # Leading whitespace also hid the read: the escape's letter joins the word, so `\b` fails.
    "\ngithub.token", "\tsecrets.NPM_TOKEN",
)
# Each form is refused wherever it appears; the levels below reach the workflow, the job,
# its snapshot and the step, including the three `${{`-less condition fields.
LEVELS = ("workflow-name", "workflow-env", "workflow-env-key", "concurrency", "dispatch-input",
          "job-name", "job-env", "job-if", "job-container", "job-services", "job-outputs", "job-strategy",
          "snapshot-if", "snapshot-image-name", "snapshot-string",
          "step-name", "step-if", "step-env", "step-env-key", "step-with", "step-run")
CONDITION_LEVELS = ("job-if", "snapshot-if", "step-if")


def placed(level, text, repo="web"):
    """Return the generated CI workflow of `repo` with `text` inserted at one placement."""
    workflow = json.loads(generator.workflow(repo))
    job = workflow["jobs"]["ci"]
    step = job["steps"][-1]
    if level == "workflow-name":
        workflow["name"] = f"CI {text}"
    elif level == "workflow-env":
        workflow["env"] = {"NPM_TOKEN": text}
    elif level == "workflow-env-key":
        workflow["env"] = {text: "1"}
    elif level == "concurrency":
        workflow["concurrency"]["group"] = text
    elif level == "dispatch-input":
        workflow["on"]["workflow_dispatch"] = {"inputs": {"ref": {"default": text}}}
    elif level == "job-name":
        job["name"] = f"CI {text}"
    elif level == "job-env":
        job["env"] = {"NPM_TOKEN": text}
    elif level == "job-if":
        job["if"] = text
    elif level == "job-container":
        job["container"] = {"image": "ghcr.io/x/y", "credentials": {"username": "x", "password": text}}
    elif level == "job-services":
        job["services"] = {"db": {"image": "postgres:17", "env": {"POSTGRES_PASSWORD": text}}}
    elif level == "job-outputs":
        job["outputs"] = {"value": text}
    elif level == "job-strategy":
        job["strategy"] = {"matrix": {"value": [text]}}
    elif level == "snapshot-if":
        job["snapshot"] = {"image-name": "ubuntu-custom", "if": text}
    elif level == "snapshot-image-name":
        job["snapshot"] = {"image-name": text}
    elif level == "snapshot-string":
        job["snapshot"] = text
    elif level == "step-name":
        step["name"] = f"Run {text}"
    elif level == "step-if":
        step["if"] = text
    elif level == "step-env":
        step["env"] = {"NPM_TOKEN": text}
    elif level == "step-env-key":
        step["env"] = {text: "1"}
    elif level == "step-with":
        job["steps"][0]["with"]["token"] = text
    elif level == "step-run":
        step["run"] += f"\necho {text}"
    else:
        raise ValueError(level)
    return workflow


def validate(workflow, name=".github/workflows/ci.yml"):
    checker.validate_workflow(name, json.dumps(workflow).encode())


def tripwire_hits(workflow):
    return any(checker.WORKFLOW_SECRET_ACCESS.search(text) for text in checker.workflow_strings(workflow))


class TripwireTests(unittest.TestCase):
    def test_every_level_of_every_generated_workflow_is_searched(self):
        # The walk reaches every key and string; each generated workflow stays clear of the tripwire.
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                workflow = json.loads(generator.workflow(repo, setup=setup))
                strings = list(checker.workflow_strings(workflow))
                self.assertIn("persist-credentials", strings)
                self.assertIn("python scripts/check_repository.py", " ".join(strings))
                self.assertFalse(tripwire_hits(workflow), repo)
        for level in LEVELS:
            with self.subTest(level=level):
                self.assertFalse(tripwire_hits(placed(level, "plain text")))
                self.assertTrue(tripwire_hits(placed(level, "github.token")))

    def test_whitespace_split_token_reads_are_refused_at_every_level(self):
        for form in SPLIT_TOKEN_READS:
            expression = "${{ " + form + " }}"
            for level in LEVELS:
                with self.subTest(level=level, form=form):
                    workflow = placed(level, expression)
                    with self.assertRaisesRegex(ValueError, "secrets"):
                        validate(workflow)
                    # The tripwire alone refuses the decoded strings, while the serialized document
                    # hides the same read behind a JSON escape (S1): the walk is not optional.
                    self.assertTrue(tripwire_hits(workflow))
                    self.assertIsNone(checker.WORKFLOW_SECRET_ACCESS.search(json.dumps(workflow)))
                    if level in CONDITION_LEVELS:
                        # Conditions evaluate the same read without `${{`; the tripwire, not the
                        # `if` refusal, must be the reason so that the message names the secret.
                        with self.assertRaisesRegex(ValueError, "secrets"):
                            validate(placed(level, form))

    def test_tripwire_still_refuses_a_mistakenly_widened_allowlist(self):
        # The property S1 asked for: even if a whitespace-split expression were allowlisted by
        # mistake, the tripwire behind the allowlist refuses it at every level.
        for form in SPLIT_TOKEN_READS:
            expression = "${{ " + form + " }}"
            with mock.patch.object(checker, "WORKFLOW_EXPRESSIONS", checker.WORKFLOW_EXPRESSIONS | {expression}):
                for level in LEVELS:
                    with self.subTest(level=level, form=form):
                        with self.assertRaisesRegex(ValueError, "public candidate jobs must not receive secrets"):
                            validate(placed(level, expression))
        # Control: a widened allowlist does admit an innocuous expression, so the test above
        # proves the tripwire and not the allowlist.
        with mock.patch.object(checker, "WORKFLOW_EXPRESSIONS", checker.WORKFLOW_EXPRESSIONS | {"${{ github.sha }}"}):
            validate(placed("step-env", "${{ github.sha }}"))
        with self.assertRaisesRegex(ValueError, "unreviewed workflow expression"):
            validate(placed("step-env", "${{ github.sha }}"))

    def test_tripwire_whitespace_covers_the_expression_lexer(self):
        # Python's `\s` (str.isspace) covers every character .NET Char.IsWhiteSpace skips:
        # controls U+0009-U+000D, U+0085 and the Zs/Zl/Zp separators.
        for space in WHITESPACE:
            self.assertRegex(space, r"^\s+$")
            self.assertIsNotNone(checker.WORKFLOW_SECRET_ACCESS.search(f"github{space}.{space}token"))
            self.assertIsNotNone(checker.WORKFLOW_SECRET_ACCESS.search(f"toJSON({space}github{space})"))
            self.assertIsNotNone(checker.WORKFLOW_SECRET_ACCESS.search(f"github{space}['token']"))

    def test_secret_context_and_bracket_reads_stay_refused(self):
        for form in ("secrets.NPM_TOKEN", "secrets\n.NPM_TOKEN", "SECRETS['X']", "toJSON(secrets)",
                     "github['token']", 'github["token"]', "github[format('to{0}', 'ken')]", "GitHub.Token",
                     "github.token", "toJson(github)", "TOJSON(GITHUB)"):
            for level in ("job-if", "step-if", "snapshot-if", "step-run", "workflow-env-key"):
                with self.subTest(level=level, form=form):
                    with self.assertRaisesRegex(ValueError, "secrets"):
                        validate(placed(level, form))
        # Words that merely resemble the contexts do not trip.
        validate(placed("step-run", "secretsmanager github_token tokens github.tokens githubtoken.json"))


class ConditionTests(unittest.TestCase):
    def test_if_is_refused_at_the_three_schema_placements(self):
        # workflow-v1.0.json: job-if, step-if and snapshot-if are the condition fields, and each
        # evaluates its expression without `${{`.
        for level in CONDITION_LEVELS:
            for condition in ("true", "always()", "success()", "github.event_name == 'push'", "!cancelled()"):
                with self.subTest(level=level, condition=condition):
                    with self.assertRaisesRegex(ValueError, "conditions are not part of the generated workflows"):
                        validate(placed(level, condition))
            for condition in ("github.token != ''", "github\n.token != ''", "startsWith(github\n.token, 'ghs_a')",
                              "toJSON(\ngithub) != ''", "secrets.X != ''"):
                with self.subTest(level=level, condition=condition):
                    with self.assertRaisesRegex(ValueError, "secrets"):
                        validate(placed(level, condition))
        # The snapshot mapping is not a condition; the job-key allowlist refuses it as a key, and a
        # token inside it is still reported by the tripwire first.
        with self.assertRaisesRegex(ValueError, "job-level key"):
            validate(placed("snapshot-image-name", "ubuntu-custom"))
        with self.assertRaisesRegex(ValueError, "secrets"):
            validate(placed("snapshot-image-name", "github\n.token"))

    def test_if_is_refused_at_any_nesting_level(self):
        def at(path, seed=None):
            workflow = json.loads(generator.workflow("web"))
            node = workflow
            for key in path:
                if isinstance(key, int):
                    node = node[key]
                else:
                    node = node.setdefault(key, {})
            node.update(seed or {})
            node["if"] = "true"
            return workflow

        placements = {
            "top-level": (),
            "on.workflow_dispatch": ("on", "workflow_dispatch"),
            "on.workflow_dispatch.inputs": ("on", "workflow_dispatch", "inputs"),
            "concurrency": ("concurrency",),
            "jobs.ci": ("jobs", "ci"),
            "jobs.ci.env": ("jobs", "ci", "env"),
            "jobs.ci.container": ("jobs", "ci", "container"),
            "jobs.ci.services.db": ("jobs", "ci", "services", "db"),
            "jobs.ci.strategy": ("jobs", "ci", "strategy"),
            "jobs.ci.strategy.matrix": ("jobs", "ci", "strategy", "matrix"),
            "jobs.ci.defaults.run": ("jobs", "ci", "defaults", "run"),
            "jobs.ci.snapshot": ("jobs", "ci", "snapshot"),
            "jobs.ci.steps[0]": ("jobs", "ci", "steps", 0),
            "jobs.ci.steps[-1]": ("jobs", "ci", "steps", -1),
            "jobs.ci.steps[-1].env": ("jobs", "ci", "steps", -1, "env"),
            "jobs.ci.services.db.env": ("jobs", "ci", "services", "db", "env"),
            "jobs.other": ("jobs", "other"),
        }
        seeds = {"jobs.ci.container": {"image": "ghcr.io/x/y"}, "jobs.ci.services.db": {"image": "postgres:17"},
                 "jobs.ci.snapshot": {"image-name": "ubuntu-custom"},
                 "jobs.other": {"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}}
        for placement, path in placements.items():
            with self.subTest(placement=placement):
                with self.assertRaisesRegex(ValueError, "conditions are not part of the generated workflows"):
                    validate(at(path, seeds.get(placement)))
        # Mappings inside lists at any depth, a reusable-workflow job, and non-string values.
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["ci"]["container"] = {"image": "ghcr.io/x/y", "extra": [{"nested": [{"if": "true"}]}]}
        with self.assertRaisesRegex(ValueError, "conditions"):
            validate(workflow)
        # Inside an action's `with`, the input allowlist refuses the key before the walk descends.
        with self.assertRaisesRegex(ValueError, "unreviewed action input"):
            validate(at(("jobs", "ci", "steps", 0, "with")))
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["reuse"] = {"uses": f"octo/x/.github/workflows/y.yml@{SHA}", "if": "true"}
        with self.assertRaisesRegex(ValueError, "conditions"):
            validate(workflow)
        for value in (True, False, 1, None, {}, [], ["true"], {"expression": "true"}):
            with self.subTest(value=value):
                workflow = json.loads(generator.workflow("web"))
                workflow["jobs"]["ci"]["steps"][-1]["if"] = value
                with self.assertRaisesRegex(ValueError, "conditions"):
                    validate(workflow)
        # A string value "if" is not a key and is not refused by this rule.
        validate(placed("step-run", "if"))
        validate(placed("step-name", "if"))

    def test_workflow_mappings_reaches_every_mapping(self):
        document = {"a": {"b": [{"c": 1}, [{"d": {"e": "x"}}], "s"]}, "f": []}
        mappings = list(checker.workflow_mappings(document))
        self.assertEqual(5, len(mappings))
        self.assertEqual([document, document["a"], {"c": 1}, {"d": {"e": "x"}}, {"e": "x"}], mappings)
        self.assertEqual([], list(checker.workflow_mappings("if")))
        self.assertEqual([], list(checker.workflow_mappings(["if", 1, None])))


class ActionAllowlistTests(unittest.TestCase):
    def test_allowlist_equals_the_actions_and_inputs_the_generator_emits(self):
        emitted, pins = {}, {}
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                workflow = json.loads(generator.workflow(repo, setup=setup))
                for mapping in checker.workflow_mappings(workflow):
                    if "uses" in mapping:
                        action, _, commit = mapping["uses"].partition("@")
                        pins.setdefault(action, set()).add(commit)
                        emitted.setdefault(action, set()).update(mapping.get("with", {}))
        self.assertEqual(checker.WORKFLOW_ACTIONS, emitted)
        self.assertEqual({f"actions/{name}": {pin} for name, pin in generator.PROFILES["actions"].items()}, pins)
        self.assertEqual({
            "actions/checkout": {"persist-credentials", "fetch-depth"}, "actions/setup-python": {"python-version"},
            "actions/setup-node": {"node-version-file"}, "actions/setup-java": {"distribution", "java-version"},
        }, checker.WORKFLOW_ACTIONS)
        for commits in pins.values():
            for commit in commits:
                self.assertIsNotNone(checker.ACTION_COMMIT.fullmatch(commit))
        # The action that receives github.token through a default input is not emitted and not listed.
        self.assertNotIn("actions/github-script", checker.WORKFLOW_ACTIONS)

    def test_github_script_is_refused_even_when_pinned(self):
        # actions/github-script is GitHub-owned and can be SHA-pinned, yet its default input
        # `github-token: ${{ github.token }}` hands the token to arbitrary script without any
        # expression appearing in this workflow, so only the exact emitted names pass.
        for inputs in (None, {"script": "console.log(context.repo)"},
                       {"script": "return 1", "result-encoding": "string"}):
            with self.subTest(inputs=inputs):
                workflow = json.loads(generator.workflow("web"))
                step = {"name": "Script", "uses": f"actions/github-script@{SHA}"}
                if inputs is not None:
                    step["with"] = inputs
                workflow["jobs"]["ci"]["steps"].append(step)
                self.assertFalse(tripwire_hits(workflow))
                with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
                    validate(workflow)

    def test_unlisted_unpinned_or_malformed_uses_is_refused_at_any_nesting_level(self):
        refused = (
            f"actions/cache@{SHA}", f"actions/upload-artifact@{SHA}", f"actions/download-artifact@{SHA}",
            f"actions/create-github-app-token@{SHA}", f"actions/attest-build-provenance@{SHA}",
            f"actions/setup-go@{SHA}", f"actions/setup-dotnet@{SHA}", f"actions/labeler@{SHA}", f"actions/stale@{SHA}",
            f"actions/dependency-review-action@{SHA}", f"actions/deploy-pages@{SHA}", f"actions/add-to-project@{SHA}",
            f"github/codeql-action/init@{SHA}", f"github/codeql-action/analyze@{SHA}", f"octo/evil@{SHA}",
            f"octo/evil/.github/workflows/x.yml@{SHA}", f"./.github/workflows/x.yml", "./.github/actions/local",
            "docker://alpine:3.20", f"docker://ghcr.io/octo/evil@sha256:{SHA}00000000000000000000000",
            f"Actions/Checkout@{SHA}", f"actions/Checkout@{SHA}", f"actions/checkout/@{SHA}",
            f"actions/checkout/subdir@{SHA}", f" actions/checkout@{SHA}", f"actions/checkout@{SHA} ",
            f"actions/checkout@{SHA}\n", f"actions/checkout@{SHA[:39]}", f"actions/checkout@{SHA}0",
            f"actions/checkout@{SHA.upper()}", f"actions/checkout@{SHA}@{SHA}", f"actions/checkout@v4",
            "actions/checkout@main", "actions/checkout@refs/tags/v4", f"actions/checkout@refs/heads/{SHA}",
            "actions/checkout", "actions/checkout@", f"@{SHA}", f"actions/checkout {SHA}", f"actions/setup-node@{SHA}x",
            f"actions/setup-python@{SHA[:20]}\u200b{SHA[20:]}",
        )
        for uses in refused:
            with self.subTest(uses=uses):
                workflow = json.loads(generator.workflow("web"))
                workflow["jobs"]["ci"]["steps"].append({"name": "Step", "uses": uses, "with": {"persist-credentials": False}})
                with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
                    validate(workflow)
        for uses in ([f"actions/checkout@{SHA}"], {"action": f"actions/checkout@{SHA}"}, None, 42, True):
            with self.subTest(uses=uses):
                workflow = json.loads(generator.workflow("web"))
                workflow["jobs"]["ci"]["steps"].append({"name": "Step", "uses": uses})
                with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
                    validate(workflow)
        # A job-level `uses` calls a reusable workflow this check never sees; it is refused whether
        # or not GitHub would also reject the `runs-on` pairing, and `secrets: inherit` trips first.
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["reuse"] = {"runs-on": "ubuntu-24.04", "uses": f"octo/x/.github/workflows/y.yml@{SHA}"}
        with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
            validate(workflow)
        workflow["jobs"]["reuse"]["secrets"] = "inherit"
        with self.assertRaisesRegex(ValueError, "public candidate jobs must not receive secrets"):
            validate(workflow)
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["reuse"] = {"uses": f"actions/checkout@{SHA}", "with": {"persist-credentials": False}}
        # A listed action as a reusable-workflow job passes the action rule; the job-key allowlist
        # then refuses `uses`/`with` at job level before the runner rule is reached.
        with self.assertRaisesRegex(ValueError, "job-level key"):
            validate(workflow)
        # Any other nesting of `uses` is held to the same rule.
        for path in (("jobs", "ci", "container"), ("jobs", "ci", "steps", -1, "env"), ("jobs", "ci", "env")):
            with self.subTest(path=path):
                workflow = json.loads(generator.workflow("web"))
                node = workflow
                for key in path:
                    node = node[key] if isinstance(key, int) else node.setdefault(key, {})
                node["uses"] = f"actions/github-script@{SHA}"
                with self.assertRaisesRegex(ValueError, "immutable and one of the generated GitHub-owned actions"):
                    validate(workflow)

    def test_listed_actions_pass_only_with_a_full_commit_and_checkout_stays_credential_free(self):
        for action, inputs in sorted(checker.WORKFLOW_ACTIONS.items()):
            with self.subTest(action=action):
                workflow = json.loads(generator.workflow("web"))
                step = {"name": "Step", "uses": f"{action}@{SHA}"}
                if action == "actions/checkout":
                    step["with"] = {"persist-credentials": False}
                workflow["jobs"]["ci"]["steps"].append(step)
                validate(workflow)
                if action != "actions/checkout":
                    for key in inputs:
                        step["with"] = {key: "1"}
                        validate(workflow)
        # The checker holds the name and the commit shape; the exact pin is the generator's
        # `--check` contract, so a consumer cannot loosen a pin by hand without a visible diff.
        for inputs in ({}, {"persist-credentials": True}, {"persist-credentials": "false"},
                       {"persist-credentials": None}, {"fetch-depth": 0}, None):
            with self.subTest(inputs=inputs):
                workflow = json.loads(generator.workflow("web"))
                checkout = workflow["jobs"]["ci"]["steps"][0]
                if inputs is None:
                    del checkout["with"]
                else:
                    checkout["with"] = inputs
                with self.assertRaisesRegex(ValueError, "checkout must not retain credentials"):
                    validate(workflow)
        for repo in generator.PROFILES["repositories"]:
            for setup in (False, True):
                name = f".github/workflows/{'copilot-setup-steps' if setup else 'ci'}.yml"
                checker.validate_workflow(name, generator.workflow(repo, setup=setup).encode())

    def test_unlisted_inputs_of_listed_actions_are_refused(self):
        # actions/checkout binds `AUTHORIZATION: basic x-access-token:<github.token>` to the origin
        # of its github-server-url input and fetches from it (src/git-auth-helper.ts,
        # src/url-helper.ts), so a plain string with no expression would send the job token to
        # another host. Only the inputs the generator emits are accepted, for every listed action.
        refused = {
            "actions/checkout": ("github-server-url", "token", "ssh-key", "ssh-known-hosts", "repository", "ref",
                                 "path", "submodules", "set-safe-directory", "Persist-Credentials",
                                 "persist-credentials ", "PERSIST-CREDENTIALS", "fetch_depth"),
            "actions/setup-python": ("token", "cache", "cache-dependency-path", "python-version-file"),
            "actions/setup-node": ("token", "registry-url", "scope", "mirror", "mirror-token", "cache",
                                   "always-auth", "node-version"),
            "actions/setup-java": ("token", "cache", "check-latest", "server-id", "server-username",
                                   "server-password", "gpg-private-key", "jdkFile"),
        }
        for action, keys in refused.items():
            for key in keys:
                with self.subTest(action=action, key=key):
                    workflow = json.loads(generator.workflow("web"))
                    inputs = {"persist-credentials": False} if action == "actions/checkout" else {}
                    inputs[key] = "https://evil.example" if key == "github-server-url" else "x"
                    workflow["jobs"]["ci"]["steps"].append({"name": "Step", "uses": f"{action}@{SHA}", "with": inputs})
                    self.assertFalse(tripwire_hits(workflow))
                    with self.assertRaisesRegex(ValueError, "unreviewed action input"):
                        validate(workflow)
            for inputs in ("persist-credentials: false", ["persist-credentials"], 1, None):
                with self.subTest(action=action, inputs=inputs):
                    workflow = json.loads(generator.workflow("web"))
                    workflow["jobs"]["ci"]["steps"].append({"name": "Step", "uses": f"{action}@{SHA}", "with": inputs})
                    with self.assertRaisesRegex(ValueError, "unreviewed action input"):
                        validate(workflow)
        # The generated checkout step itself, re-pointed at another host, is refused.
        workflow = json.loads(generator.workflow("web"))
        workflow["jobs"]["ci"]["steps"][0]["with"]["github-server-url"] = "https://evil.example"
        with self.assertRaisesRegex(ValueError, "unreviewed action input"):
            validate(workflow)


if __name__ == "__main__":
    unittest.main()
