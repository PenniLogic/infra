"""governance/README.md stays true to the code it documents (PenniLogic/infra#54, notes Q1, C1
and C2 of PR #51): the rule table lists every `Refused` message of the checker template in the
order `validate_workflow` evaluates them, the prose names the stages by the right rule numbers,
and the generated-file list is exactly what `artifacts()` renders."""

import ast
import fnmatch
import importlib.util
from pathlib import Path
import re
import unittest


HERE = Path(__file__).resolve().parents[1]
TEMPLATE = HERE / "templates/check_repository.py"
README = HERE / "README.md"
# Backticked names in the first paragraph that are not generated files.
NOT_GENERATED = {"generate.py", "repository-profiles.json", "main", "artifacts()", "governance/tests/test_rule_table.py"}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("rule_table_generator", HERE / "generate.py")


def module_functions(source):
    tree = ast.parse(source)
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def refusals(node, functions, stack=()):
    """Yield the `raise Refused("...")` messages reachable from `node`, in evaluation order.

    The checker is straight-line code whose rules are early raises: within a function the
    evaluation order is the source order, and a call to another module-level function evaluates
    that function's rules at the call site, so it is expanded in place (once per call chain, so
    the recursive walkers terminate). Loops evaluate their body per element; the README states
    that interleaving in prose and the table keeps the per-element order.
    """
    if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name) and node.exc.func.id == "Refused"):
        yield node.exc.args[0].value
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in functions and node.func.id not in stack):
        yield from refusals(functions[node.func.id], functions, stack + (node.func.id,))
    for child in ast.iter_child_nodes(node):
        yield from refusals(child, functions, stack)


def first_loop(function):
    return next(node for node in ast.walk(function) if isinstance(node, ast.For))


class RuleTableTests(unittest.TestCase):
    def setUp(self):
        self.source = TEMPLATE.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")
        self.functions = module_functions(self.source)
        self.order = list(refusals(self.functions["validate_workflow"], self.functions, ("validate_workflow",)))

    def test_readme_table_lists_every_rule_in_evaluation_order(self):
        rows = re.findall(r"^\| (\d+) \| `([^`]+)` \| .+ \|$", self.readme, re.MULTILINE)
        self.assertEqual([str(number) for number in range(1, len(self.order) + 1)], [number for number, _ in rows])
        self.assertEqual(self.order, [text for _, text in rows])
        # Every Refused of the template is reachable from validate_workflow exactly once, so the
        # table is complete and the order above is the order of the whole checker.
        messages = re.findall(r'raise Refused\("([^"\\{}]*)"\)', self.source)
        self.assertEqual(self.source.count("raise Refused("), len(messages))
        self.assertEqual(sorted(messages), sorted(self.order))
        self.assertEqual(len(set(self.order)), len(self.order))
        self.assertEqual(32, len(self.order))
        # The document rules stay first; PR G extends only the per-file/profile exception.
        self.assertEqual(["UTF-8 byte order mark before the JSON document", "Duplicate JSON key",
                          "workflow document must be one JSON object", "expected read-only workflow token",
                          "unreviewed workflow expression; public jobs must not receive secrets"], self.order[:5])
        self.assertEqual("action commit differs from the generated pin; regenerate instead of editing it", self.order[8])
        self.assertTrue(self.order[-11].startswith("CI must run on exactly"))
        self.assertEqual("workflow file outside the generated pair or infra-only conformance.yml", self.order[-1])

    def test_source_order_equals_evaluation_order_inside_each_stage(self):
        # The derivation above relies on each helper being straight-line: its rules appear in the
        # source in the order they are evaluated. json_document is the one place where a nested
        # hook runs later than its definition would suggest, so the hook is defined after the BOM
        # rule; this pins that placement.
        json_document = ast.get_source_segment(self.source, self.functions["json_document"])
        self.assertLess(json_document.index("UTF-8 byte order mark"), json_document.index("def unique"))
        self.assertLess(json_document.index("def unique"), json_document.index("Duplicate JSON key"))
        # No rule is raised directly by check(), main(), the inventory or the walkers: every rule
        # belongs to validate_workflow's stages (the empty function table disables expansion).
        for name in ("check", "main", "inventory", "git", "workflow_strings", "workflow_mappings"):
            self.assertEqual([], list(refusals(self.functions[name], {})), name)

    def test_readme_names_the_stages_by_their_rule_numbers(self):
        def span(messages):
            numbers = [self.order.index(message) + 1 for message in messages]
            self.assertEqual(list(range(numbers[0], numbers[-1] + 1)), numbers)
            return f"{numbers[0]}-{numbers[-1]}"

        functions = self.functions
        mappings = list(refusals(functions["validate_mappings"], functions, ("validate_mappings",)))
        shape = list(refusals(functions["validate_shape"], functions, ("validate_shape",)))
        per_mapping = list(refusals(first_loop(functions["validate_mappings"]), functions, ("validate_mappings",)))
        per_job = list(refusals(first_loop(functions["validate_shape"]), functions, ("validate_shape",)))
        runner = list(refusals(first_loop(functions["validate_workflow"]), functions, ("validate_workflow",)))
        per_file = self.order[self.order.index(runner[-1]) + 1:]
        self.assertEqual(mappings, per_mapping)
        self.assertEqual(6, len(mappings))
        self.assertEqual(6, len(shape))
        self.assertEqual(4, len(per_job))
        self.assertEqual(2, len(runner))
        self.assertEqual(11, len(per_file))
        # Prose ranges: per-element interleaving (C2) and the stage descriptions after the table.
        for text in (f"rules {span(per_mapping)} are applied to each mapping", f"rules {span(per_job)} to each job",
                     f"rules {span(runner)} to each job in turn", f"Rules {span(shape)} accept exactly the keys",
                     f"Rules {span(mappings[1:3])} bind each `uses`", f"Rules {span(per_file)} bind each generated workflow file"):
            self.assertIn(text, self.readme)
        # The two rules named as tripwires point at the rule they stand behind.
        self.assertIn(f"(tripwire behind rule {self.order.index(self.order[4]) + 1})", self.readme)
        job_key = self.order.index("job-level key outside the generated job keys name, runs-on, timeout-minutes, env, steps") + 1
        self.assertIn(f"tripwire behind rule {job_key}, which already refuses the key", self.readme)
        self.assertEqual(16, job_key)

    def test_readme_generated_file_list_is_exactly_what_artifacts_renders(self):
        paragraph = self.readme.split("\n\n")[1]
        self.assertTrue(paragraph.startswith("`generate.py` renders"), paragraph)
        listed = [token for token in re.findall(r"`([^`]+)`", paragraph) if token not in NOT_GENERATED]
        conformance = ".github/workflows/conformance.yml"
        self.assertIn(conformance, listed)
        self.assertIn("20 common files", paragraph)
        self.assertIn("infra alone has 21 files", paragraph)
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo):
                names = sorted(generator.artifacts(repo))
                self.assertEqual(21 if repo == "infra" else 20, len(names))
                applicable = [token for token in listed if token != conformance or repo == "infra"]
                self.assertIn(".github/instructions/source.instructions.md", names)
                for name in names:
                    self.assertTrue(any(fnmatch.fnmatchcase(name, token) for token in applicable), name)
                for token in applicable:
                    self.assertTrue(any(fnmatch.fnmatchcase(name, token) for name in names), token)
        self.assertIn("`.github/instructions/source.instructions.md`", paragraph)
        self.assertEqual(len(set(listed)), len(listed))


if __name__ == "__main__":
    unittest.main()
