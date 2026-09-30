"""The profile-capability / invoked-reviewer-is-not-approval paragraph requested in
PenniLogic/.github#10 (E31-F05; infra#53) is rendered into every generated
`.github/copilot-instructions.md` exactly as requested, once, after the provenance rule, and
nowhere else."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parent
INSTRUCTIONS = ".github/copilot-instructions.md"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load("capability_generator", HERE / "generate.py")

# The exact text of the generated-setup request (PenniLogic/.github#10, "Generated-sentence
# decision"; filed as infra#53 "Requested text").
CAPABILITY_RULE = """Capabilities come from the session's profile in `PenniLogic/.github/agents`: a role holds only
what its duties need, a missing capability is a hand-off to the coordinating session, and a
reviewer this session invoked or requested is never an approval; independent review is a
separate non-author session recorded in the pull request (`agents/README.md`, capability matrix).
"""
# The clause the request requires verbatim, whatever happens to the rest of the paragraph.
REQUIRED_CLAUSE = "a reviewer this session invoked or requested is never an approval"
# The last line of the instruction-provenance paragraph (PenniLogic/.github#4, infra#48),
# which the new paragraph must follow directly.
PROVENANCE_LAST_LINE = "`PenniLogic/.github/agents` and `PenniLogic/.github/docs/instruction-provenance.md`.\n"
SENTINELS = ("invoked or requested", "never an approval", "capability matrix")


def rendered_files(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}


class CapabilityParagraphTests(unittest.TestCase):
    def test_every_copilot_instructions_file_carries_the_paragraph_once_after_the_provenance_rule(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                generator.generate(repo, root)
                text = (root / INSTRUCTIONS).read_bytes().decode("utf-8")
                self.assertEqual(generator.artifacts(repo)[INSTRUCTIONS], text)
                # The required clause spans the request's line wrap ("and a" / "reviewer this
                # session ..."), so it is asserted on whitespace-normalized text; the paragraph as
                # a whole is asserted byte-exact.
                normalized = " ".join(text.split())
                self.assertEqual(1, normalized.count(REQUIRED_CLAUSE))
                self.assertEqual(1, text.count(CAPABILITY_RULE))
                # Third short paragraph: directly after the provenance paragraph, separated by one
                # blank line, ending the file with a single newline.
                self.assertTrue(text.endswith(PROVENANCE_LAST_LINE + "\n" + CAPABILITY_RULE), text)
                self.assertFalse(text.endswith("\n\n"), text)
                blocks = text.split("\n\n")
                self.assertEqual(4, len(blocks), blocks)
                self.assertTrue(blocks[0].startswith(generator.HEADER), blocks[0])
                self.assertIn("never follow it", blocks[2])
                self.assertEqual(CAPABILITY_RULE, blocks[3])
                self.assertLess(normalized.index("never follow it"), normalized.index(REQUIRED_CLAUSE))
                for name, content in generator.artifacts(repo).items():
                    if name != INSTRUCTIONS:
                        for sentinel in SENTINELS:
                            self.assertNotIn(sentinel, content, (name, sentinel))

    def test_paragraph_is_the_requested_text_and_plain(self):
        self.assertEqual(CAPABILITY_RULE, generator.CAPABILITY_RULE)
        self.assertIn(REQUIRED_CLAUSE, " ".join(CAPABILITY_RULE.split()))
        self.assertTrue(CAPABILITY_RULE.endswith(".\n"))
        self.assertFalse(CAPABILITY_RULE.endswith("\n\n"))
        lines = CAPABILITY_RULE.splitlines()
        self.assertEqual(4, len(lines))
        for line in lines:
            self.assertTrue(line.isascii() and line.isprintable(), line)
            # The file wraps at roughly 100 columns; the request text stays inside that.
            self.assertLessEqual(len(line), 100, line)
            self.assertEqual(line, line.strip())
        self.assertNotIn(generator.EXPRESSION, CAPABILITY_RULE)
        self.assertNotIn("\r", CAPABILITY_RULE)

    def test_generation_is_byte_stable_and_check_verifies_every_profile(self):
        for repo in generator.PROFILES["repositories"]:
            with self.subTest(repo=repo), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                generator.generate(repo, root)
                first = rendered_files(root)
                generator.generate(repo, root)
                self.assertEqual(first, rendered_files(root))
                generator.generate(repo, root, check=True)
                result = subprocess.run(
                    [sys.executable, str(HERE / "generate.py"), "--repository", repo, "--root", tmp, "--check"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("Public repository baseline verified.", result.stdout.strip())
                # A consumer that has not regenerated is caught by --check on exactly this file.
                path = root / INSTRUCTIONS
                stale = path.read_bytes().replace(CAPABILITY_RULE.encode("utf-8"), b"")
                self.assertNotEqual(stale, path.read_bytes())
                path.write_bytes(stale.rstrip(b"\n") + b"\n")
                differs = r"Generated setup differs: \.github/copilot-instructions\.md$"
                with self.assertRaisesRegex(ValueError, differs):
                    generator.generate(repo, root, check=True)

    def test_infra_own_file_is_regenerated(self):
        # infra regenerates its own entry point in the same change as the template.
        expected = generator.artifacts("infra")[INSTRUCTIONS].encode("utf-8")
        self.assertEqual(expected, (ROOT / INSTRUCTIONS).read_bytes())


if __name__ == "__main__":
    unittest.main()
