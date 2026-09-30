"""Load the canonical generator (``governance/generate.py``) as a module without importing side effects
beyond reading ``repository-profiles.json``; the same file-based loading the governance tests use."""

import importlib.util
from pathlib import Path


GOVERNANCE = Path(__file__).resolve().parents[1]
INFRA_ROOT = GOVERNANCE.parent
_CACHE = {}


def load(path=None, name="public_generator"):
    """Return the generator module at ``path`` (default: the sibling ``generate.py``), cached by path."""
    path = Path(path or GOVERNANCE / "generate.py").resolve()
    key = (str(path), name)
    if key not in _CACHE:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CACHE[key] = module
    return _CACHE[key]


def profiles(generator=None):
    generator = generator or load()
    return generator.PROFILES["repositories"]


def repository_full_name(profile_name, generator=None):
    generator = generator or load()
    return f"{generator.PROFILES['organization']}/{profile_name}"
