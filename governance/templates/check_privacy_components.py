"""Resolve fresh Android components, then run the owning privacy harness assertion."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from privacy_traffic.safety import MAX_DOCUMENT_BYTES, Refusal, physical, require
from privacy_traffic_harness import main as privacy_main
from quality_gates import EXECUTED, ROOT, run_gradle, task_labels


TASK = ":app:privacyComponentInventory"
PREFIX = "PRIVACY_COMPONENT_INVENTORY "


def main() -> int:
    try:
        init_script = physical(ROOT / "scripts" / "privacy_traffic" / "components.init.gradle")
        run = run_gradle((TASK,), ("--init-script", str(init_script), "--no-configuration-cache"))
        if run.exit_code:
            print("Privacy component inventory: native resolution failed.", file=sys.stderr)
            return run.exit_code
        require(task_labels(run.console).get(TASK) == [EXECUTED], "component_inventory_not_fresh")
        lines = [line for line in run.console.splitlines() if line.startswith(PREFIX.rstrip())]
        require(len(lines) == 1 and lines[0].startswith(PREFIX), "component_inventory_prefix_refused")
        raw = lines[0][len(PREFIX):].encode("utf-8")
        require(0 < len(raw) <= MAX_DOCUMENT_BYTES, "component_inventory_size_refused")
        build = physical(ROOT / "build")
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="privacy-components-", dir=build) as directory:
            inventory = Path(directory) / "inventory.json"
            with inventory.open("xb") as stream:
                stream.write(raw)
            return privacy_main(["check-components", str(inventory)])
    except Refusal as error:
        print(json.dumps({"code": error.code, "release_qualified": False}), file=sys.stderr)
        return 2
    except OSError:
        print("Privacy component inventory: owned input/output operation failed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
