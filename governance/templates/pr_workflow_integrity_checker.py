import hashlib


PR_GATE_FILE = ".github/workflows/pr-workflow-integrity.yml"
PR_GATE_SHA256 = "__PR_GATE_SHA256__"
REQUIRED += (PR_GATE_FILE,)


def validate_workflow(name, data):
    if name == PR_GATE_FILE:
        if hashlib.sha256(data).hexdigest() != PR_GATE_SHA256:
            raise Refused("PR workflow integrity must match its generated data-only workflow")
    else:
        validate_standard_workflow(name, data)
