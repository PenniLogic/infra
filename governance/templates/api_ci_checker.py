import hashlib


API_CI_SHA256 = "__API_CI_SHA256__"
REQUIRED += ("scripts/qualify_windows.py",)


def validate_workflow(name, data):
    if name == ".github/workflows/ci.yml":
        if hashlib.sha256(data).hexdigest() != API_CI_SHA256:
            raise Refused("API CI must match its generated qualification jobs and required result")
    else:
        validate_non_api_ci_workflow(name, data)
