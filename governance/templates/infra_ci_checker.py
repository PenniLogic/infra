import hashlib


INFRA_CI_SHA256 = "__INFRA_CI_SHA256__"


def validate_workflow(name, data):
    if name == ".github/workflows/ci.yml":
        if hashlib.sha256(data).hexdigest() != INFRA_CI_SHA256:
            raise Refused("Infra CI must match its generated qualification jobs and required result")
    else:
        validate_non_infra_ci_workflow(name, data)
