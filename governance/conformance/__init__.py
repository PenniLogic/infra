"""CI conformance job for the nine PenniLogic repositories (PenniLogic/infra#24).

Read-only against every consumer: the job clones each repository's ``main`` into a scratch
directory, asserts the numeric repository id, verifies the generated baseline byte for byte,
runs the consumer's own ``scripts/check_repository.py``, plants defects in the scratch tree and
proves the profile's real command refuses them, checks that every check name the branch ruleset
requires is produced by a workflow, records the last ``main`` CI wall-clock against the ten-minute
budget, and writes a machine-readable report plus a Markdown summary. Nothing is written to any
consumer repository; the scratch tree is restored after every planted defect.

Standard library only. ``CI_CONFORMANCE.md`` at the repository root explains how to run it, how to
read the report and why the workflow that would schedule it is a generated-setup request.
"""
