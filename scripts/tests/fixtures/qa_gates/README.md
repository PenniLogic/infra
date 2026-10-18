# Synthetic JUnit samples for the infra#28 quarantine gate

These files are hand-written synthetic samples shaped after the documented JUnit XML output of Gradle, pytest,
Vitest and Maven Surefire. They were **not** captured from those tools, contain no real test names or project
data, and do not establish parser fidelity against real producer output; that remains unverified until real
reports are ingested in CI (held integration). `surefire-rerun-shaped.xml` shows an in-file re-run element,
which the gate refuses because a retry inside one report hides an attempt.
