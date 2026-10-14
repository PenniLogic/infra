"""Clean control for the PenniLogic/infra#28 SAST rule set (synthetic; never imported or run).

The safe counterparts of planted_injection.py: no rule in scripts/qa-gates/rules/python.yml may match here.
"""

import subprocess


def control_sql_bound_parameter(cursor, account_name):
    cursor.execute("SELECT id FROM synthetic_accounts WHERE name = %s", (account_name,))


def control_argument_list(archive_name):
    subprocess.run(["tar", "-tf", archive_name], check=False)


def control_literal_eval():
    return eval("1 + 1")
