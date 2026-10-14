"""Planted injection-prone patterns for the PenniLogic/infra#28 SAST rule set (synthetic; never imported or run).

Each function is a deliberate positive for one rule in scripts/qa-gates/rules/python.yml. The data is synthetic
and the module is not a package member, so unittest discovery and the application never load it.
"""

import os
import subprocess


def planted_sql_built_string(cursor, account_name):
    cursor.execute(f"SELECT id FROM synthetic_accounts WHERE name = '{account_name}'")


def planted_sql_percent_format(cursor, account_name):
    cursor.execute("SELECT id FROM synthetic_accounts WHERE name = '%s'" % account_name)


def planted_shell_command(archive_name):
    subprocess.run("tar -tf " + archive_name, shell=True, check=False)


def planted_os_system(archive_name):
    os.system("ls " + archive_name)


def planted_dynamic_eval(expression):
    return eval(expression)
