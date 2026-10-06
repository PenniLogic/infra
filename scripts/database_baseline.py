"""Finite, byte-exact PostgreSQL grammar for API's already accepted V001/V002.

No arbitrary procedural SQL is admitted. A one-byte semantic edit leaves this
finite language and must pass database_sql's closed DDL grammar instead. The
columns below are the complete stored shape of the pinned V002, not inferred
from column names. API retains its original SQL and its only execution path.
"""

from database_sql import Shape


API_REPOSITORY_ID = 1394134582
API_COMMIT = "d39f4692c13413040439c5e87fed81728e0577f1"
API_TREE = "8da895cc998e5ec43105cfb6fa41a82ea2194f8c"

_TABLES = {
    "ledger_currencies": {
        "code": "char(3)", "exponent": "smallint", "admitted_at": "timestamptz(3)",
    },
    "accounts": {
        "id": "uuid", "owner_id": "uuid", "type": "text", "currency": "char(3)",
        "system_role": "text", "is_archived": "boolean", "created_at": "timestamptz(3)",
        "name": "bytea", "institution": "bytea", "mask": "bytea", "mask_bidx": "bytea",
    },
    "statement_snapshots": {
        "id": "uuid", "owner_id": "uuid", "account_id": "uuid", "currency": "char(3)",
        "statement_date": "date", "statement_balance_minor": "bigint", "source": "text",
        "evidence_ref": "uuid", "captured_at": "timestamptz(3)", "booked_at": "timestamptz(3)",
    },
    "exchange_groups": {
        "id": "uuid", "owner_id": "uuid", "base_currency": "char(3)", "quote_currency": "char(3)",
        "quoted_rate_e10": "bigint", "rate_source": "text", "rate_feed": "text",
        "rate_instant": "timestamptz(3)", "rounding_side": "text", "occurred_at": "timestamptz(3)",
        "booked_at": "timestamptz(3)", "evidence_ref": "uuid", "reverses_group_id": "uuid",
    },
    "transactions": {
        "id": "uuid", "owner_id": "uuid", "currency": "char(3)", "kind": "text", "status": "text",
        "occurred_at": "timestamptz(3)", "booked_at": "timestamptz(3)", "created_at": "timestamptz(3)",
        "value_date": "date", "entry_count": "smallint", "reverses": "uuid", "replaces": "uuid",
        "correction_id": "uuid", "reason_code": "text", "reason_ref": "uuid", "reason_note": "bytea",
        "reconciles_snapshot_id": "uuid", "exchange_group_id": "uuid", "description": "bytea",
        "merchant_display": "bytea", "merchant_bidx": "bytea", "merchant_raw": "bytea",
        "merchant_amount_minor": "bytea", "merchant_currency": "char(3)", "note": "bytea",
        "external_ref": "bytea", "external_ref_bidx": "bytea",
    },
    "entries": {
        "id": "uuid", "transaction_id": "uuid", "owner_id": "uuid", "account_id": "uuid",
        "currency": "char(3)", "amount_minor": "bigint",
    },
}

LEDGER_COLUMNS = tuple(sorted(
    (f"pennilogic.{table}.{column}", sql_type)
    for table, columns in _TABLES.items() for column, sql_type in columns.items()
))
EMPTY = Shape((), ())
SCRIPTS = {
    ("V001__create_pennilogic_schema", "up"): (
        "2655508299a325f56469fd8236014e0765321933ae76c0eed616c46331705cee", EMPTY,
    ),
    ("V001__create_pennilogic_schema", "down"): (
        "3b02e971aad8478c132e21a03009c7ffd5ea8a68c827f361c4e4fb1d2bad9556", EMPTY,
    ),
    ("V002__create_ledger", "up"): (
        "4c5fc158d50fe7676a0518fbb0463955b1460a57f5f83c5e906a6b88b14844b5", Shape(LEDGER_COLUMNS, ()),
    ),
    ("V002__create_ledger", "down"): (
        "a7c101892b51c67f85ae5d2d5a7abfd9a8c63ae7d595755aff338011f98a2f18", EMPTY,
    ),
}
