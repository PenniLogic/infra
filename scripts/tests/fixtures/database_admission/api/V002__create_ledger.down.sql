-- A denied RLS read must fail, never masquerade as proof that history is empty.
SET LOCAL row_security = off;
LOCK TABLE pennilogic.accounts, pennilogic.transactions, pennilogic.entries,
    pennilogic.statement_snapshots, pennilogic.exchange_groups, pennilogic.ledger_currencies
    IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pennilogic.accounts)
        OR EXISTS (SELECT 1 FROM pennilogic.transactions)
        OR EXISTS (SELECT 1 FROM pennilogic.entries)
        OR EXISTS (SELECT 1 FROM pennilogic.statement_snapshots)
        OR EXISTS (SELECT 1 FROM pennilogic.exchange_groups)
        OR EXISTS (SELECT 1 FROM pennilogic.ledger_currencies WHERE code <> 'INR' OR exponent <> 2) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'ledger.reverse_refused',
            SCHEMA = 'pennilogic', TABLE = 'entries', CONSTRAINT = 'ledger_history_preserved';
    END IF;
END $$;

DROP TABLE pennilogic.entries RESTRICT;
DROP TABLE pennilogic.transactions RESTRICT;
DROP TABLE pennilogic.exchange_groups RESTRICT;
DROP TABLE pennilogic.statement_snapshots RESTRICT;
DROP TABLE pennilogic.accounts RESTRICT;
DROP TABLE pennilogic.ledger_currencies RESTRICT;
DROP FUNCTION ledger.assert_transaction_sealed() RESTRICT;
DROP FUNCTION ledger.assert_exchange_group() RESTRICT;
DROP FUNCTION ledger.check_exchange_group(UUID) RESTRICT;
DROP FUNCTION ledger.assert_transaction_balanced() RESTRICT;
DROP FUNCTION ledger.serialize_transaction_write() RESTRICT;
DROP FUNCTION ledger.booked_at_plausible() RESTRICT;
DROP FUNCTION ledger.guard_posting() RESTRICT;
DROP FUNCTION ledger.guard_transaction_facts() RESTRICT;
DROP FUNCTION ledger.guard_account() RESTRICT;
DROP FUNCTION ledger.reject_history_mutation() RESTRICT;
DROP SCHEMA ledger RESTRICT;
