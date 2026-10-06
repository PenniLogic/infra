-- phase: expand
-- owner: api#2
-- reversal: down
--
-- Local ledger preparation against ADR-017/018 at Docs 47986ef6.
-- Identity providers, runtime grants/policies and usable crypto remain prerequisites.
CREATE SCHEMA ledger;
REVOKE ALL ON SCHEMA ledger FROM PUBLIC;

CREATE TABLE pennilogic.ledger_currencies (
    code CHAR(3) PRIMARY KEY CHECK (code ~ '^[A-Z]{3}$'),
    exponent SMALLINT NOT NULL CHECK (exponent BETWEEN 0 AND 3),
    admitted_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(admitted_at))
);
INSERT INTO pennilogic.ledger_currencies (code, exponent, admitted_at)
VALUES ('INR', 2, CURRENT_TIMESTAMP);

CREATE TABLE pennilogic.accounts (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('ASSET', 'LIABILITY', 'INCOME', 'EXPENSE', 'EQUITY', 'CLEARING')),
    currency CHAR(3) NOT NULL REFERENCES pennilogic.ledger_currencies (code),
    system_role TEXT CHECK (system_role IN ('OPENING_BALANCE', 'RECONCILIATION', 'FX_CLEARING', 'FX_FEE')),
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(created_at)),
    name BYTEA,
    institution BYTEA,
    mask BYTEA,
    mask_bidx BYTEA,
    CONSTRAINT accounts_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT accounts_system_role_type CHECK (
        (type = 'CLEARING') = (system_role IS NOT NULL AND system_role = 'FX_CLEARING')
        AND (system_role IS NULL OR
             (system_role IN ('OPENING_BALANCE', 'RECONCILIATION') AND type = 'EQUITY') OR
             (system_role = 'FX_CLEARING' AND type = 'CLEARING') OR
             (system_role = 'FX_FEE' AND type = 'EXPENSE'))
    ),
    CONSTRAINT accounts_crypto_unavailable CHECK (
        name IS NULL AND institution IS NULL AND mask IS NULL AND mask_bidx IS NULL
    ),
    UNIQUE (id, owner_id),
    UNIQUE (id, currency)
);
CREATE UNIQUE INDEX accounts_system_role_currency
    ON pennilogic.accounts (owner_id, system_role, currency) WHERE system_role IS NOT NULL;

CREATE TABLE pennilogic.statement_snapshots (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    account_id UUID NOT NULL,
    currency CHAR(3) NOT NULL,
    statement_date DATE NOT NULL CHECK (isfinite(statement_date)),
    statement_balance_minor BIGINT NOT NULL CHECK (statement_balance_minor >= -9223372036854775807),
    source TEXT NOT NULL CHECK (source IN ('MANUAL', 'IMPORT')),
    evidence_ref UUID,
    captured_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(captured_at)),
    booked_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(booked_at)),
    CONSTRAINT statement_snapshots_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    FOREIGN KEY (account_id, owner_id) REFERENCES pennilogic.accounts (id, owner_id),
    FOREIGN KEY (account_id, currency) REFERENCES pennilogic.accounts (id, currency),
    UNIQUE (id, owner_id, currency)
);

CREATE TABLE pennilogic.exchange_groups (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    base_currency CHAR(3) NOT NULL REFERENCES pennilogic.ledger_currencies (code),
    quote_currency CHAR(3) NOT NULL REFERENCES pennilogic.ledger_currencies (code),
    quoted_rate_e10 BIGINT NOT NULL CHECK (quoted_rate_e10 > 0),
    rate_source TEXT NOT NULL CHECK (rate_source IN ('PROVIDER_STATEMENT', 'USER_ENTERED', 'REFERENCE_FEED')),
    rate_feed TEXT,
    rate_instant TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(rate_instant)),
    rounding_side TEXT NOT NULL CHECK (rounding_side IN ('QUOTE', 'BASE')),
    occurred_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(occurred_at)),
    booked_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(booked_at)),
    evidence_ref UUID,
    reverses_group_id UUID UNIQUE,
    CONSTRAINT exchange_groups_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT exchange_distinct_currencies CHECK (base_currency <> quote_currency),
    CONSTRAINT exchange_rate_feed_pair CHECK ((rate_source = 'REFERENCE_FEED') = (rate_feed IS NOT NULL)),
    -- The accepted reference-feed provider/list does not exist in this preparation.
    CONSTRAINT exchange_rate_feed_unavailable CHECK (rate_feed IS NULL),
    CHECK (reverses_group_id IS DISTINCT FROM id),
    UNIQUE (id, owner_id),
    FOREIGN KEY (reverses_group_id, owner_id) REFERENCES pennilogic.exchange_groups (id, owner_id)
);

CREATE TABLE pennilogic.transactions (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL,
    currency CHAR(3) NOT NULL REFERENCES pennilogic.ledger_currencies (code),
    kind TEXT NOT NULL CHECK (
        kind IN ('STANDARD', 'OPENING_BALANCE', 'REVERSAL', 'REPOST', 'RECONCILIATION_ADJUSTMENT', 'EXCHANGE_LEG')
    ),
    status TEXT NOT NULL CHECK (status IN ('candidate', 'posted', 'suppressed_by_link', 'reversed')),
    occurred_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(occurred_at)),
    booked_at TIMESTAMPTZ(3) CHECK (isfinite(booked_at)),
    created_at TIMESTAMPTZ(3) NOT NULL CHECK (isfinite(created_at)),
    value_date DATE CHECK (isfinite(value_date)),
    entry_count SMALLINT NOT NULL CHECK (entry_count = 0 OR entry_count >= 2),
    reverses UUID UNIQUE,
    replaces UUID,
    correction_id UUID,
    reason_code TEXT CHECK (
        reason_code IN ('USER_CORRECTION', 'DUPLICATE_LINK', 'RECONCILIATION', 'EXCHANGE_REVERSAL', 'ADMINISTRATIVE')
    ),
    reason_ref UUID,
    reason_note BYTEA,
    reconciles_snapshot_id UUID UNIQUE,
    exchange_group_id UUID,
    description BYTEA,
    merchant_display BYTEA,
    merchant_bidx BYTEA,
    merchant_raw BYTEA,
    merchant_amount_minor BYTEA,
    merchant_currency CHAR(3),
    note BYTEA,
    external_ref BYTEA,
    external_ref_bidx BYTEA,
    CONSTRAINT transactions_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT candidate_entry_count CHECK (
        (status IN ('candidate', 'suppressed_by_link')) = (entry_count = 0)
        AND (entry_count = 0) = (booked_at IS NULL)
        AND (kind = 'STANDARD' OR entry_count >= 2)
    ),
    CONSTRAINT reversal_link_shape CHECK ((kind = 'REVERSAL') = (reverses IS NOT NULL)),
    CONSTRAINT repost_link_shape CHECK ((kind = 'REPOST') = (replaces IS NOT NULL)),
    CONSTRAINT correction_link_shape CHECK ((kind IN ('REVERSAL', 'REPOST')) = (correction_id IS NOT NULL)),
    CONSTRAINT reconciliation_link_shape CHECK (
        (kind = 'RECONCILIATION_ADJUSTMENT') = (reconciles_snapshot_id IS NOT NULL)
    ),
    CONSTRAINT correction_reason_required CHECK (
        kind NOT IN ('REVERSAL', 'REPOST', 'RECONCILIATION_ADJUSTMENT') OR reason_code IS NOT NULL
    ),
    CONSTRAINT reason_ref_shape CHECK (
        (reason_code IS NOT NULL AND reason_code IN ('DUPLICATE_LINK', 'ADMINISTRATIVE')) = (reason_ref IS NOT NULL)
    ),
    -- No duplicate-link or administrative-request provider exists yet.
    CONSTRAINT reason_provider_unavailable CHECK (reason_ref IS NULL),
    CONSTRAINT reconciliation_reason CHECK (kind <> 'RECONCILIATION_ADJUSTMENT' OR reason_code = 'RECONCILIATION'),
    CONSTRAINT exchange_link_shape CHECK (
        (kind <> 'EXCHANGE_LEG' OR exchange_group_id IS NOT NULL)
        AND (exchange_group_id IS NULL OR kind IN ('EXCHANGE_LEG', 'REVERSAL'))
    ),
    CONSTRAINT effective_date_required CHECK (
        kind NOT IN ('OPENING_BALANCE', 'RECONCILIATION_ADJUSTMENT') OR value_date IS NOT NULL
    ),
    CONSTRAINT correction_not_self CHECK (reverses IS DISTINCT FROM id AND replaces IS DISTINCT FROM id),
    CONSTRAINT transactions_crypto_unavailable CHECK (
        reason_note IS NULL AND description IS NULL AND merchant_display IS NULL AND merchant_bidx IS NULL
        AND merchant_raw IS NULL AND note IS NULL AND external_ref IS NULL AND external_ref_bidx IS NULL
        AND merchant_amount_minor IS NULL AND merchant_currency IS NULL
    ),
    UNIQUE (id, owner_id),
    UNIQUE (id, currency),
    UNIQUE (id, owner_id, currency),
    CONSTRAINT reversal_target FOREIGN KEY (reverses, owner_id, currency)
        REFERENCES pennilogic.transactions (id, owner_id, currency),
    FOREIGN KEY (replaces, owner_id) REFERENCES pennilogic.transactions (id, owner_id),
    FOREIGN KEY (reconciles_snapshot_id, owner_id, currency)
        REFERENCES pennilogic.statement_snapshots (id, owner_id, currency),
    CONSTRAINT exchange_group_owner FOREIGN KEY (exchange_group_id, owner_id)
        REFERENCES pennilogic.exchange_groups (id, owner_id)
);

CREATE TABLE pennilogic.entries (
    id UUID PRIMARY KEY,
    transaction_id UUID NOT NULL,
    owner_id UUID NOT NULL,
    account_id UUID NOT NULL,
    currency CHAR(3) NOT NULL,
    amount_minor BIGINT NOT NULL,
    CONSTRAINT entries_uuid_v7 CHECK (
        (get_byte(uuid_send(id), 6) >> 4) = 7 AND (get_byte(uuid_send(id), 8) & 192) = 128
    ),
    CONSTRAINT entry_nonzero_or_range CHECK (amount_minor <> 0 AND amount_minor >= -9223372036854775807),
    CONSTRAINT entry_owner FOREIGN KEY (transaction_id, owner_id)
        REFERENCES pennilogic.transactions (id, owner_id),
    CONSTRAINT transaction_single_currency FOREIGN KEY (transaction_id, currency)
        REFERENCES pennilogic.transactions (id, currency),
    CONSTRAINT entry_account_owner FOREIGN KEY (account_id, owner_id)
        REFERENCES pennilogic.accounts (id, owner_id),
    CONSTRAINT entry_account_currency FOREIGN KEY (account_id, currency)
        REFERENCES pennilogic.accounts (id, currency)
);

CREATE INDEX entries_owner_account ON pennilogic.entries (owner_id, account_id, transaction_id, id);
CREATE INDEX entries_transaction_currency ON pennilogic.entries (transaction_id, currency);
CREATE INDEX transactions_owner_occurred ON pennilogic.transactions (owner_id, occurred_at DESC, id DESC);
CREATE INDEX transactions_owner_booked ON pennilogic.transactions (owner_id, booked_at, id) WHERE booked_at IS NOT NULL;
CREATE INDEX transactions_replaces ON pennilogic.transactions (replaces, correction_id) WHERE replaces IS NOT NULL;
CREATE INDEX transactions_exchange_group ON pennilogic.transactions (exchange_group_id) WHERE exchange_group_id IS NOT NULL;

ALTER TABLE pennilogic.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.entries FORCE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.statement_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.statement_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.exchange_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE pennilogic.exchange_groups FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE pennilogic.accounts, pennilogic.transactions, pennilogic.entries,
    pennilogic.statement_snapshots, pennilogic.exchange_groups, pennilogic.ledger_currencies FROM PUBLIC;
-- With no admitting policy, FORCE RLS denies every non-bypass identity, including the owner.

CREATE FUNCTION ledger.reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.append_only',
        SCHEMA = 'pennilogic', TABLE = TG_TABLE_NAME, CONSTRAINT = 'append_only';
END $$;

CREATE FUNCTION ledger.guard_account() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id, NEW.owner_id, NEW.type, NEW.currency, NEW.system_role, NEW.created_at)
            IS DISTINCT FROM ROW(OLD.id, OLD.owner_id, OLD.type, OLD.currency, OLD.system_role, OLD.created_at) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.account_immutable',
                SCHEMA = 'pennilogic', TABLE = 'accounts', CONSTRAINT = 'account_immutable';
        END IF;
    ELSIF NEW.system_role IN ('FX_CLEARING', 'FX_FEE')
        AND NOT EXISTS (SELECT 1 FROM pennilogic.ledger_currencies WHERE code <> NEW.currency) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_not_admitted',
            SCHEMA = 'pennilogic', TABLE = 'accounts', CONSTRAINT = 'exchange_not_admitted';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION ledger.guard_transaction_facts() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF ROW(NEW.id, NEW.owner_id, NEW.currency, NEW.kind, NEW.occurred_at, NEW.value_date, NEW.created_at,
           NEW.reverses, NEW.replaces, NEW.correction_id, NEW.reason_code, NEW.reason_ref,
           NEW.reason_note, NEW.reconciles_snapshot_id, NEW.exchange_group_id)
        IS DISTINCT FROM
       ROW(OLD.id, OLD.owner_id, OLD.currency, OLD.kind, OLD.occurred_at, OLD.value_date, OLD.created_at,
           OLD.reverses, OLD.replaces, OLD.correction_id, OLD.reason_code, OLD.reason_ref,
           OLD.reason_note, OLD.reconciles_snapshot_id, OLD.exchange_group_id)
       OR (OLD.status = 'reversed' AND NEW.status <> 'reversed')
       OR (OLD.entry_count >= 2 AND NEW.status NOT IN ('posted', 'reversed')) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.transaction_immutable',
            SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'transaction_immutable';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION ledger.guard_posting() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT (OLD.status IN ('candidate', 'suppressed_by_link') AND OLD.entry_count = 0 AND OLD.booked_at IS NULL
            AND NEW.status = 'posted' AND NEW.entry_count >= 2 AND NEW.booked_at IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.transaction_sealed',
            SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'transaction_sealed';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION ledger.booked_at_plausible() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.booked_at IS NOT NULL AND
       (NOT isfinite(NEW.booked_at) OR NEW.booked_at < clock_timestamp() - INTERVAL '5 minutes'
        OR NEW.booked_at > clock_timestamp() + INTERVAL '5 minutes') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.booked_at_plausible',
            SCHEMA = 'pennilogic', TABLE = TG_TABLE_NAME, CONSTRAINT = 'booked_at_plausible';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION ledger.serialize_transaction_write() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    target UUID;
BEGIN
    IF TG_TABLE_NAME = 'entries' THEN
        target := NEW.transaction_id;
    ELSE
        target := COALESCE(NEW.reverses, NEW.replaces);
    END IF;
    IF target IS NOT NULL THEN
        -- A tuple write, not only a row/advisory lock: stale repeatable-read writers must abort.
        -- No ledger fact changes. T-SEC-01 must admit the same owner's SELECT and UPDATE(status).
        UPDATE pennilogic.transactions SET status = status WHERE id = target;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.transaction_sealed',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'transaction_sealed';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION ledger.assert_transaction_balanced() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    -- PostgreSQL SUM(BIGINT) is NUMERIC; even intermediate sums above BIGINT remain exact.
    IF EXISTS (
        SELECT 1 FROM pennilogic.entries
        WHERE transaction_id = COALESCE(NEW.transaction_id, OLD.transaction_id)
        GROUP BY currency HAVING SUM(amount_minor) <> 0 OR COUNT(*) < 2
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.transaction_zero_sum',
            SCHEMA = 'pennilogic', TABLE = 'entries', CONSTRAINT = 'transaction_zero_sum';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION ledger.check_exchange_group(group_id UUID) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    current_group pennilogic.exchange_groups%ROWTYPE;
    original_group pennilogic.exchange_groups%ROWTYPE;
    leg pennilogic.transactions%ROWTYPE;
    clearing BIGINT;
BEGIN
    SELECT * INTO current_group FROM pennilogic.exchange_groups WHERE id = group_id;
    IF NOT FOUND OR (SELECT COUNT(*) FROM pennilogic.transactions WHERE exchange_group_id = group_id) <> 2
        OR (SELECT COUNT(DISTINCT currency) FROM pennilogic.transactions WHERE exchange_group_id = group_id) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_shape',
            SCHEMA = 'pennilogic', TABLE = 'exchange_groups', CONSTRAINT = 'exchange_group_shape';
    END IF;
    IF current_group.reverses_group_id IS NOT NULL THEN
        SELECT * INTO original_group FROM pennilogic.exchange_groups WHERE id = current_group.reverses_group_id;
        IF NOT FOUND OR original_group.reverses_group_id IS NOT NULL
            OR ROW(current_group.owner_id, current_group.base_currency, current_group.quote_currency,
                   current_group.quoted_rate_e10, current_group.rate_source, current_group.rate_feed,
                   current_group.rate_instant, current_group.rounding_side, current_group.occurred_at)
               IS DISTINCT FROM
               ROW(original_group.owner_id, original_group.base_currency, original_group.quote_currency,
                   original_group.quoted_rate_e10, original_group.rate_source, original_group.rate_feed,
                   original_group.rate_instant, original_group.rounding_side, original_group.occurred_at)
            OR (SELECT COUNT(DISTINCT correction_id) FROM pennilogic.transactions WHERE exchange_group_id = group_id) <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_reversal',
                SCHEMA = 'pennilogic', TABLE = 'exchange_groups', CONSTRAINT = 'exchange_group_reversal';
        END IF;
    END IF;
    FOR leg IN SELECT * FROM pennilogic.transactions WHERE exchange_group_id = group_id LOOP
        IF leg.owner_id <> current_group.owner_id OR leg.occurred_at <> current_group.occurred_at
            OR leg.currency NOT IN (current_group.base_currency, current_group.quote_currency)
            OR leg.kind <> (CASE WHEN current_group.reverses_group_id IS NULL THEN 'EXCHANGE_LEG' ELSE 'REVERSAL' END)
            OR (SELECT COUNT(*) FROM pennilogic.entries e JOIN pennilogic.accounts a ON a.id = e.account_id
                WHERE e.transaction_id = leg.id AND a.system_role = 'FX_CLEARING') <> 1
            OR NOT EXISTS (SELECT 1 FROM pennilogic.entries e JOIN pennilogic.accounts a ON a.id = e.account_id
                           WHERE e.transaction_id = leg.id AND a.system_role IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_shape',
                SCHEMA = 'pennilogic', TABLE = 'exchange_groups', CONSTRAINT = 'exchange_group_shape';
        END IF;
        SELECT e.amount_minor INTO clearing FROM pennilogic.entries e
            JOIN pennilogic.accounts a ON a.id = e.account_id
            WHERE e.transaction_id = leg.id AND a.system_role = 'FX_CLEARING';
        IF (clearing > 0) IS DISTINCT FROM
            ((leg.currency = current_group.base_currency) = (current_group.reverses_group_id IS NULL)) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_shape',
                SCHEMA = 'pennilogic', TABLE = 'exchange_groups', CONSTRAINT = 'exchange_group_shape';
        END IF;
        IF current_group.reverses_group_id IS NOT NULL
            AND (leg.reason_code IS DISTINCT FROM 'EXCHANGE_REVERSAL' OR NOT EXISTS (
                SELECT 1 FROM pennilogic.transactions
                WHERE id = leg.reverses AND exchange_group_id = original_group.id
            )) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_reversal',
                SCHEMA = 'pennilogic', TABLE = 'exchange_groups', CONSTRAINT = 'exchange_group_reversal';
        END IF;
    END LOOP;
END $$;

CREATE FUNCTION ledger.assert_exchange_group() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM ledger.check_exchange_group(NEW.id);
    RETURN NULL;
END $$;

CREATE FUNCTION ledger.assert_transaction_sealed() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    target UUID;
    posted pennilogic.transactions%ROWTYPE;
    original pennilogic.transactions%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'entries' THEN target := NEW.transaction_id;
    ELSE target := NEW.id;
    END IF;
    SELECT * INTO posted FROM pennilogic.transactions WHERE id = target;
    IF NOT FOUND OR (SELECT COUNT(*) FROM pennilogic.entries WHERE transaction_id = target) <> posted.entry_count
        OR EXISTS (SELECT 1 FROM pennilogic.entries e WHERE e.transaction_id = target
                   AND NOT EXISTS (SELECT 1 FROM pennilogic.accounts a WHERE a.id = e.account_id)) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.transaction_sealed',
            SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'transaction_sealed';
    END IF;
    IF (posted.kind = 'REVERSAL' OR posted.entry_count < 2)
        AND EXISTS (SELECT 1 FROM pennilogic.transactions WHERE reverses = target) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.reversal_terminal',
            SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'reversal_terminal';
    END IF;
    IF (posted.status = 'reversed') <> EXISTS (SELECT 1 FROM pennilogic.transactions WHERE reverses = target) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.status_reversed_equivalence',
            SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'status_reversed_equivalence';
    END IF;
    IF posted.kind = 'REVERSAL' THEN
        SELECT * INTO original FROM pennilogic.transactions WHERE id = posted.reverses;
        IF NOT FOUND OR original.kind = 'REVERSAL' OR original.entry_count < 2 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.reversal_terminal',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'reversal_terminal';
        END IF;
        IF original.status <> 'reversed' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.status_reversed_equivalence',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'status_reversed_equivalence';
        END IF;
        IF posted.occurred_at <> original.occurred_at OR posted.value_date IS DISTINCT FROM original.value_date
            OR posted.entry_count <> original.entry_count
            OR EXISTS (
                (SELECT account_id, amount_minor FROM pennilogic.entries WHERE transaction_id = target
                 EXCEPT ALL
                 SELECT account_id, -amount_minor FROM pennilogic.entries WHERE transaction_id = original.id)
                UNION ALL
                (SELECT account_id, -amount_minor FROM pennilogic.entries WHERE transaction_id = original.id
                 EXCEPT ALL
                 SELECT account_id, amount_minor FROM pennilogic.entries WHERE transaction_id = target)
            ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.reversal_exact_negation',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'reversal_exact_negation';
        END IF;
        IF original.exchange_group_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM pennilogic.exchange_groups
            WHERE id = posted.exchange_group_id AND reverses_group_id = original.exchange_group_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.exchange_group_reversal',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'exchange_group_reversal';
        END IF;
    ELSIF posted.kind = 'REPOST' THEN
        SELECT * INTO original FROM pennilogic.transactions WHERE id = posted.replaces;
        IF NOT FOUND OR original.kind = 'REVERSAL' OR original.entry_count < 2 OR original.status <> 'reversed'
            OR (original.value_date IS NOT NULL AND posted.value_date IS NULL)
            OR NOT EXISTS (SELECT 1 FROM pennilogic.transactions WHERE reverses = original.id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.repost_without_reversal',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'repost_without_reversal';
        END IF;
        IF posted.status <> 'reversed' AND EXISTS (SELECT 1 FROM pennilogic.transactions
                   WHERE replaces = posted.replaces AND correction_id <> posted.correction_id AND status <> 'reversed') THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.repost_supersedes_prior',
                SCHEMA = 'pennilogic', TABLE = 'transactions', CONSTRAINT = 'repost_supersedes_prior';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM pennilogic.entries e JOIN pennilogic.accounts a ON a.id = e.account_id
        WHERE e.transaction_id = target AND a.system_role = 'FX_CLEARING'
    ) AND NOT (posted.kind = 'EXCHANGE_LEG' OR
               (posted.kind = 'REVERSAL' AND original.kind = 'EXCHANGE_LEG')) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'ledger.clearing_entry_membership',
            SCHEMA = 'pennilogic', TABLE = 'entries', CONSTRAINT = 'clearing_entry_membership';
    END IF;
    IF posted.exchange_group_id IS NOT NULL THEN
        PERFORM ledger.check_exchange_group(posted.exchange_group_id);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER accounts_facts BEFORE INSERT OR UPDATE ON pennilogic.accounts
    FOR EACH ROW EXECUTE FUNCTION ledger.guard_account();
CREATE TRIGGER accounts_no_delete BEFORE DELETE ON pennilogic.accounts
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER accounts_no_truncate BEFORE TRUNCATE ON pennilogic.accounts
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER transactions_facts BEFORE UPDATE ON pennilogic.transactions
    FOR EACH ROW EXECUTE FUNCTION ledger.guard_transaction_facts();
CREATE TRIGGER transactions_posting BEFORE UPDATE OF entry_count, booked_at ON pennilogic.transactions
    FOR EACH ROW EXECUTE FUNCTION ledger.guard_posting();
CREATE TRIGGER booked_at_plausible BEFORE INSERT OR UPDATE OF booked_at ON pennilogic.transactions
    FOR EACH ROW EXECUTE FUNCTION ledger.booked_at_plausible();
CREATE TRIGGER transactions_serialize BEFORE INSERT ON pennilogic.transactions
    FOR EACH ROW EXECUTE FUNCTION ledger.serialize_transaction_write();
CREATE TRIGGER transactions_no_delete BEFORE DELETE ON pennilogic.transactions
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER transactions_no_truncate BEFORE TRUNCATE ON pennilogic.transactions
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER entries_serialize BEFORE INSERT ON pennilogic.entries
    FOR EACH ROW EXECUTE FUNCTION ledger.serialize_transaction_write();
CREATE TRIGGER entries_no_mutation BEFORE UPDATE OR DELETE ON pennilogic.entries
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER entries_no_truncate BEFORE TRUNCATE ON pennilogic.entries
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE CONSTRAINT TRIGGER transaction_zero_sum AFTER INSERT OR UPDATE OR DELETE ON pennilogic.entries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger.assert_transaction_balanced();
CREATE CONSTRAINT TRIGGER transaction_sealed AFTER INSERT OR UPDATE ON pennilogic.transactions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger.assert_transaction_sealed();
CREATE CONSTRAINT TRIGGER transaction_sealed AFTER INSERT ON pennilogic.entries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger.assert_transaction_sealed();
CREATE TRIGGER booked_at_plausible BEFORE INSERT ON pennilogic.statement_snapshots
    FOR EACH ROW EXECUTE FUNCTION ledger.booked_at_plausible();
CREATE TRIGGER snapshots_no_mutation BEFORE UPDATE OR DELETE ON pennilogic.statement_snapshots
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER snapshots_no_truncate BEFORE TRUNCATE ON pennilogic.statement_snapshots
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER booked_at_plausible BEFORE INSERT ON pennilogic.exchange_groups
    FOR EACH ROW EXECUTE FUNCTION ledger.booked_at_plausible();
CREATE TRIGGER exchanges_no_mutation BEFORE UPDATE OR DELETE ON pennilogic.exchange_groups
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER exchanges_no_truncate BEFORE TRUNCATE ON pennilogic.exchange_groups
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE CONSTRAINT TRIGGER exchange_group_shape AFTER INSERT ON pennilogic.exchange_groups
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ledger.assert_exchange_group();
CREATE TRIGGER currencies_no_mutation BEFORE UPDATE OR DELETE ON pennilogic.ledger_currencies
    FOR EACH ROW EXECUTE FUNCTION ledger.reject_history_mutation();
CREATE TRIGGER currencies_no_truncate BEFORE TRUNCATE ON pennilogic.ledger_currencies
    FOR EACH STATEMENT EXECUTE FUNCTION ledger.reject_history_mutation();

REVOKE ALL ON FUNCTION ledger.reject_history_mutation(), ledger.guard_account(),
    ledger.guard_transaction_facts(), ledger.guard_posting(), ledger.booked_at_plausible(),
    ledger.serialize_transaction_write(), ledger.assert_transaction_balanced(),
    ledger.check_exchange_group(UUID), ledger.assert_exchange_group(), ledger.assert_transaction_sealed() FROM PUBLIC;
