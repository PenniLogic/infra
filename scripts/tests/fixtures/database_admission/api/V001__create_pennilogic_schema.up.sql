-- phase: expand
-- owner: api#55
-- reversal: down
--
-- Baseline: the application schema every later migration (starting with the ledger in api#2)
-- creates its objects in. The registry tables themselves are runner infrastructure and are
-- bootstrapped by the runner, not by a migration, so that this first change is already applied
-- under the lock and recorded with its checksum.
CREATE SCHEMA pennilogic;
