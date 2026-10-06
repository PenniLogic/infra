-- Rehearsed reverse of V001. RESTRICT (the default) is deliberate: if a later migration left
-- objects in the schema, reversing this one must fail instead of destroying them.
DROP SCHEMA pennilogic RESTRICT;
