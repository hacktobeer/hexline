-- The reader never wrote reply_to_post_id (threads are flat in v1), so the
-- column only cost a scan slot. Dropping it keeps the schema honest.
ALTER TABLE posts DROP COLUMN reply_to_post_id;
