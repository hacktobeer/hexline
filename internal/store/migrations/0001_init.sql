-- 0001_init.sql — the complete v1.0 schema.
-- Timestamps are UTC unix seconds. Booleans are INTEGER 0/1. All tables are STRICT.

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    handle        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL DEFAULT '',
    real_name     TEXT NOT NULL DEFAULT '',
    location      TEXT NOT NULL DEFAULT '',
    signature     TEXT NOT NULL DEFAULT '',
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    role          TEXT NOT NULL DEFAULT 'user',
    status        TEXT NOT NULL DEFAULT 'probation',
    created_at    INTEGER NOT NULL,
    last_call_at  INTEGER NOT NULL DEFAULT 0,
    calls         INTEGER NOT NULL DEFAULT 0,
    time_online_s INTEGER NOT NULL DEFAULT 0,
    pass_hash     TEXT NOT NULL,
    pass_params   TEXT NOT NULL,
    prefs_json    TEXT NOT NULL DEFAULT '{}',
    promoted_at   INTEGER NOT NULL DEFAULT 0,
    is_guest      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE ssh_keys (
    fingerprint TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE areas (
    id                 TEXT PRIMARY KEY,
    tag                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    sort_order         INTEGER NOT NULL DEFAULT 0,
    acl_read           TEXT NOT NULL DEFAULT 'user',
    acl_post           TEXT NOT NULL DEFAULT 'user',
    acl_moderate       TEXT NOT NULL DEFAULT 'moderator',
    retention_days     INTEGER NOT NULL DEFAULT 0,
    rate_limit_per_hour INTEGER NOT NULL DEFAULT 0,
    is_public          INTEGER NOT NULL DEFAULT 1,
    created_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE threads (
    id                 TEXT PRIMARY KEY,
    area_id            TEXT NOT NULL REFERENCES areas(id) ON DELETE CASCADE,
    subject            TEXT NOT NULL,
    author_id          TEXT NOT NULL REFERENCES users(id),
    created_at         INTEGER NOT NULL,
    last_post_at       INTEGER NOT NULL,
    post_count         INTEGER NOT NULL DEFAULT 0,
    is_sticky          INTEGER NOT NULL DEFAULT 0,
    is_locked          INTEGER NOT NULL DEFAULT 0,
    is_deleted         INTEGER NOT NULL DEFAULT 0,
    moved_from_area_id TEXT
) STRICT;

CREATE TABLE posts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id       TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    author_id       TEXT NOT NULL REFERENCES users(id),
    body            TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    edited_at       INTEGER NOT NULL DEFAULT 0,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    deleted_by      TEXT,
    delete_reason   TEXT,
    reply_to_post_id INTEGER,
    ip_hash         TEXT
) STRICT;

CREATE TABLE thread_reads (
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    thread_id         TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    last_read_post_id INTEGER NOT NULL DEFAULT 0,
    read_at           INTEGER NOT NULL,
    PRIMARY KEY (user_id, thread_id)
) STRICT;

CREATE VIRTUAL TABLE posts_fts USING fts5(
    subject,
    body,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER posts_fts_ai AFTER INSERT ON posts BEGIN
    INSERT INTO posts_fts(rowid, subject, body)
    VALUES (new.id, (SELECT subject FROM threads WHERE id = new.thread_id), new.body);
END;

CREATE TRIGGER posts_fts_ad AFTER DELETE ON posts BEGIN
    DELETE FROM posts_fts WHERE rowid = old.id;
END;

CREATE TRIGGER posts_fts_au AFTER UPDATE OF body ON posts BEGIN
    DELETE FROM posts_fts WHERE rowid = old.id;
    INSERT INTO posts_fts(rowid, subject, body)
    VALUES (new.id, (SELECT subject FROM threads WHERE id = new.thread_id), new.body);
END;

CREATE INDEX idx_threads_area ON threads(area_id, is_sticky DESC, last_post_at DESC);
CREATE INDEX idx_posts_thread ON posts(thread_id, id);
CREATE INDEX idx_posts_author ON posts(author_id, created_at DESC);
CREATE INDEX idx_posts_created ON posts(created_at DESC);

CREATE TABLE mail (
    id                   TEXT PRIMARY KEY,
    from_id              TEXT NOT NULL REFERENCES users(id),
    to_id                TEXT NOT NULL REFERENCES users(id),
    subject              TEXT NOT NULL,
    body                 TEXT NOT NULL,
    created_at           INTEGER NOT NULL,
    read_at              INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_from   INTEGER NOT NULL DEFAULT 0,
    is_deleted_by_to     INTEGER NOT NULL DEFAULT 0,
    thread_key           TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_mail_to ON mail(to_id, read_at, created_at DESC);
CREATE INDEX idx_mail_from ON mail(from_id, created_at DESC);

CREATE TABLE mail_blocks (
    owner_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (owner_id, blocked_id)
) STRICT;

CREATE TABLE file_areas (
    id          TEXT PRIMARY KEY,
    tag         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sort_order  INTEGER NOT NULL DEFAULT 0,
    acl_read    TEXT NOT NULL DEFAULT 'user',
    acl_upload  TEXT NOT NULL DEFAULT 'user',
    quota_bytes INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE files (
    id             TEXT PRIMARY KEY,
    area_id        TEXT NOT NULL REFERENCES file_areas(id) ON DELETE CASCADE,
    filename       TEXT NOT NULL,
    stored_path    TEXT NOT NULL,
    size_bytes     INTEGER NOT NULL,
    sha256         TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    uploader_id    TEXT NOT NULL REFERENCES users(id),
    uploaded_at    INTEGER NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 0,
    is_deleted     INTEGER NOT NULL DEFAULT 0,
    scan_status    TEXT NOT NULL DEFAULT 'clean'
) STRICT;

CREATE INDEX idx_files_area ON files(area_id, uploaded_at DESC);

CREATE TABLE file_downloads (
    file_id    TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at         INTEGER NOT NULL,
    bytes_sent INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_file_downloads_file ON file_downloads(file_id, at DESC);

CREATE TABLE file_ratings (
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stars   INTEGER NOT NULL,
    at      INTEGER NOT NULL,
    PRIMARY KEY (file_id, user_id)
) STRICT;

CREATE TABLE oneliners (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  TEXT NOT NULL REFERENCES users(id),
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    is_hidden  INTEGER NOT NULL DEFAULT 0,
    hidden_by  TEXT
) STRICT;

CREATE INDEX idx_oneliners_created ON oneliners(created_at DESC);

CREATE TABLE polls (
    id         TEXT PRIMARY KEY,
    question   TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    closes_at  INTEGER NOT NULL DEFAULT 0,
    is_hidden  INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE poll_options (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id  TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    label    TEXT NOT NULL,
    sort     INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE poll_votes (
    poll_id   TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at        INTEGER NOT NULL,
    PRIMARY KEY (poll_id, user_id)
) STRICT;

CREATE TABLE bulletins (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    sort       INTEGER NOT NULL DEFAULT 0,
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE bulletin_dismissals (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bulletin_id TEXT NOT NULL REFERENCES bulletins(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, bulletin_id)
) STRICT;

CREATE TABLE bans (
    id         TEXT PRIMARY KEY,
    scope      TEXT NOT NULL,
    value      TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX idx_bans_scope ON bans(scope, value);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT,
    node       INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER NOT NULL DEFAULT 0,
    ip_hash    TEXT NOT NULL DEFAULT '',
    client     TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_sessions_started ON sessions(started_at DESC);

CREATE TABLE login_attempts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      INTEGER NOT NULL,
    ip_hash TEXT NOT NULL,
    handle  TEXT NOT NULL,
    ok      INTEGER NOT NULL
) STRICT;

CREATE INDEX idx_login_attempts ON login_attempts(ip_hash, at DESC);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    actor_id    TEXT,
    actor       TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip_hash     TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_audit_at ON audit_log(at DESC);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
