-- PodPeopleDB v2 schema.
--
-- Timestamps are ISO-8601 UTC text ("2026-10-20T21:04:05Z") so they sort lexically and survive
-- JSON round trips unchanged.

-- A person: host, guest, producer... anyone credited on a podcast or episode.
CREATE TABLE people (
    id              INTEGER PRIMARY KEY,
    slug            TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    name_normalized TEXT    NOT NULL,
    bio             TEXT,
    img             TEXT,
    website         TEXT,
    -- Reviewed by an admin, or seen in a feed's own <podcast:person> tags.
    verified        INTEGER NOT NULL DEFAULT 0,
    -- Removed by moderation. Hidden people are excluded everywhere public.
    hidden          INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_people_name_normalized ON people(name_normalized);
CREATE INDEX idx_people_updated_at ON people(updated_at);

-- Ids of people merged into another person, so old links and integrations keep resolving.
CREATE TABLE person_aliases (
    old_id    INTEGER PRIMARY KEY,
    person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE
);

CREATE TABLE podcasts (
    id               INTEGER PRIMARY KEY,
    podcastindex_id  INTEGER UNIQUE,
    podcast_guid     TEXT,
    feed_url         TEXT,
    title            TEXT    NOT NULL,
    description      TEXT,
    author           TEXT,
    owner_name       TEXT,
    image            TEXT,
    link             TEXT,
    -- The feed itself carries <podcast:person> tags.
    has_person_tags  INTEGER NOT NULL DEFAULT 0,
    -- HTTP validators for conditional re-crawls.
    etag             TEXT,
    last_modified    TEXT,
    last_crawled_at  TEXT,
    next_crawl_at    TEXT,
    crawl_error      TEXT,
    crawl_failures   INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX idx_podcasts_feed_url ON podcasts(feed_url) WHERE feed_url IS NOT NULL;
CREATE INDEX idx_podcasts_guid ON podcasts(podcast_guid);
CREATE INDEX idx_podcasts_next_crawl ON podcasts(next_crawl_at);
CREATE INDEX idx_podcasts_updated_at ON podcasts(updated_at);

CREATE TABLE episodes (
    id             INTEGER PRIMARY KEY,
    podcast_id     INTEGER NOT NULL REFERENCES podcasts(id) ON DELETE CASCADE,
    guid           TEXT,
    enclosure_url  TEXT,
    title          TEXT    NOT NULL,
    description    TEXT,
    link           TEXT,
    image          TEXT,
    pub_date       TEXT,
    duration       INTEGER,
    season         INTEGER,
    episode_number INTEGER,
    created_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX idx_episodes_guid ON episodes(podcast_id, guid) WHERE guid IS NOT NULL;
CREATE INDEX idx_episodes_enclosure ON episodes(enclosure_url);
CREATE INDEX idx_episodes_podcast_date ON episodes(podcast_id, pub_date DESC);
CREATE INDEX idx_episodes_updated_at ON episodes(updated_at);

-- Every appearance of a person, at podcast level (episode_id NULL) or on one episode.
-- Replaces v1's host_podcasts + episode_guests.
CREATE TABLE credits (
    id            INTEGER PRIMARY KEY,
    person_id     INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
    podcast_id    INTEGER NOT NULL REFERENCES podcasts(id) ON DELETE CASCADE,
    episode_id    INTEGER REFERENCES episodes(id) ON DELETE CASCADE,
    -- Podcasting 2.0 person taxonomy, lowercased: host, co-host, guest, producer, ...
    role          TEXT    NOT NULL,
    person_group  TEXT    NOT NULL DEFAULT 'cast',
    -- 'feed': read from the feed's own tags (the feed is authoritative and re-crawls replace it).
    -- 'community': submitted by a person through the site or a PinePods server.
    source        TEXT    NOT NULL CHECK (source IN ('feed', 'community')),
    verified      INTEGER NOT NULL DEFAULT 0,
    hidden        INTEGER NOT NULL DEFAULT 0,
    submission_id INTEGER REFERENCES submissions(id) ON DELETE SET NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE UNIQUE INDEX idx_credits_unique
    ON credits(person_id, podcast_id, IFNULL(episode_id, 0), role, source);
CREATE INDEX idx_credits_person ON credits(person_id);
CREATE INDEX idx_credits_podcast ON credits(podcast_id, episode_id);
CREATE INDEX idx_credits_episode ON credits(episode_id);
CREATE INDEX idx_credits_submission ON credits(submission_id);
CREATE INDEX idx_credits_updated_at ON credits(updated_at);

-- One community contribution. Contributions are live as soon as they are made; `status` tracks
-- review: 'live' (unreviewed), 'approved', or 'reverted'.
CREATE TABLE submissions (
    id           INTEGER PRIMARY KEY,
    kind         TEXT    NOT NULL CHECK (kind IN ('credits', 'person_edit', 'podcast')),
    -- What was submitted, plus the previous values for edits so a revert can restore them.
    payload      TEXT    NOT NULL,
    summary      TEXT    NOT NULL,
    podcast_id   INTEGER REFERENCES podcasts(id) ON DELETE SET NULL,
    person_id    INTEGER REFERENCES people(id) ON DELETE SET NULL,
    -- 'web', or 'pinepods' for submissions forwarded by a PinePods server.
    client       TEXT    NOT NULL DEFAULT 'web',
    -- Random id a PinePods server sends with every submission, so an abusive instance's
    -- contributions can be reverted together. Not linked to any user.
    instance_id  TEXT,
    -- Salted hash of the submitter's IP, for rate limiting and bulk revert only.
    ip_hash      TEXT,
    status       TEXT    NOT NULL DEFAULT 'live' CHECK (status IN ('live', 'approved', 'reverted')),
    reviewed_by  INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    reviewed_at  TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_submissions_status ON submissions(status, created_at);
CREATE INDEX idx_submissions_instance ON submissions(instance_id);
CREATE INDEX idx_submissions_ip ON submissions(ip_hash);

CREATE TABLE admins (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    -- argon2id PHC string; bcrypt hashes imported from v1 are upgraded on next login.
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE sessions (
    -- sha256 of the cookie token; the token itself is never stored.
    token_hash TEXT    PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    admin_id    INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL,
    target_id   INTEGER,
    detail      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- Tombstones for /api/v2/changes, so mirrors learn about deletions.
CREATE TABLE deletions (
    entity     TEXT    NOT NULL,
    entity_id  INTEGER NOT NULL,
    deleted_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (entity, entity_id)
);
CREATE INDEX idx_deletions_at ON deletions(deleted_at);

-- Keep updated_at current. recursive_triggers is off, so the inner UPDATE doesn't re-fire.
CREATE TRIGGER trg_people_updated AFTER UPDATE ON people WHEN NEW.updated_at = OLD.updated_at
BEGIN UPDATE people SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER trg_podcasts_updated AFTER UPDATE ON podcasts WHEN NEW.updated_at = OLD.updated_at
BEGIN UPDATE podcasts SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER trg_episodes_updated AFTER UPDATE ON episodes WHEN NEW.updated_at = OLD.updated_at
BEGIN UPDATE episodes SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = NEW.id; END;
CREATE TRIGGER trg_credits_updated AFTER UPDATE ON credits WHEN NEW.updated_at = OLD.updated_at
BEGIN UPDATE credits SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE id = NEW.id; END;

CREATE TRIGGER trg_people_deleted AFTER DELETE ON people
BEGIN INSERT OR REPLACE INTO deletions(entity, entity_id) VALUES ('person', OLD.id); END;
CREATE TRIGGER trg_podcasts_deleted AFTER DELETE ON podcasts
BEGIN INSERT OR REPLACE INTO deletions(entity, entity_id) VALUES ('podcast', OLD.id); END;
CREATE TRIGGER trg_episodes_deleted AFTER DELETE ON episodes
BEGIN INSERT OR REPLACE INTO deletions(entity, entity_id) VALUES ('episode', OLD.id); END;
CREATE TRIGGER trg_credits_deleted AFTER DELETE ON credits
BEGIN INSERT OR REPLACE INTO deletions(entity, entity_id) VALUES ('credit', OLD.id); END;
