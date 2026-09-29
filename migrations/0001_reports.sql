CREATE TABLE indicators (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('khqr_account')),
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,
    indicator_id BIGINT NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
    reporter_hash BYTEA NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'disputed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (indicator_id, reporter_hash)
);

CREATE INDEX reports_reporter_created ON reports (reporter_hash, created_at);
