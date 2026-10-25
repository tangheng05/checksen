CREATE TABLE feedback (
    id BIGSERIAL PRIMARY KEY,
    reporter_hash BYTEA NOT NULL,
    helpful BOOLEAN NOT NULL,
    rules_version INT NOT NULL,
    level TEXT NOT NULL,
    subject TEXT NOT NULL,
    signals TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX feedback_reporter_created ON feedback (reporter_hash, created_at);

-- Messages people chose to share after a wrong reply; deleted after 30 days.
CREATE TABLE shared (
    id BIGSERIAL PRIMARY KEY,
    feedback_id BIGINT NOT NULL UNIQUE REFERENCES feedback (id) ON DELETE CASCADE,
    text TEXT,
    photo_file_id TEXT,
    label TEXT CHECK (label IN ('scam', 'legit')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (text IS NOT NULL OR photo_file_id IS NOT NULL)
);

CREATE INDEX shared_created ON shared (created_at);
