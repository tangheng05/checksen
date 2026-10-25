ALTER TABLE indicators
    ADD COLUMN review TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (review IN ('unreviewed', 'confirmed', 'cleared')),
    ADD COLUMN reviewed_at TIMESTAMPTZ;

CREATE INDEX indicators_unreviewed ON indicators (id) WHERE review = 'unreviewed';
