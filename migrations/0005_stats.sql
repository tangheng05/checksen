-- Counts only: no message, no person.
CREATE TABLE daily_checks (
    day DATE NOT NULL,
    subject TEXT NOT NULL,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    checks BIGINT NOT NULL,
    PRIMARY KEY (day, subject, level, category)
);

CREATE TABLE weekly_posts (
    week DATE PRIMARY KEY,
    posted_at TIMESTAMPTZ
);
