CREATE TABLE IF NOT EXISTS jobs (
    id         SERIAL PRIMARY KEY,
    job_id     INTEGER NOT NULL,
    result     INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
