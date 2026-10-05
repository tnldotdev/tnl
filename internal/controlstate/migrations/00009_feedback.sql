-- +goose Up
CREATE TABLE control.feedback_event_clock (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    next_cursor bigint NOT NULL DEFAULT 1 CHECK (next_cursor >= 1)
);
INSERT INTO control.feedback_event_clock (id) VALUES (1);

CREATE TABLE control.feedback_threads (
    id text PRIMARY KEY CHECK (id <> ''),
    preview_id text NOT NULL,
    team_id text NOT NULL CHECK (team_id <> ''),
    public_url_id text NOT NULL,
    publish_run_id text NOT NULL,
    publish_run_number bigint NOT NULL CHECK (publish_run_number >= 1),
    service text NOT NULL CHECK (service <> ''),
    page_path text NOT NULL CHECK (page_path LIKE '/%' AND char_length(page_path) <= 2048),
    report_text text NOT NULL CHECK (char_length(report_text) BETWEEN 1 AND 4000),
    author_display_name text CHECK (char_length(author_display_name) BETWEEN 1 AND 64),
    element jsonb NOT NULL,
    evidence jsonb NOT NULL,
    checkout_at_report jsonb NOT NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'ready_for_recheck', 'resolved')),
    created_at timestamptz NOT NULL,
    state_updated_at timestamptz NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    UNIQUE (publish_run_id, idempotency_key),
    FOREIGN KEY (preview_id, team_id)
        REFERENCES control.previews(id, team_id) ON DELETE RESTRICT,
    FOREIGN KEY (public_url_id, team_id)
        REFERENCES control.public_urls(id, team_id) ON DELETE RESTRICT,
    FOREIGN KEY (publish_run_id, public_url_id, publish_run_number)
        REFERENCES control.publish_runs(id, public_url_id, publish_run_number) ON DELETE RESTRICT
);

CREATE INDEX feedback_threads_by_preview_page
    ON control.feedback_threads (preview_id, public_url_id, page_path, created_at DESC, id);
CREATE INDEX feedback_threads_by_team
    ON control.feedback_threads (team_id, created_at DESC, id);

CREATE TABLE control.feedback_events (
    cursor bigint PRIMARY KEY CHECK (cursor >= 1),
    feedback_id text NOT NULL REFERENCES control.feedback_threads(id) ON DELETE RESTRICT,
    team_id text NOT NULL CHECK (team_id <> ''),
    event_type text NOT NULL CHECK (event_type IN (
        'thread.created', 'reply', 'context.requested', 'evidence.added',
        'fix.ready_for_recheck', 'recheck.still_broken', 'thread.resolved'
    )),
    actor_kind text NOT NULL CHECK (actor_kind IN ('reviewer', 'developer')),
    actor_reference text NOT NULL CHECK (actor_reference <> ''),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    text text CHECK (char_length(text) BETWEEN 1 AND 4000),
    evidence jsonb,
    checkout_marker jsonb,
    occurred_at timestamptz NOT NULL,
    UNIQUE (feedback_id, actor_kind, actor_reference, idempotency_key)
);

CREATE INDEX feedback_events_by_thread ON control.feedback_events (feedback_id, cursor);
CREATE INDEX feedback_events_by_team ON control.feedback_events (team_id, cursor);

-- +goose Down
DROP TABLE control.feedback_events;
DROP TABLE control.feedback_threads;
DROP TABLE control.feedback_event_clock;
