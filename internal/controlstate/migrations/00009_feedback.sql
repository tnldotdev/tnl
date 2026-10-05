-- +goose Up
ALTER TABLE control.previews ADD COLUMN demo_publish_run_id text UNIQUE
    REFERENCES control.publish_runs(id) ON DELETE RESTRICT;
CREATE TABLE control.feedback_event_clock (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    next_cursor bigint NOT NULL DEFAULT 1 CHECK (next_cursor >= 1)
);
INSERT INTO control.feedback_event_clock (id) VALUES (1);

CREATE TABLE control.feedback_threads (
    id text PRIMARY KEY CHECK (id <> ''),
    schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    preview_id text NOT NULL,
    team_id text NOT NULL CHECK (team_id <> ''),
    public_url_id text NOT NULL,
    publish_run_id text NOT NULL,
    publish_run_number bigint NOT NULL CHECK (publish_run_number >= 1),
    service text NOT NULL CHECK (service <> ''),
    page_path text NOT NULL CHECK (page_path LIKE '/%' AND char_length(page_path) <= 2048),
    report_text text NOT NULL CHECK (char_length(report_text) BETWEEN 1 AND 4000),
    author_display_name text CHECK (char_length(author_display_name) BETWEEN 1 AND 64),
    anchor jsonb,
    evidence jsonb NOT NULL,
    checkout_at_report jsonb NOT NULL,
    state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
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
    schema_version smallint NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    feedback_id text NOT NULL REFERENCES control.feedback_threads(id) ON DELETE RESTRICT,
    team_id text NOT NULL CHECK (team_id <> ''),
    event_type text NOT NULL CHECK (event_type IN (
        'thread.created', 'reply', 'update', 'thread.resolved', 'thread.reopened'
    )),
    actor_kind text NOT NULL CHECK (actor_kind IN ('reviewer', 'implementer')),
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

-- the run lock serializes demo creation, comments, and cleanup. normal project
-- feedback does not have a demo_publish_run_id and is never removed here.
-- +goose StatementBegin
CREATE FUNCTION control.cleanup_demo_feedback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL THEN
        DELETE FROM control.feedback_events
        WHERE feedback_id IN (
            SELECT t.id FROM control.feedback_threads t JOIN control.previews p ON p.id = t.preview_id
            WHERE p.demo_publish_run_id = NEW.id
        );
        DELETE FROM control.feedback_threads
        WHERE preview_id IN (SELECT id FROM control.previews WHERE demo_publish_run_id = NEW.id);
        DELETE FROM control.preview_public_urls
        WHERE preview_id IN (SELECT id FROM control.previews WHERE demo_publish_run_id = NEW.id);
        DELETE FROM control.previews WHERE demo_publish_run_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER cleanup_demo_feedback AFTER UPDATE OF closed_at ON control.publish_runs
    FOR EACH ROW EXECUTE FUNCTION control.cleanup_demo_feedback();

-- +goose Down
DROP TRIGGER cleanup_demo_feedback ON control.publish_runs;
DROP FUNCTION control.cleanup_demo_feedback();
DROP TABLE control.feedback_events;
DROP TABLE control.feedback_threads;
DROP TABLE control.feedback_event_clock;
ALTER TABLE control.previews DROP COLUMN demo_publish_run_id;
