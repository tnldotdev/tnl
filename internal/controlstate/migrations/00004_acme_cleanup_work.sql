-- +goose Up
DROP INDEX control.acme_orders_available_work;
CREATE INDEX acme_orders_available_work
    ON control.acme_orders (available_at, id)
    WHERE state IN ('pending', 'authorizing', 'ready_to_finalize', 'finalizing', 'waiting_for_install', 'installed', 'failed', 'canceled');
