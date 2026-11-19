-- +goose Up
ALTER TABLE control.deployment_publisher_enrollments
    DROP CONSTRAINT deployment_publisher_enrollments_max_members_check,
    ADD CHECK (max_members >= 1);

ALTER TABLE control.share_handoffs
    DROP CONSTRAINT share_handoffs_run_ids_check,
    ADD CHECK (cardinality(run_ids) >= 1);

ALTER TABLE control.service_http_browser_logins
    DROP CONSTRAINT service_http_browser_logins_run_ids_check,
    ADD CHECK (cardinality(run_ids) >= 1);

ALTER TABLE control.service_http_browser_handoffs
    DROP CONSTRAINT service_http_browser_handoffs_run_ids_check,
    ADD CHECK (cardinality(run_ids) >= 1);
