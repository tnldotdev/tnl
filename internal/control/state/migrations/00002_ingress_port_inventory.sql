-- +goose Up
ALTER TABLE control.ingress_leases DROP CONSTRAINT ingress_leases_service_ports_check;
