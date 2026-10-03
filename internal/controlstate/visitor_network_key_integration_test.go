package controlstate

import (
	"bytes"
	"testing"
	"time"
)

func TestIntegrationVisitorNetworkHashKeyEncryptedAndShared(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_network_key")
	if err := database.EnsureVisitorNetworkHashMasterKey(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	var plaintext, ciphertext []byte
	var keyID string
	if err := database.pool.QueryRow(t.Context(), `SELECT visitor_network_hash_master_key,
		visitor_network_hash_master_key_ciphertext, visitor_network_hash_master_key_storage_key_id
		FROM control.public_url_usage_configuration`).Scan(&plaintext, &ciphertext, &keyID); err != nil {
		t.Fatal(err)
	}
	if plaintext != nil || len(ciphertext) <= 32 || keyID != database.storageKey.CurrentID() {
		t.Fatal("visitor network hash key was not stored only as a protected secret")
	}
	first, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_first", IngressRunID: "run_first", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	second, err := other.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_second", IngressRunID: "run_second", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil || first.VisitorNetworkHashKeys != second.VisitorNetworkHashKeys {
		t.Fatalf("visitor network keys changed between control processes: %v", err)
	}
}

func TestIntegrationVisitorNetworkHashKeyBackfill(t *testing.T) {
	database, _, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_network_key_backfill")
	legacy := [32]byte{1, 2, 3}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.public_url_usage_configuration
		(visitor_network_hash_master_key, created_at) VALUES ($1, $2)`, legacy[:], now); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureVisitorNetworkHashMasterKey(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	var plaintext, ciphertext []byte
	var keyID string
	if err := database.pool.QueryRow(t.Context(), `SELECT visitor_network_hash_master_key,
		visitor_network_hash_master_key_ciphertext, visitor_network_hash_master_key_storage_key_id
		FROM control.public_url_usage_configuration`).Scan(&plaintext, &ciphertext, &keyID); err != nil {
		t.Fatal(err)
	}
	if plaintext != nil || bytes.Equal(ciphertext, legacy[:]) || keyID != database.storageKey.CurrentID() {
		t.Fatal("plaintext visitor network hash key remained in the current row")
	}
	key, _, err := database.openSecret(keyID, visitorNetworkHashMasterKeyContext(), ciphertext)
	if err != nil || !bytes.Equal(key, legacy[:]) {
		t.Fatalf("backfilled visitor network hash key did not preserve its value: %v", err)
	}
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_backfill", IngressRunID: "run_backfill", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil || lease.VisitorNetworkHashKeys != visitorNetworkHashKeys(legacy, now) {
		t.Fatalf("visitor network keys changed during backfill: %v", err)
	}
}
