package controlstate

import (
	"testing"
	"time"
)

func TestIntegrationVisitorNetworkHashKeyEncryptedAndShared(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_network_key")
	first, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_first", IngressRunID: "run_first", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	var keyID string
	if err := database.pool.QueryRow(t.Context(), `SELECT visitor_network_hash_master_key_ciphertext,
		visitor_network_hash_master_key_storage_key_id FROM control.visitor_network_hash_keys`).Scan(&ciphertext, &keyID); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) <= 32 || keyID != database.storageKey.CurrentID() {
		t.Fatal("visitor network hash key was not stored only as a protected secret")
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
