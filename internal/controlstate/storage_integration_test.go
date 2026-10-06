package controlstate

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"
)

func TestIntegrationStorageKeyRotation(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "storage_rotation")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	// seed every recoverable secret kind using the old key. no read through a
	// dual-key database may lazily rotate a row before the batch assertions.
	session, err := database.CreateBuiltinControlSession(ctx, "routes.example.test", 1, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := database.AuthenticateAccessToken(ctx, session.AccessToken, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(ctx, "https://acme.example.test/rotation", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := database.ControlTLSCache(account.DirectoryURL)
	if err != nil {
		t.Fatal(err)
	}
	cacheData := []byte("rotation state")
	if err := cache.Put(ctx, "rotation.example.test", cacheData); err != nil {
		t.Fatal(err)
	}
	lease, err := database.RegisterRelay(ctx, relayLifecycleRegistration("relay-rotation"), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := database.PrepareRelayCertificateOrder(ctx, account.ID, now, time.Hour); err != nil || !created {
		t.Fatalf("seed relay order: created %t, %v", created, err)
	}
	order, found, err := database.ClaimRelayCertificateOrderWork(ctx, "old-key-worker", now, time.Second)
	if err != nil || !found {
		t.Fatalf("seed relay order key: found %t, %v", found, err)
	}
	certificate, privateKey := testRelayCertificate(t, lease.TLSServerName, now)
	if _, err := database.StoreRelayTransportCertificate(ctx, lease.RelayServiceID, lease.TLSServerName, certificate, privateKey, now); err != nil {
		t.Fatal(err)
	}
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateBuiltinGuestTrial(ctx, guest, "routes.example.test", now); err != nil {
		t.Fatal(err)
	}
	masterKey, err := database.EnsureGuestPrincipal(ctx, guest.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	visitorLease, err := database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "ingress_original_key", IngressRunID: "run_original_key", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var visitorCiphertext []byte
	var visitorKeyID string
	if err := database.pool.QueryRow(ctx, `SELECT visitor_network_hash_master_key_ciphertext,
		visitor_network_hash_master_key_storage_key_id FROM control.public_url_usage_configuration`).Scan(&visitorCiphertext, &visitorKeyID); err != nil {
		t.Fatal(err)
	}
	visitorKey, _, err := database.openSecret(visitorKeyID, visitorNetworkHashMasterKeyContext(), visitorCiphertext)
	if err != nil || len(visitorKey) != 32 {
		t.Fatalf("invalid visitor network hash key before rotation: %v", err)
	}
	stores := []struct {
		table, ciphertextColumn, keyColumn string
		plaintext                          []byte
	}{
		{"control_sessions", "retry_secret_ciphertext", "retry_secret_storage_key_id", principal.RetrySecret[:]},
		{"acme_accounts", "account_key_ciphertext", "account_key_storage_key_id", account.AccountKeyDER},
		{"control_tls_cache", "cache_ciphertext", "cache_storage_key_id", cacheData},
		{"relay_services", "transport_private_key_ciphertext", "transport_private_key_storage_key_id", privateKey},
		{"relay_certificate_orders", "private_key_ciphertext", "private_key_storage_key_id", order.PrivateKeyPEM},
		{"runtime_secret", "guest_retry_master_key_ciphertext", "guest_retry_master_key_storage_key_id", masterKey[:]},
		{"public_url_usage_configuration", "visitor_network_hash_master_key_ciphertext", "visitor_network_hash_master_key_storage_key_id", visitorKey},
	}
	before := make(map[string][]byte)
	oldKeyID := database.storageKey.CurrentID()
	for _, store := range stores {
		var ciphertext []byte
		var keyID string
		// each table has exactly one seeded row; Scan also rejects an empty store.
		var count int
		if err := database.pool.QueryRow(ctx, "SELECT count(*) FROM control."+store.table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s precondition: rows %d, %v", store.table, count, err)
		}
		if err := database.pool.QueryRow(ctx, "SELECT "+store.ciphertextColumn+", "+store.keyColumn+" FROM control."+store.table).Scan(&ciphertext, &keyID); err != nil {
			t.Fatal(err)
		}
		if keyID != oldKeyID || len(ciphertext) == 0 || bytes.Contains(ciphertext, store.plaintext) {
			t.Fatalf("%s did not persist an encrypted old-key secret", store.table)
		}
		before[store.table] = ciphertext
	}
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotating, err := Open(ctx, databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	for remaining := len(stores); remaining > len(stores)-2; remaining-- {
		rotated, err := rotating.ReencryptStorageSecrets(ctx, 1)
		if err != nil || rotated != 1 {
			t.Fatalf("rotation with %d remaining: rotated %d, %v", remaining, rotated, err)
		}
		count, err := rotating.countPreviousStorageSecrets(ctx)
		if err != nil || count != int64(remaining-1) {
			t.Fatalf("bounded batch left %d old-key rows, want %d: %v", count, remaining-1, err)
		}
	}
	// Complete must drain the other five kinds. the earlier size-limited calls
	// must not have already done all the work.
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 0 {
		t.Fatalf("completed rotation left %d old-key rows: %v", remaining, err)
	}
	if rotated, err := rotating.ReencryptStorageSecrets(ctx, 1); err != nil || rotated != 0 {
		t.Fatalf("completed rotation = %d, %v", rotated, err)
	}
	if _, err := rotating.ForgetGuestPrivateState(ctx, now.Add(73*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	database.Close()

	// removing the old key is the recovery guarantee. a dual-key read
	// would succeed even if a store had been omitted from rotation entirely.
	reopened, err := Open(ctx, databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	for _, store := range stores {
		var ciphertext []byte
		var keyID string
		if err := reopened.pool.QueryRow(ctx, "SELECT "+store.ciphertextColumn+", "+store.keyColumn+" FROM control."+store.table).Scan(&ciphertext, &keyID); err != nil {
			t.Fatal(err)
		}
		if keyID != reopened.storageKey.CurrentID() || bytes.Equal(ciphertext, before[store.table]) {
			t.Fatalf("%s retained its old ciphertext or key ID", store.table)
		}
	}
	recoveredPrincipal, err := reopened.AuthenticateAccessToken(ctx, session.AccessToken, 1, now)
	if err != nil || recoveredPrincipal.RetrySecret != principal.RetrySecret {
		t.Fatalf("recover control-session retry secret: %v", err)
	}
	recoveredAccount, err := reopened.EnsureACMEAccount(ctx, account.DirectoryURL, account.ContactEmail, now)
	if err != nil || recoveredAccount.ID != account.ID || !bytes.Equal(recoveredAccount.AccountKeyDER, account.AccountKeyDER) {
		t.Fatalf("recover ACME account key: %v", err)
	}
	recoveredCache, err := reopened.ControlTLSCache(account.DirectoryURL)
	if err != nil {
		t.Fatal(err)
	}
	data, err := recoveredCache.Get(ctx, "rotation.example.test")
	if err != nil || !bytes.Equal(data, cacheData) {
		t.Fatalf("recover control TLS cache: %v", err)
	}
	recoveredCertificate, err := reopened.GetRelayTransportCertificate(ctx, lease.RelayLeaseIdentity, now)
	if err != nil || recoveredCertificate.CertificatePEM != string(certificate) || recoveredCertificate.PrivateKeyPEM != string(privateKey) {
		t.Fatalf("recover relay certificate: %v", err)
	}
	recoveredOrder, found, err := reopened.ClaimRelayCertificateOrderWork(ctx, "new-key-worker", now.Add(time.Second), time.Minute)
	if err != nil || !found || recoveredOrder.ID != order.ID || !bytes.Equal(recoveredOrder.PrivateKeyPEM, order.PrivateKeyPEM) {
		t.Fatalf("recover relay order key: found %t, %v", found, err)
	}
	recoveredMaster, err := reopened.EnsureGuestPrincipal(ctx, guest.ID, now)
	if err != nil || recoveredMaster != masterKey {
		t.Fatalf("recover external retry master key: %v", err)
	}
	recoveredVisitorLease, err := reopened.RegisterIngress(ctx, IngressRegistration{
		IngressID: "ingress_rotated_key", IngressRunID: "run_rotated_key", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil || recoveredVisitorLease.VisitorNetworkHashKeys != visitorLease.VisitorNetworkHashKeys {
		t.Fatalf("recover visitor network hash keys after rotation: %v", err)
	}
}
