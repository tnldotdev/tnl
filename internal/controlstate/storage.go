package controlstate

import "errors"

func (d *Database) sealSecret(context string, plaintext []byte) ([]byte, error) {
	if d == nil || d.storageKey == nil {
		return nil, errors.New("controlstate: storage key is unavailable")
	}
	return d.storageKey.Seal(context, plaintext)
}

func (d *Database) openSecret(keyID, context string, ciphertext []byte) ([]byte, bool, error) {
	if d == nil || d.storageKey == nil {
		return nil, false, errors.New("controlstate: storage key is unavailable")
	}
	return d.storageKey.Open(keyID, context, ciphertext)
}

func controlSessionRetrySecretContext(sessionID string) string {
	return "control.control_sessions.retry_secret_ciphertext\x00" + sessionID
}

func guestRetryMasterKeyContext() string {
	return "control.runtime_secret.guest_retry_master_key_ciphertext\x00id"
}

func visitorNetworkHashMasterKeyContext() string {
	return "control.public_url_usage_configuration.visitor_network_hash_master_key_ciphertext\x00id"
}

func acmeAccountKeyContext(accountID string) string {
	return "control.acme_accounts.account_key_ciphertext\x00" + accountID
}

func controlTLSCacheContext(directoryURL, cacheKey string) string {
	return "control.control_tls_cache.cache_ciphertext\x00" + directoryURL + "\x00" + cacheKey
}

func relayTransportPrivateKeyContext(relayServiceID string) string {
	return "control.relay_services.transport_private_key_ciphertext\x00" + relayServiceID
}

func relayCertificateOrderPrivateKeyContext(orderID string) string {
	return "control.relay_certificate_orders.private_key_ciphertext\x00" + orderID
}
