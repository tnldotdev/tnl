package controlstate

import "testing"

func TestIntegrationStorageKeyRotation(t *testing.T) {
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "storage_key_rotation")
	testStorageKeyRotation(t, database, databaseURL)
}
