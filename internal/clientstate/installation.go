package clientstate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const installationIDPrefix = "installation_"

// InstallationID returns the stable pseudonymous identifier for this client database.
func (d *Database) InstallationID(ctx context.Context) (string, error) {
	id, err := d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: read installation ID: %w", err)
	}
	if id != "" {
		if !validInstallationID(id) {
			return "", errors.New("clientstate: installation ID is invalid")
		}
		return id, nil
	}
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("clientstate: generate installation ID: %w", err)
	}
	generated := installationIDPrefix + hex.EncodeToString(material[:])
	if err := d.queries.SetInstallationID(ctx, generated); err != nil {
		return "", fmt.Errorf("clientstate: save installation ID: %w", err)
	}
	id, err = d.queries.GetInstallationID(ctx)
	if err != nil {
		return "", fmt.Errorf("clientstate: reread installation ID: %w", err)
	}
	if !validInstallationID(id) {
		return "", errors.New("clientstate: installation ID is invalid")
	}
	return id, nil
}

func validInstallationID(id string) bool {
	encoded, found := strings.CutPrefix(id, installationIDPrefix)
	if !found || len(encoded) != 32 || encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}
