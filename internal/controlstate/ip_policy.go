package controlstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/ippolicy"
)

func publicURLIPPolicyContext(publicURLID string) string {
	return "control.public_urls.allowed_ip_policy_ciphertext\x00" + publicURLID
}

func publicURLRequestDigestContext(publicURLID string) string {
	return "control.public_urls.request_digest_ciphertext\x00" + publicURLID
}

func publishRunRequestDigestContext(publishRunID string) string {
	return "control.publish_runs.request_digest_ciphertext\x00" + publishRunID
}

func (d *Database) storeIPPolicy(publicURLID string, prefixes []netip.Prefix, guest bool) (ciphertext, hashes []byte, keyID string, err error) {
	if len(prefixes) == 0 {
		return nil, nil, "", nil
	}
	keyID = d.storageKey.CurrentID()
	key, err := d.storageKey.IPPolicyKey(keyID, "url:"+publicURLID)
	if err != nil {
		return nil, nil, "", err
	}
	entries := make([]ippolicy.Entry, len(prefixes))
	canonical := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		entry, err := ippolicy.Hash(key, prefix)
		if err != nil {
			return nil, nil, "", err
		}
		entries[index], canonical[index] = entry, prefix.String()
	}
	hashes, err = json.Marshal(entries)
	if err != nil {
		return nil, nil, "", fmt.Errorf("controlstate: encode hashed IP policy: %w", err)
	}
	if guest {
		return nil, hashes, keyID, nil
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, nil, "", fmt.Errorf("controlstate: encode saved IP policy: %w", err)
	}
	ciphertext, err = d.sealSecret(publicURLIPPolicyContext(publicURLID), encoded)
	return ciphertext, hashes, keyID, err
}

func (d *Database) openIPPolicy(publicURLID, keyID string, ciphertext []byte) ([]netip.Prefix, error) {
	if len(ciphertext) == 0 && keyID == "" {
		return nil, nil
	}
	if len(ciphertext) == 0 || keyID == "" {
		return nil, errors.New("controlstate: stored IP policy is incomplete")
	}
	encoded, _, err := d.openSecret(keyID, publicURLIPPolicyContext(publicURLID), ciphertext)
	if err != nil {
		return nil, err
	}
	var strings []string
	if err := json.Unmarshal(encoded, &strings); err != nil || len(strings) == 0 {
		return nil, errors.New("controlstate: stored IP policy is invalid")
	}
	prefixes := make([]netip.Prefix, len(strings))
	for index, value := range strings {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return nil, errors.New("controlstate: stored IP prefix is invalid")
		}
		prefixes[index] = prefix
	}
	return prefixes, nil
}

func (d *Database) restorePublicURLPolicy(route *PublicURL, keyID pgtype.Text, ciphertext, hashes []byte) error {
	if len(hashes) == 0 {
		if len(ciphertext) != 0 || len(route.AllowedIPPrefixes) != 0 {
			return errors.New("controlstate: public URL IP policy has not been protected")
		}
		route.AllowedIPPrefixes = nil
		return nil
	}
	if len(ciphertext) == 0 {
		if keyID.Valid {
			return errors.New("controlstate: guest IP policy has unexpected ciphertext key")
		}
		route.AllowedIPPrefixes = nil
		return nil
	}
	prefixes, err := d.openIPPolicy(route.ID, keyID.String, ciphertext)
	if err != nil {
		return err
	}
	route.AllowedIPPrefixes = prefixes
	return nil
}
