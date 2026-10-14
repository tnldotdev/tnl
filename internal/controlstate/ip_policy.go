package controlstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

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

type operatorIPEntry struct {
	ID        string    `json:"id"`
	Prefix    string    `json:"prefix"`
	OwnerID   string    `json:"owner_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type savedIPPolicy struct {
	Source   []string          `json:"source"`
	Operator []operatorIPEntry `json:"operator,omitempty"`
}

func (d *Database) storeIPPolicy(publicURLID string, prefixes []netip.Prefix, guest bool) (ciphertext, hashes []byte, keyID string, err error) {
	return d.storeIPPolicyWithOperator(publicURLID, prefixes, nil, guest)
}

func (d *Database) storeIPPolicyWithOperator(publicURLID string, prefixes []netip.Prefix, operator []operatorIPEntry, guest bool) (ciphertext, hashes []byte, keyID string, err error) {
	if len(prefixes) == 0 {
		if len(operator) != 0 {
			return nil, nil, "", ErrPublicURLInvalid
		}
		return nil, nil, "", nil
	}
	keyID = d.storageKey.CurrentID()
	key, err := d.storageKey.IPPolicyKey(keyID, "url:"+publicURLID)
	if err != nil {
		return nil, nil, "", err
	}
	canonical := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		canonical[index] = prefix.String()
	}
	policy := savedIPPolicy{Source: canonical, Operator: operator}
	entries, err := hashSavedIPPolicy(key, policy)
	if err != nil {
		return nil, nil, "", err
	}
	hashes, err = json.Marshal(entries)
	if err != nil {
		return nil, nil, "", fmt.Errorf("controlstate: encode hashed IP policy: %w", err)
	}
	if guest {
		return nil, hashes, keyID, nil
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, nil, "", fmt.Errorf("controlstate: encode saved IP policy: %w", err)
	}
	ciphertext, err = d.sealSecret(publicURLIPPolicyContext(publicURLID), encoded)
	return ciphertext, hashes, keyID, err
}

func hashSavedIPPolicy(key [32]byte, policy savedIPPolicy) ([]ippolicy.Entry, error) {
	entries := make([]ippolicy.Entry, 0, len(policy.Source)+len(policy.Operator))
	for _, value := range policy.Source {
		prefix, err := parseStoredIPPrefix(value)
		if err != nil {
			return nil, err
		}
		entry, err := ippolicy.Hash(key, prefix)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	for _, allowed := range policy.Operator {
		prefix, err := parseStoredIPPrefix(allowed.Prefix)
		if err != nil || allowed.ExpiresAt.IsZero() {
			return nil, ErrPublicURLInvalid
		}
		entry, err := ippolicy.Hash(key, prefix)
		if err != nil {
			return nil, err
		}
		entry.ExpiresAt = &allowed.ExpiresAt
		entries = append(entries, entry)
	}
	return entries, nil
}

func (d *Database) openIPPolicy(publicURLID, keyID string, ciphertext []byte) ([]netip.Prefix, error) {
	policy, err := d.openSavedIPPolicy(publicURLID, keyID, ciphertext)
	if err != nil {
		return nil, err
	}
	if len(policy.Source) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(policy.Source))
	for _, value := range policy.Source {
		prefix, err := parseStoredIPPrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (d *Database) openSavedIPPolicy(publicURLID, keyID string, ciphertext []byte) (savedIPPolicy, error) {
	if len(ciphertext) == 0 && keyID == "" {
		return savedIPPolicy{}, nil
	}
	if len(ciphertext) == 0 || keyID == "" {
		return savedIPPolicy{}, errors.New("controlstate: stored IP policy is incomplete")
	}
	encoded, _, err := d.openSecret(keyID, publicURLIPPolicyContext(publicURLID), ciphertext)
	if err != nil {
		return savedIPPolicy{}, err
	}
	var policy savedIPPolicy
	if err := json.Unmarshal(encoded, &policy); err != nil || len(policy.Source) == 0 {
		return savedIPPolicy{}, errors.New("controlstate: stored IP policy is invalid")
	}
	for _, value := range policy.Source {
		if _, err := parseStoredIPPrefix(value); err != nil {
			return savedIPPolicy{}, err
		}
	}
	for _, entry := range policy.Operator {
		if entry.ID == "" || entry.OwnerID == "" || entry.ExpiresAt.IsZero() {
			return savedIPPolicy{}, errors.New("controlstate: stored operator IP entry is invalid")
		}
		if _, err := parseStoredIPPrefix(entry.Prefix); err != nil {
			return savedIPPolicy{}, err
		}
	}
	return policy, nil
}

func parseStoredIPPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || prefix.String() != value {
		return netip.Prefix{}, errors.New("controlstate: stored IP prefix is invalid")
	}
	return prefix, nil
}

func nextOperatorIPExpiry(entries []operatorIPEntry) pgtype.Timestamptz {
	var next time.Time
	for _, entry := range entries {
		if next.IsZero() || entry.ExpiresAt.Before(next) {
			next = entry.ExpiresAt
		}
	}
	return pgtype.Timestamptz{Time: next, Valid: !next.IsZero()}
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
