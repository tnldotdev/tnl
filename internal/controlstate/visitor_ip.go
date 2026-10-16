package controlstate

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/ippolicy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type VisitorIPGrantInput struct {
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
type VisitorIPGrant struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func ipGrantContext(urlID, id string) string { return "visitor-ip-grant:" + urlID + ":" + id }

func (d *Database) readVisitorIPs(ctx context.Context, q *controlstatedb.Queries, urlID string, now time.Time) ([]VisitorIPGrant, error) {
	rows, err := q.ListVisitorIPGrants(ctx, urlID)
	if err != nil {
		return nil, err
	}
	result := make([]VisitorIPGrant, 0, len(rows))
	for _, row := range rows {
		if row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(now) {
			continue
		}
		raw, _, err := d.storageKey.Open(row.StorageKeyID, ipGrantContext(urlID, row.ID), row.PrefixCiphertext)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(string(raw))
		if err != nil || prefix != prefix.Masked() {
			return nil, ErrPublicURLInvalid
		}
		result = append(result, VisitorIPGrant{ID: row.ID, Prefix: prefix.String(), ExpiresAt: optionalTime(row.ExpiresAt)})
	}
	return result, nil
}

// refreshVisitorIPPolicy changes only admission for new connections. it leaves
// the run and target untouched, and advances routing-table invalidation.
func (d *Database) refreshVisitorIPPolicy(ctx context.Context, q *controlstatedb.Queries, urlID string, now time.Time, advance bool) error {
	grants, err := d.readVisitorIPs(ctx, q, urlID, now)
	if err != nil {
		return err
	}
	prefixes := make([]netip.Prefix, len(grants))
	for i, g := range grants {
		prefixes[i], _ = netip.ParsePrefix(g.Prefix)
	}
	cipher, hashes, keyID, err := d.storeIPPolicy(urlID, prefixes, false)
	if err != nil {
		return err
	}
	changed, err := q.SaveVisitorIPPolicy(ctx, controlstatedb.SaveVisitorIPPolicyParams{PublicURLID: urlID, Ciphertext: cipher, StorageKeyID: nullableText(func() string {
		if len(cipher) == 0 {
			return ""
		}
		return keyID
	}()), Hashes: hashes, HashKeyID: nullableText(keyID), Now: timestamptz(now), AdvanceMutation: advance})
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrPublicURLMutationStale
	}
	err = q.ExpireVisitorIPGrants(ctx, controlstatedb.ExpireVisitorIPGrantsParams{PublicURLID: urlID, Now: timestamptz(now)})
	if err != nil {
		return err
	}
	url, err := q.LockPublicURLForRun(ctx, urlID)
	if err != nil {
		return err
	}
	run, err := q.GetOpenPublishRun(ctx, urlID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = q.LockPublishRun(ctx, run.ID); err != nil {
		return err
	}
	connections, err := validReadyPublisherConnections(ctx, q, run.ID, now)
	if err != nil {
		return err
	}
	pending := pendingIngressRoutingTableEvents{}
	if err = pending.addPublisherConnectionChanges(ctx, q, url, run, connections, now); err != nil {
		return err
	}
	return pending.publish(ctx, q)
}

// ReplaceVisitorAccess updates the complete access policy in one transaction.
// the current publish run and its publisher connections remain unchanged.
func (d *Database) ReplaceVisitorAccess(ctx context.Context, urlID, actorID string, mode VisitorAccessMode, values []string, expected uint64, now time.Time) (result PublicURL, retErr error) {
	if !mode.Valid() || len(values) > 256 || expected == 0 || expected > 9223372036854775807 {
		return result, ErrPublicURLInvalid
	}
	prefixes := make([]netip.Prefix, len(values))
	for i, value := range values {
		var err error
		prefixes[i], err = netip.ParsePrefix(value)
		if err != nil || prefixes[i] != prefixes[i].Masked() || prefixes[i].Addr().Is4In6() || prefixes[i].Addr().Zone() != "" {
			return result, ErrPublicURLInvalid
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "replace visitor access", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return result, err
	}
	if url.Purpose != "app" && url.Purpose != "alias" {
		return result, ErrPublicURLInvalid
	}
	if url.ServiceProtocol == "ssh" && mode != VisitorAccessRestricted {
		return result, ErrPublicURLInvalid
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return result, err
	}
	changed, err := q.SetPublicURLAccessMode(ctx, controlstatedb.SetPublicURLAccessModeParams{
		PublicURLID: urlID, AccessMode: string(mode), ExpectedRevision: int64(expected), Now: timestamptz(now),
	})
	if err != nil {
		return result, err
	}
	if changed != 1 {
		return result, ErrPublicURLMutationStale
	}
	if err = q.RevokeVisitorIPGrants(ctx, controlstatedb.RevokeVisitorIPGrantsParams{PublicURLID: urlID, RevokedAt: timestamptz(now)}); err != nil {
		return result, err
	}
	if err = q.MarkVisitorIPSet(ctx, urlID); err != nil {
		return result, err
	}
	for _, prefix := range prefixes {
		id, idErr := opaqueid.New(opaqueid.SharePrefix)
		if idErr != nil {
			return result, idErr
		}
		cipher, sealErr := d.storageKey.Seal(ipGrantContext(urlID, id), []byte(prefix.String()))
		if sealErr != nil {
			return result, sealErr
		}
		if err = q.CreateVisitorIPGrant(ctx, controlstatedb.CreateVisitorIPGrantParams{
			ID: id, PublicURLID: urlID, PrefixCiphertext: cipher, StorageKeyID: d.storageKey.CurrentID(), CreatedAt: timestamptz(now),
		}); err != nil {
			return result, err
		}
	}
	if err = d.refreshVisitorIPPolicy(ctx, q, urlID, now, false); err != nil {
		return result, err
	}
	updated, err := q.LockPublicURLForRun(ctx, urlID)
	if err != nil {
		return result, err
	}
	result = publicURLFromModel(updated, "")
	result.AllowedIPPrefixes = prefixes
	if err = tx.Commit(ctx); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}

func (d *Database) MutateVisitorIPs(ctx context.Context, urlID, actorID, operation, removeID string, input []VisitorIPGrantInput, now time.Time) (result []VisitorIPGrant, retErr error) {
	if len(input) > 256 || operation != "set" && operation != "add" && operation != "remove" && operation != "list" {
		return nil, ErrPublicURLInvalid
	}
	for _, item := range input {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || item.ExpiresAt != nil && !item.ExpiresAt.After(now) {
			return nil, ErrPublicURLInvalid
		}
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "mutate visitor IP set", &retErr)()
	q := controlstatedb.New(tx)
	url, err := lockVisitorURL(ctx, q, urlID)
	if err != nil {
		return nil, err
	}
	if err = visitorManager(ctx, q, url, actorID); err != nil {
		return nil, err
	}
	initialized, err := q.HasVisitorIPSet(ctx, urlID)
	if err != nil {
		return nil, err
	}
	if operation == "list" && !initialized && url.IpPolicy == "allow_all" {
		return []VisitorIPGrant{}, tx.Commit(ctx)
	}
	// the first add/list imports the existing explicit IP policy into the live set.
	if !initialized && operation != "set" {
		prefixes, err := d.openIPPolicy(urlID, url.AllowedIpPolicyStorageKeyID.String, url.AllowedIpPolicyCiphertext)
		if err != nil {
			return nil, err
		}
		for _, prefix := range prefixes {
			input = append(input, VisitorIPGrantInput{Prefix: prefix.String()})
		}
	}
	if operation == "set" {
		if err = q.RevokeVisitorIPGrants(ctx, controlstatedb.RevokeVisitorIPGrantsParams{PublicURLID: urlID, RevokedAt: timestamptz(now)}); err != nil {
			return nil, err
		}
	}
	if operation == "remove" {
		count, err := q.RemoveVisitorIPGrant(ctx, controlstatedb.RemoveVisitorIPGrantParams{PublicURLID: urlID, ID: removeID, RevokedAt: timestamptz(now)})
		if err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, ErrShareNotFound
		}
	}
	for _, item := range input {
		id, err := opaqueid.New(opaqueid.SharePrefix)
		if err != nil {
			return nil, err
		}
		cipher, err := d.storageKey.Seal(ipGrantContext(urlID, id), []byte(item.Prefix))
		if err != nil {
			return nil, err
		}
		if err = q.CreateVisitorIPGrant(ctx, controlstatedb.CreateVisitorIPGrantParams{ID: id, PublicURLID: urlID, PrefixCiphertext: cipher, StorageKeyID: d.storageKey.CurrentID(), CreatedAt: timestamptz(now), ExpiresAt: nullableTime(item.ExpiresAt)}); err != nil {
			return nil, err
		}
	}
	if operation != "list" || !initialized {
		if err = q.MarkVisitorIPSet(ctx, urlID); err != nil {
			return nil, err
		}
		if err = d.refreshVisitorIPPolicy(ctx, q, urlID, now, operation != "list"); err != nil {
			return nil, err
		}
	}
	result, err = d.readVisitorIPs(ctx, q, urlID, now)
	if err != nil {
		return nil, err
	}
	if len(result) > 256 {
		return nil, ErrPublicURLInvalid
	}
	return result, tx.Commit(ctx)
}

// ExpireVisitorIPs is replica-safe and bounded. call it from the control worker
// at least once per second; live permission reads also enforce expiry directly.
func (d *Database) ExpireVisitorIPs(ctx context.Context, now time.Time) (int, error) {
	urls, err := controlstatedb.New(d.pool).ExpiringVisitorIPURLs(ctx, timestamptz(now))
	if err != nil {
		return 0, err
	}
	for i, id := range urls {
		tx, err := d.pool.Begin(ctx)
		if err != nil {
			return i, err
		}
		q := controlstatedb.New(tx)
		_, err = lockVisitorURL(ctx, q, id)
		if errors.Is(err, ErrPreviewAccess) {
			err = q.ExpireVisitorIPGrants(ctx, controlstatedb.ExpireVisitorIPGrantsParams{PublicURLID: id, Now: timestamptz(now)})
		} else if err == nil {
			err = d.refreshVisitorIPPolicy(ctx, q, id, now, true)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return i, err
		}
		if err = tx.Commit(ctx); err != nil {
			return i, err
		}
	}
	return len(urls), nil
}

func (d *Database) ExpireVisitorPermissions(ctx context.Context, now time.Time) error {
	if _, err := d.ExpireVisitorIPs(ctx, now); err != nil {
		return err
	}
	q := controlstatedb.New(d.pool)
	if err := q.CleanupVisitorSessions(ctx, timestamptz(now)); err != nil {
		return err
	}
	if err := q.CleanupVisitorHandoffs(ctx, timestamptz(now)); err != nil {
		return err
	}
	return q.CleanupVisitorLogins(ctx, timestamptz(now))
}

func (d *Database) visitorIPAllowed(ctx context.Context, q *controlstatedb.Queries, url controlstatedb.ControlPublicUrl, source string, now time.Time) (bool, *time.Time, error) {
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return false, nil, nil
	}
	addr = addr.Unmap()
	if url.IpPolicy == string(IPPolicyAllowAll) {
		return true, nil, nil
	}
	initialized, err := q.HasVisitorIPSet(ctx, url.ID)
	if err != nil {
		return false, nil, err
	}
	if initialized {
		grants, err := d.readVisitorIPs(ctx, q, url.ID, now)
		if err != nil {
			return false, nil, err
		}
		var latest *time.Time
		for _, g := range grants {
			prefix, _ := netip.ParsePrefix(g.Prefix)
			if prefix.Contains(addr) {
				if g.ExpiresAt == nil {
					return true, nil, nil
				}
				if latest == nil || g.ExpiresAt.After(*latest) {
					latest = g.ExpiresAt
				}
			}
		}
		return latest != nil, latest, nil
	}
	if url.IpPolicy == "allow_all" {
		return true, nil, nil
	}
	if len(url.AllowedIpPolicyCiphertext) == 0 && len(url.AllowedIpHashes) != 0 {
		var entries []ippolicy.Entry
		if err := json.Unmarshal(url.AllowedIpHashes, &entries); err != nil {
			return false, nil, err
		}
		if len(entries) == 0 {
			return false, nil, nil
		}
		key, err := d.storageKey.IPPolicyKey(url.AllowedIpHashKeyID.String, "url:"+url.ID)
		if err != nil {
			return false, nil, err
		}
		policy, err := ippolicy.New(key, entries)
		if err != nil {
			return false, nil, err
		}
		return policy.Allows(addr), nil, nil
	}
	prefixes, err := d.openIPPolicy(url.ID, url.AllowedIpPolicyStorageKeyID.String, url.AllowedIpPolicyCiphertext)
	if err != nil {
		return false, nil, err
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true, nil, nil
		}
	}
	return false, nil, nil
}
