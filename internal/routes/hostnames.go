package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const (
	hostnamePageSize       = 100
	randomHostnameAttempts = 16
)

type Hostname struct {
	ID            string
	IdentityID    string
	Hostname      string
	Kind          string
	Status        string
	Source        string
	CreatedAt     time.Time
	ActivatedAt   time.Time
	DeactivatedAt time.Time
}

const (
	HostnameKindManaged      = "managed"
	HostnameKindCustomDomain = "custom_domain"
	HostnameKindTemporary    = "temporary"

	HostnameStatusPendingRoute = "pending_route"
	HostnameStatusActive       = "active"
	HostnameStatusInactive     = "inactive"
	HostnameStatusAvailable    = "available"
	HostnameStatusRetired      = "retired"

	HostnameSourceUser      = "user"
	HostnameSourceGenerated = "generated"
)

func (s *Store) AddManagedHostname(
	ctx context.Context,
	identityID, label, requestKey string,
) (hostname Hostname, err error) {
	return s.AddHostname(ctx, identityID, HostnameKindManaged, label, requestKey)
}

func (s *Store) AddHostname(
	ctx context.Context,
	identityID, kind, name, requestKey string,
) (hostname Hostname, err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationHostname, started, err) }()
	if strings.TrimSpace(identityID) == "" || strings.TrimSpace(requestKey) != requestKey ||
		requestKey == "" || len(requestKey) > 128 {
		return Hostname{}, ErrInvalidArgument
	}
	if kind != HostnameKindManaged && kind != HostnameKindTemporary {
		return Hostname{}, ErrInvalidArgument
	}
	if kind == HostnameKindTemporary && name != "" {
		return Hostname{}, ErrInvalidArgument
	}
	canonicalLabel, err := s.canonicalBaseName(name)
	if err != nil {
		return Hostname{}, err
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: begin hostname: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)

	// Resolve request-key replays before quota checks or allocation.
	hostname, requestedLabel, requestedKind, found, err := readHostnameRequest(ctx, queries, identityID, requestKey)
	if err != nil {
		return Hostname{}, err
	}
	if found {
		if requestedLabel != canonicalLabel || requestedKind != kind || hostname.Status == HostnameStatusRetired {
			return Hostname{}, ErrInvalidStatus
		}
		return hostname, nil
	}
	if canonicalLabel != "" {
		hostname, err = readHostnameByName(ctx, queries, canonicalLabel+"."+s.hostnameSuffix)
		if err == nil {
			if hostname.IdentityID != identityID || hostname.Kind != HostnameKindManaged {
				return Hostname{}, ErrNameUnavailable
			}
			if hostname.Status == HostnameStatusInactive {
				if err := s.checkActiveHostnameQuota(ctx, queries, identityID); err != nil {
					return Hostname{}, err
				}
				count, err := queries.ReactivateManagedHostname(ctx, statedb.ReactivateManagedHostnameParams{
					ActivatedAt: now.UnixNano(), ID: hostname.ID, IdentityID: identityID,
				})
				if err != nil || count != 1 {
					return Hostname{}, ErrInvalidStatus
				}
				hostname.Status = HostnameStatusActive
				hostname.ActivatedAt = now
				hostname.DeactivatedAt = time.Time{}
			} else if hostname.Status != HostnameStatusActive {
				return Hostname{}, ErrNameUnavailable
			}
			if err := s.recordHostnameRequest(ctx, queries, identityID, requestKey, canonicalLabel, kind, hostname.ID, now); err != nil {
				return Hostname{}, err
			}
			if err := tx.Commit(); err != nil {
				return Hostname{}, fmt.Errorf("routes: commit hostname: %w", err)
			}
			return hostname, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Hostname{}, err
		}
	}
	if kind == HostnameKindManaged {
		if err := s.checkActiveHostnameQuota(ctx, queries, identityID); err != nil {
			return Hostname{}, err
		}
	}

	if canonicalLabel == "" {
		// Let the unique index arbitrate collisions and retry with fresh entropy.
		for range randomHostnameAttempts {
			candidate, candidateErr := randomHostnameLabel()
			if candidateErr != nil {
				return Hostname{}, candidateErr
			}
			hostname, found, err = s.insertHostname(ctx, queries, identityID, candidate, kind, HostnameSourceGenerated, now)
			if err != nil {
				return Hostname{}, err
			}
			if found {
				break
			}
		}
		if !found {
			return Hostname{}, errors.New("routes: allocate hostname")
		}
	} else {
		hostname, found, err = s.insertHostname(ctx, queries, identityID, canonicalLabel, kind, HostnameSourceUser, now)
		if err != nil {
			return Hostname{}, err
		}
		if !found {
			hostname, err = readHostnameByName(ctx, queries, canonicalLabel+"."+s.hostnameSuffix)
			if err != nil {
				return Hostname{}, err
			}
			if hostname.IdentityID != identityID || hostname.Kind != kind || hostname.Status != HostnameStatusActive {
				return Hostname{}, ErrNameUnavailable
			}
		}
	}
	if err := s.recordHostnameRequest(ctx, queries, identityID, requestKey, canonicalLabel, kind, hostname.ID, now); err != nil {
		return Hostname{}, err
	}
	if err := tx.Commit(); err != nil {
		return Hostname{}, fmt.Errorf("routes: commit hostname: %w", err)
	}
	return hostname, nil
}

func (s *Store) checkActiveHostnameQuota(ctx context.Context, queries *statedb.Queries, identityID string) error {
	active, err := queries.CountActivePersistentHostnames(ctx, identityID)
	if err != nil {
		return fmt.Errorf("routes: count hostnames: %w", err)
	}
	if active >= int64(s.maxActiveHostnames) {
		return ErrInvalidStatus
	}
	return nil
}

// FriendlyNameCapacity returns total allocator capacity and a conservative
// remaining count. Every managed base is counted because a custom label may
// also be a member of the friendly corpus.
func (s *Store) FriendlyNameCapacity(ctx context.Context) (int64, int64, error) {
	manifest, err := naming.FriendlyCorpusManifest()
	if err != nil {
		return 0, 0, err
	}
	consumed, err := s.queries.CountFriendlyNameCapacityConsumers(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("routes: count friendly name capacity: %w", err)
	}
	remaining := manifest.RemainingNamespaceCapacity - consumed
	if remaining < 0 {
		remaining = 0
	}
	return manifest.RemainingNamespaceCapacity, remaining, nil
}

func (s *Store) ListHostnames(ctx context.Context, identityID string) ([]Hostname, error) {
	var hostnames []Hostname
	cursor := ""
	for {
		page, next, err := s.ListHostnamesPage(ctx, identityID, cursor)
		if err != nil {
			return nil, err
		}
		hostnames = append(hostnames, page...)
		if next == "" {
			return hostnames, nil
		}
		cursor = next
	}
}

func (s *Store) ListHostnamesPage(
	ctx context.Context,
	identityID, cursor string,
) ([]Hostname, string, error) {
	storedHostnames, err := s.queries.ListHostnamesPage(ctx, statedb.ListHostnamesPageParams{
		IdentityID: identityID,
		Cursor:     cursor,
		Limit:      hostnamePageSize + 1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("routes: list hostnames: %w", err)
	}
	var hostnames []Hostname
	for _, hostname := range storedHostnames {
		hostnames = append(hostnames, hostnameFromDB(hostname))
	}
	if len(hostnames) <= hostnamePageSize {
		return hostnames, "", nil
	}
	next := hostnames[hostnamePageSize-1].ID
	return hostnames[:hostnamePageSize], next, nil
}

func (s *Store) ActiveRouteIDForHostname(ctx context.Context, identityID, hostnameID string) (string, error) {
	routeIDs, err := s.ActiveRouteIDsForHostname(ctx, identityID, hostnameID)
	if err != nil {
		return "", err
	}
	if len(routeIDs) == 0 {
		return "", nil
	}
	return routeIDs[0], nil
}

func (s *Store) ActiveRouteIDsForHostname(ctx context.Context, identityID, hostnameID string) ([]string, error) {
	routes, err := s.queries.ListActiveRoutesForHostname(ctx, statedb.ListActiveRoutesForHostnameParams{
		HostnameID: hostnameID,
		IdentityID: identityID,
	})
	if err != nil {
		return nil, fmt.Errorf("routes: find hostname routes: %w", err)
	}
	result := make([]string, 0, len(routes))
	for _, routeID := range routes {
		if routeID.Valid {
			result = append(result, routeID.String)
		}
	}
	if len(routes) == 0 {
		return nil, ErrNotFound
	}
	return result, nil
}

func (s *Store) RemoveHostname(ctx context.Context, identityID, hostnameID string) (err error) {
	started := time.Now()
	defer func() { s.observe(StoreOperationHostnameRemove, started, err) }()
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("routes: begin hostname removal: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	hostname, err := queries.GetHostnameByID(ctx, hostnameID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && hostname.IdentityID.String != identityID {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: read removed hostname: %w", err)
	}
	var count int64
	switch hostname.Kind {
	case HostnameKindManaged:
		count, err = queries.DeactivateManagedHostname(ctx, statedb.DeactivateManagedHostnameParams{
			DeactivatedAt: now.UnixNano(), ID: hostnameID, IdentityID: identityID,
		})
	case HostnameKindCustomDomain:
		count, err = queries.MakeCustomDomainAvailable(ctx, statedb.MakeCustomDomainAvailableParams{
			DeactivatedAt: now.UnixNano(), ID: hostnameID, IdentityID: identityID,
		})
	default:
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("routes: remove hostname: %w", err)
	}
	if err := requireCount(count, ErrNotFound); err != nil {
		return err
	}
	if _, err := s.stopHostnameRoutes(ctx, queries, hostnameID, now); err != nil {
		return err
	}
	if hostname.Kind == HostnameKindCustomDomain {
		if err := queries.InvalidateDomainVerificationsForHostname(ctx, statedb.InvalidateDomainVerificationsForHostnameParams{
			InvalidatedAt: sql.NullInt64{Int64: now.UnixNano(), Valid: true}, Domain: hostname.Hostname,
		}); err != nil {
			return fmt.Errorf("routes: invalidate removed domain verifications: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("routes: commit hostname removal: %w", err)
	}
	return nil
}

func (s *Store) stopHostnameRoutes(
	ctx context.Context,
	queries *statedb.Queries,
	hostnameID string,
	now time.Time,
) ([]string, error) {
	routes, err := queries.ListActiveHostnameRouteVersions(ctx, hostnameID)
	if err != nil {
		return nil, fmt.Errorf("routes: list stopped routes: %w", err)
	}
	if err := queries.DeleteHostnameRoutes(ctx, statedb.DeleteHostnameRoutesParams{DeletedAt: now.UnixNano(), HostnameID: hostnameID}); err != nil {
		return nil, fmt.Errorf("routes: delete stopped routes: %w", err)
	}
	if err := queries.RevokeHostnameRouteCredentials(ctx, statedb.RevokeHostnameRouteCredentialsParams{RevokedAt: now.UnixNano(), HostnameID: hostnameID}); err != nil {
		return nil, fmt.Errorf("routes: revoke stopped routes: %w", err)
	}
	if err := queries.ExpireHostnameRouteSessions(ctx, hostnameID); err != nil {
		return nil, fmt.Errorf("routes: expire stopped routes: %w", err)
	}
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		result = append(result, route.ID)
		version := uint64(route.Version)
		if err := s.recordLifecycle(ctx, queries, route.ID, version, now, LifecycleDisconnected); err != nil {
			return nil, err
		}
		if err := s.recordLifecycle(ctx, queries, route.ID, version, now, LifecycleDeleted); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) insertHostname(
	ctx context.Context,
	queries *statedb.Queries,
	identityID, label, kind, source string,
	now time.Time,
) (Hostname, bool, error) {
	id, err := newID("hostname")
	if err != nil {
		return Hostname{}, false, err
	}
	hostname := label + "." + s.hostnameSuffix
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return Hostname{}, false, ErrInvalidArgument
	}
	var count int64
	if kind == HostnameKindTemporary {
		count, err = queries.InsertTemporaryHostname(ctx, statedb.InsertTemporaryHostnameParams{
			ID: id, IdentityID: identityID, Hostname: hostname, CreatedAt: now.UnixNano(),
		})
	} else if source == HostnameSourceGenerated {
		count, err = queries.InsertGeneratedManagedHostname(ctx, statedb.InsertGeneratedManagedHostnameParams{
			ID: id, IdentityID: identityID, Hostname: hostname, CreatedAt: now.UnixNano(),
		})
	} else {
		count, err = queries.InsertHostname(ctx, statedb.InsertHostnameParams{
			ID: id, IdentityID: identityID, Hostname: hostname, CreatedAt: now.UnixNano(),
		})
	}
	if err != nil {
		return Hostname{}, false, fmt.Errorf("routes: insert hostname: %w", err)
	}
	if count == 0 {
		return Hostname{}, false, nil
	}
	status := HostnameStatusActive
	activatedAt := now
	if kind == HostnameKindTemporary {
		status = HostnameStatusPendingRoute
		activatedAt = time.Time{}
	}
	return Hostname{
		ID: id, IdentityID: identityID, Hostname: hostname, Kind: kind, Status: status,
		Source: source, CreatedAt: now, ActivatedAt: activatedAt,
	}, true, nil
}

func (s *Store) recordHostnameRequest(
	ctx context.Context,
	queries *statedb.Queries,
	identityID, requestKey, requestedLabel, requestedKind, hostnameID string,
	now time.Time,
) error {
	requests, err := queries.CountHostnameRequests(ctx, identityID)
	if err != nil {
		return fmt.Errorf("routes: count hostname requests: %w", err)
	}
	if requests >= int64(s.maxHostnameRequests) {
		return ErrInvalidStatus
	}
	if err := queries.InsertHostnameRequest(ctx, statedb.InsertHostnameRequestParams{
		IdentityID:     identityID,
		RequestKey:     requestKey,
		RequestedLabel: requestedLabel,
		RequestedKind:  requestedKind,
		HostnameID:     hostnameID,
		CreatedAt:      now.UnixNano(),
	}); err != nil {
		return fmt.Errorf("routes: record hostname request: %w", err)
	}
	return nil
}

func (s *Store) canonicalLabel(label string) (string, error) {
	if label == "" {
		return "", nil
	}
	canonical, err := naming.CanonicalizeHostname(label)
	if err != nil || strings.Contains(canonical, ".") {
		return "", ErrInvalidArgument
	}
	if _, reserved := s.reservedRouteNames[canonical]; reserved {
		return "", ErrNameUnavailable
	}
	return canonical, nil
}

func (s *Store) canonicalBaseName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	canonical, err := naming.CanonicalizeHostname(name)
	if err != nil {
		return "", ErrInvalidArgument
	}
	if !strings.Contains(canonical, ".") {
		return s.canonicalLabel(canonical)
	}
	label, found := strings.CutSuffix(canonical, "."+s.hostnameSuffix)
	if !found || label == "" || strings.Contains(label, ".") {
		return "", ErrInvalidArgument
	}
	return s.canonicalLabel(label)
}

func (s *Store) canonicalHostname(hostname string) (string, error) {
	return s.canonicalRouteHostname(hostname)
}

func (s *Store) canonicalRouteHostname(hostname string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func randomHostnameLabel() (string, error) {
	return naming.FriendlyName()
}

func hostnameFromDB(hostname statedb.Hostname) Hostname {
	result := Hostname{
		ID:         hostname.ID,
		IdentityID: hostname.IdentityID.String,
		Hostname:   hostname.Hostname,
		Kind:       hostname.Kind,
		Status:     hostname.Status,
		Source:     hostname.Source,
		CreatedAt:  time.Unix(0, hostname.CreatedAt).UTC(),
	}
	if hostname.ActivatedAt.Valid {
		result.ActivatedAt = time.Unix(0, hostname.ActivatedAt.Int64).UTC()
	}
	if hostname.DeactivatedAt.Valid {
		result.DeactivatedAt = time.Unix(0, hostname.DeactivatedAt.Int64).UTC()
	}
	return result
}

func readHostnameByName(ctx context.Context, queries *statedb.Queries, hostname string) (Hostname, error) {
	stored, err := queries.GetHostnameByHostname(ctx, hostname)
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: scan hostname: %w", err)
	}
	return hostnameFromDB(stored), nil
}

func readHostnameRequest(
	ctx context.Context,
	queries *statedb.Queries,
	identityID, requestKey string,
) (Hostname, string, string, bool, error) {
	request, err := queries.GetHostnameRequest(ctx, statedb.GetHostnameRequestParams{
		IdentityID: identityID,
		RequestKey: requestKey,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Hostname{}, "", "", false, nil
	}
	if err != nil {
		return Hostname{}, "", "", false, fmt.Errorf("routes: read hostname request: %w", err)
	}
	return hostnameFromDB(request.Hostname), request.RequestedLabel, request.RequestedKind, true, nil
}
