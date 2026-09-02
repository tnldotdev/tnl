package routes

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
)

func TestSignedRouteTransactionsReplayRenewalAndExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authorization.NewVerifier(authorization.Config{
		Issuer: "https://authority.example", Receiver: "https://server.example", KeyID: "key-1",
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	recorder := &testLifecycleRecorder{seen: make(map[string]struct{})}
	store, err := NewStore(db, "example", StoreConfig{
		AuthorizationVerifier: verifier,
		LifecycleRecorder:     recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"192.0.2.0/24", "2001:db8::/64"}
	createRequest := signedStoreRequest(t, authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, Hostname: "route.example",
		LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(), AllowedIPPrefixes: prefixes,
	})
	publishChecks := 0
	coordinator, err := NewCoordinator(ctx, store, "preflight", CoordinatorConfig{
		CheckHostnamePublishability: func(context.Context, string) error {
			publishChecks++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	if _, err := coordinator.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", routeToken, createRequest,
	); !errors.Is(err, ErrUnauthenticated) || publishChecks != 0 {
		t.Fatalf("invalid preflight = %v, publish checks = %d", err, publishChecks)
	}
	createClaims := signedClaims{
		Version: 1, KeyID: "key-1", Algorithm: authorization.Algorithm,
		Operation: authorization.OperationRouteCreate, Issuer: "https://authority.example", Receiver: "https://server.example",
		AuthorizationID: "authorization_00000000000000000000000000000001", Hostname: "route.example",
		Revision: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(20 * time.Second),
		RetryID:              "retry_00000000000000000000000000000001",
		CanonicalRequestHash: createRequest.RequestHash.String(), IPPolicyHash: digestString(createRequest.IPPolicyHash),
	}
	createRequest.Token = signSignedClaims(t, privateKey, createClaims)
	recordErr := errors.New("record registration")
	recorder.registrationErr = recordErr
	if _, err := store.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", "instance", routeToken, createRequest,
	); !errors.Is(err, recordErr) {
		t.Fatalf("registration failure = %v", err)
	}
	var routeRows int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM routes").Scan(&routeRows); err != nil {
		t.Fatal(err)
	}
	if routeRows != 0 {
		t.Fatalf("routes after registration rollback = %d, want 0", routeRows)
	}
	recorder.registrationErr = nil
	created, err := store.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", "instance", routeToken, createRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if created.Route.IdentityID != "" || created.Route.HostnameID != "" ||
		created.Route.AuthorizationID != createClaims.AuthorizationID || !created.Session.ExpiresAt.Equal(createClaims.ExpiresAt) {
		t.Fatalf("created = %#v", created)
	}
	if len(recorder.registrations) != 1 {
		t.Fatalf("registrations = %#v", recorder.registrations)
	}
	registration := recorder.registrations[0]
	if registration.RegistrationID == "" || registration.RouteID != created.Route.ID ||
		registration.Hostname != created.Route.Hostname || registration.SigningKeyID != createClaims.KeyID ||
		registration.AuthorizationID != createClaims.AuthorizationID || !registration.CreatedAt.Equal(now) ||
		registration.RetryID != createClaims.RetryID {
		t.Fatalf("registration = %#v", registration)
	}
	replayed, err := store.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", "instance", routeToken, createRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.ReusedResult || replayed.Route.ID != created.Route.ID || replayed.Session.ID != created.Session.ID ||
		replayed.SessionToken != created.SessionToken {
		t.Fatalf("replayed = %#v, created = %#v", replayed, created)
	}
	if len(recorder.registrations) != 1 {
		t.Fatalf("registrations after replay = %#v", recorder.registrations)
	}
	if err := store.InvalidateOtherServerInstances(ctx, "instance-2"); err != nil {
		t.Fatal(err)
	}
	restored, err := store.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", "instance-2", routeToken, createRequest,
	)
	if err != nil || !restored.ReusedResult || !restored.Restored || restored.Session.Status != SessionStatusPending ||
		restored.Session.ID != created.Session.ID || restored.SessionToken != created.SessionToken {
		t.Fatalf("restored retry = %#v, %v", restored, err)
	}
	createdKey, err := signedTailcatDialerKey(created.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	replayedKey, err := signedTailcatDialerKey(replayed.SessionToken)
	if err != nil || !createdKey.Equal(replayedKey) {
		t.Fatalf("reused tailcat dialer key differs: %v", err)
	}
	var hostnameRows, identityRows, prefixRows, useRows int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM hostnames").Scan(&hostnameRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM identities").Scan(&identityRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM route_allowed_ip_prefixes").Scan(&prefixRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM route_authorization_uses").Scan(&useRows); err != nil {
		t.Fatal(err)
	}
	if hostnameRows != 0 || identityRows != 0 || prefixRows != len(prefixes) || useRows != 1 {
		t.Fatalf("rows: hostnames=%d identities=%d prefixes=%d uses=%d", hostnameRows, identityRows, prefixRows, useRows)
	}

	reusedIDClaims := createClaims
	reusedIDClaims.RetryID = "retry_00000000000000000000000000000002"
	reusedIDRequest := createRequest
	reusedIDRequest.Token = signSignedClaims(t, privateKey, reusedIDClaims)
	if _, err := store.CreateSigned(
		ctx, "route.example", "http://127.0.0.1:3000", "instance", routeToken, reusedIDRequest,
	); !errors.Is(err, ErrAuthorizationReuseRejected) {
		t.Fatalf("authorization ID replay error = %v", err)
	}

	sessionRequest := signedStoreRequest(t, authorization.OperationRequest{
		Operation:  authorization.OperationRouteSessionCreate,
		RouteToken: routeToken.String(), AllowedIPPrefixes: prefixes,
	})
	routeID := created.Route.ID
	routeVersion := uint64(2)
	sessionClaims := signedClaims{
		Version: 1, KeyID: "key-1", Algorithm: authorization.Algorithm,
		Operation: authorization.OperationRouteSessionCreate, Issuer: "https://authority.example", Receiver: "https://server.example",
		AuthorizationID: "authorization_00000000000000000000000000000002", Hostname: "route.example",
		RouteID: &routeID, RouteVersion: &routeVersion, Revision: 2,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(20 * time.Second),
		RetryID:              "retry_00000000000000000000000000000003",
		CanonicalRequestHash: sessionRequest.RequestHash.String(), IPPolicyHash: digestString(sessionRequest.IPPolicyHash),
	}
	sessionRequest.Token = signSignedClaims(t, privateKey, sessionClaims)
	replacement, err := store.CreateSignedSession(ctx, routeID, "instance", routeToken, sessionRequest)
	if err != nil {
		t.Fatal(err)
	}
	sessionReplay, err := store.CreateSignedSession(ctx, routeID, "instance", routeToken, sessionRequest)
	if err != nil || !sessionReplay.ReusedResult || sessionReplay.SessionToken != replacement.SessionToken ||
		sessionReplay.Session.ID != replacement.Session.ID {
		t.Fatalf("session replay = %#v, %v", sessionReplay, err)
	}

	renewHash, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRenew, RouteVersion: routeVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	renewClaims := sessionClaims
	renewClaims.Operation = authorization.OperationRenew
	renewClaims.AuthorizationID = "authorization_00000000000000000000000000000003"
	renewClaims.RetryID = "retry_00000000000000000000000000000004"
	renewClaims.ExpiresAt = now.Add(10 * time.Minute)
	renewClaims.CanonicalRequestHash = renewHash.String()
	lowerRevisionClaims := renewClaims
	lowerRevisionClaims.Revision = 1
	if _, err := store.HeartbeatSigned(
		ctx, replacement.Session, signSignedClaims(t, privateKey, lowerRevisionClaims), renewHash,
	); !errors.Is(err, ErrAuthorizationReuseRejected) {
		t.Fatalf("lower revision renewal error = %v", err)
	}
	shorterClaims := renewClaims
	shorterClaims.ExpiresAt = now.Add(10 * time.Second)
	if _, err := store.HeartbeatSigned(
		ctx, replacement.Session, signSignedClaims(t, privateKey, shorterClaims), renewHash,
	); !errors.Is(err, ErrAuthorizationReuseRejected) {
		t.Fatalf("shorter renewal error = %v", err)
	}
	renewal := signSignedClaims(t, privateKey, renewClaims)
	expiresAt, err := store.HeartbeatSigned(ctx, replacement.Session, renewal, renewHash)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(SessionLifetime); !expiresAt.Equal(want) {
		t.Fatalf("renewed session expiry = %v, want %v", expiresAt, want)
	}
	if _, err := store.HeartbeatSigned(ctx, replacement.Session, renewal, renewHash); !errors.Is(err, ErrAuthorizationReuseRejected) {
		t.Fatalf("renewal replay error = %v", err)
	}
	if _, err := store.CreateSignedSession(
		ctx, routeID, "instance", routeToken, sessionRequest,
	); !errors.Is(err, ErrAuthorizationReuseRejected) {
		t.Fatalf("superseded session authorization replay error = %v", err)
	}
	now = now.Add(21 * time.Second)
	if _, err := store.AuthenticateSession(ctx, routeID, routeVersion, replacement.SessionToken, "instance"); err != nil {
		t.Fatalf("renewed session authentication: %v", err)
	}
	now = renewClaims.ExpiresAt.Add(time.Nanosecond)
	expiredRenewalClaims := renewClaims
	expiredRenewalClaims.AuthorizationID = "authorization_00000000000000000000000000000004"
	expiredRenewalClaims.RetryID = "retry_00000000000000000000000000000005"
	expiredRenewalClaims.IssuedAt = now
	expiredRenewalClaims.ExpiresAt = now.Add(10 * time.Minute)
	expiredRenewal := signSignedClaims(t, privateKey, expiredRenewalClaims)
	expiredSession, err := store.AuthenticateSessionForRenewal(ctx, routeID, routeVersion, replacement.SessionToken, "instance")
	if err != nil {
		t.Fatalf("authenticate expired session for renewal: %v", err)
	}
	if expiry, err := store.HeartbeatSigned(ctx, expiredSession, expiredRenewal, renewHash); err != nil ||
		!expiry.Equal(now.Add(SessionLifetime)) {
		t.Fatalf("expired authorization renewal = %v, %v", expiry, err)
	}
	if _, err := store.AuthenticateSession(ctx, routeID, routeVersion, replacement.SessionToken, "instance"); err != nil {
		t.Fatalf("authenticate recovered session: %v", err)
	}
	now = expiredRenewalClaims.ExpiresAt.Add(time.Nanosecond)
	if _, err := store.AuthenticateSession(ctx, routeID, routeVersion, replacement.SessionToken, "instance"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("expired authorization session error = %v", err)
	}
	wrongRouteToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSigned(ctx, routeID, wrongRouteToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong signed delete credential error = %v", err)
	}
	if err := store.DeleteSigned(ctx, routeID, routeToken); err != nil {
		t.Fatal(err)
	}
	if count := len(recorder.changes); count < 2 ||
		recorder.changes[count-2].Transition != LifecycleDisconnected ||
		recorder.changes[count-1].Transition != LifecycleDeleted {
		t.Fatalf("signed delete lifecycle = %#v", recorder.changes)
	}
	if err := store.DeleteSigned(ctx, routeID, routeToken); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("signed delete replay error = %v", err)
	}
}

func TestCreateSignedAuthorizationRevisionFloor(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authorization.NewVerifier(authorization.Config{
		Issuer: "https://authority.example", Receiver: "https://server.example", KeyID: "key-1",
		PublicKey: publicKey, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewStore(db, "example", StoreConfig{AuthorizationVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	request := signedStoreRequest(t, authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, Hostname: "route.example",
		LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	})
	claims := signedClaims{
		Version: 1, KeyID: "key-1", Algorithm: authorization.Algorithm,
		Operation: authorization.OperationRouteCreate, Issuer: "https://authority.example",
		Receiver: "https://server.example", Hostname: "route.example",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute),
		CanonicalRequestHash: request.RequestHash.String(),
	}
	create := func(authorizationID, retryID string, revision uint64) (Provisioning, error) {
		t.Helper()
		claims.AuthorizationID = authorizationID
		claims.RetryID = retryID
		claims.Revision = revision
		signedRequest := request
		signedRequest.Token = signSignedClaims(t, privateKey, claims)
		return store.CreateSigned(
			ctx, "route.example", "http://127.0.0.1:3000", "instance", routeToken, signedRequest,
		)
	}

	created, err := create(
		"authorization_00000000000000000000000000000010",
		"retry_00000000000000000000000000000010",
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := create(
		"authorization_00000000000000000000000000000011",
		"retry_00000000000000000000000000000011",
		2,
	); !errors.Is(err, ErrAuthorizationReplayed) {
		t.Fatalf("lower revision active replacement error = %v", err)
	}
	equal, err := create(
		"authorization_00000000000000000000000000000012",
		"retry_00000000000000000000000000000012",
		3,
	)
	if err != nil {
		t.Fatal(err)
	}
	if equal.Route.ID != created.Route.ID || equal.Route.RouteVersion != 2 || equal.Route.AuthorizationRevision != 3 {
		t.Fatalf("equal revision replacement = %#v", equal.Route)
	}
	if err := store.DeleteSigned(ctx, equal.Route.ID, routeToken); err != nil {
		t.Fatal(err)
	}
	if _, err := create(
		"authorization_00000000000000000000000000000013",
		"retry_00000000000000000000000000000013",
		2,
	); !errors.Is(err, ErrAuthorizationReplayed) {
		t.Fatalf("lower revision recreation error = %v", err)
	}
	routeToken, _, _, err = credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	request = signedStoreRequest(t, authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, Hostname: "route.example",
		LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	})
	claims.CanonicalRequestHash = request.RequestHash.String()
	newer, err := create(
		"authorization_00000000000000000000000000000014",
		"retry_00000000000000000000000000000014",
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	if newer.Route.ID == equal.Route.ID || newer.Route.RouteVersion != 1 || newer.Route.AuthorizationRevision != 4 {
		t.Fatalf("newer revision recreation = %#v", newer.Route)
	}
}

type signedClaims struct {
	Version              uint64                  `json:"version"`
	KeyID                string                  `json:"kid"`
	Algorithm            string                  `json:"alg"`
	Operation            authorization.Operation `json:"operation"`
	Issuer               string                  `json:"issuer"`
	Receiver             string                  `json:"receiver"`
	AuthorizationID      string                  `json:"authorization_id"`
	Hostname             string                  `json:"hostname"`
	RouteID              *string                 `json:"route_id,omitempty"`
	RouteVersion         *uint64                 `json:"route_version,omitempty"`
	Revision             uint64                  `json:"revision"`
	IssuedAt             time.Time               `json:"issued_at"`
	ExpiresAt            time.Time               `json:"expires_at"`
	RetryID              string                  `json:"retry_id"`
	CanonicalRequestHash string                  `json:"canonical_request_hash"`
	IPPolicyHash         *string                 `json:"ip_policy_hash,omitempty"`
}

func signedStoreRequest(t *testing.T, operation authorization.OperationRequest) SignedRequest {
	t.Helper()
	requestHash, err := authorization.CanonicalRequestHash(operation)
	if err != nil {
		t.Fatal(err)
	}
	ipHash, err := authorization.IPPolicyHash(operation.AllowedIPPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	return SignedRequest{
		RequestHash: requestHash, IPPolicyHash: ipHash,
		AllowedIPPrefixes: append([]string(nil), operation.AllowedIPPrefixes...),
	}
}

func signSignedClaims(t *testing.T, privateKey ed25519.PrivateKey, claims signedClaims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": authorization.Algorithm, "kid": claims.KeyID, "typ": authorization.Type,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(encoded)))
}

func digestString(digest *authorization.Digest) *string {
	if digest == nil {
		return nil
	}
	value := digest.String()
	return &value
}
