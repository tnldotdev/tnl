package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// EnrollmentFiles stores whole private records durably before returning from
// Write. the caller scopes it to the exact server, project, deployment and slot.
type EnrollmentFiles interface {
	Read(context.Context, string, int64) ([]byte, bool, error)
	Write(context.Context, string, []byte) error
	Lock(context.Context, string) (io.Closer, error)
}

type EnrollmentControl interface {
	RedeemScopedDeploymentPublisherEnrollment(context.Context, string, ed25519.PublicKey, string, string) (controlv1.DeploymentPublisherIdentity, error)
	VerifyDeploymentIdentity(context.Context, controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherVerification, error)
}

type EnrollmentSelection struct {
	ControlURL   string `json:"control_url"`
	ProjectKey   string `json:"project_key"`
	DeploymentID string `json:"deployment_id"`
	Instance     string `json:"instance"`
}

type enrollmentRecord struct {
	Version    int                                    `json:"version"`
	Selection  EnrollmentSelection                    `json:"selection"`
	PrivateKey string                                 `json:"private_key"`
	Bootstrap  string                                 `json:"bootstrap_digest,omitempty"`
	Member     *controlv1.DeploymentPublisherIdentity `json:"member,omitempty"`
}

// EnrolledIdentity holds the selection's exclusive lock until all publication
// work joins. the signing key never leaves publisher-owned code.
type EnrolledIdentity struct {
	Member  controlv1.DeploymentPublisherIdentity
	Private ed25519.PrivateKey
	Server  string
	lock    io.Closer
	once    sync.Once
	err     error
}

func (*EnrolledIdentity) String() string   { return "enrolled publisher identity" }
func (*EnrolledIdentity) GoString() string { return "enrolled publisher identity" }

func (i *EnrolledIdentity) Close() error {
	i.once.Do(func() {
		clear(i.Private)
		i.err = i.lock.Close()
	})
	return i.err
}

// OpenEnrolledIdentity reuses a saved identity without redeeming its bootstrap
// key again. an ambiguous redemption keeps its durable pending signing key;
// neither network failure nor invalid state silently creates another identity.
func OpenEnrolledIdentity(ctx context.Context, files EnrollmentFiles, control EnrollmentControl, selection EnrollmentSelection, secret string) (_ *EnrolledIdentity, result error) {
	return OpenPublisherIdentity(ctx, files, func(string) (EnrollmentControl, error) { return control, nil }, selection, func(context.Context) (string, error) { return secret, nil })
}

// OpenPublisherIdentity resolves the control origin from the saved slot before
// asking for bootstrap authority. a pending record binds the exact key digest,
// but never stores the enrollment secret.
func OpenPublisherIdentity(ctx context.Context, files EnrollmentFiles, client func(string) (EnrollmentControl, error), selection EnrollmentSelection, bootstrap func(context.Context) (string, error)) (_ *EnrolledIdentity, result error) {
	validServer := func(server string) bool {
		canonical, err := naming.CanonicalControlURL(server)
		return err == nil && canonical == server
	}
	validScope := func(project, deployment string) bool {
		return project == "" && deployment == "" || naming.ValidProjectKey(project) && opaqueid.Valid(deployment, "dpl_")
	}
	if selection.ControlURL != "" && !validServer(selection.ControlURL) ||
		!validScope(selection.ProjectKey, selection.DeploymentID) || !naming.ValidServiceName(selection.Instance) ||
		files == nil || client == nil {
		return nil, ErrScope
	}
	lock, err := files.Lock(ctx, "enrollment-owner")
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			result = errors.Join(result, lock.Close())
		}
	}()
	data, found, err := files.Read(ctx, "identity.json", 8192)
	defer clear(data)
	if err != nil {
		return nil, err
	}
	var record enrollmentRecord
	loadBootstrap := func() (string, string, error) {
		if bootstrap == nil {
			return "", "", ErrScope
		}
		secret, err := bootstrap(ctx)
		if err != nil {
			return "", "", err
		}
		if err := context.Cause(ctx); err != nil {
			return "", "", err
		}
		id, key, found := strings.Cut(secret, ".")
		if len(secret) > 256 || !found || !opaqueid.Valid(id, opaqueid.PublisherEnrollmentPrefix) || key == "" || strings.Contains(key, ".") {
			return "", "", ErrScope
		}
		digest := sha256.Sum256([]byte(secret))
		return secret, base64.RawURLEncoding.EncodeToString(digest[:]), nil
	}
	var secret string
	if found {
		if json.Unmarshal(data, &record, json.RejectUnknownMembers(true)) != nil ||
			record.Version != 1 || record.Selection.Instance != selection.Instance ||
			!validServer(record.Selection.ControlURL) || selection.ControlURL != "" && record.Selection.ControlURL != selection.ControlURL ||
			!validScope(record.Selection.ProjectKey, record.Selection.DeploymentID) ||
			selection.ProjectKey != "" && (record.Selection.ProjectKey != selection.ProjectKey || record.Selection.DeploymentID != selection.DeploymentID) ||
			(record.Member == nil) != (record.Bootstrap != "") {
			return nil, ErrScope
		}
	} else {
		var digest string
		secret, digest, err = loadBootstrap()
		if err != nil {
			return nil, err
		}
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		defer clear(private)
		if selection.ControlURL == "" {
			selection.ControlURL = naming.DefaultControlURL
		}
		record = enrollmentRecord{Version: 1, Selection: selection, PrivateKey: base64.RawURLEncoding.EncodeToString(private), Bootstrap: digest}
		if err := writeEnrollmentRecord(ctx, files, record); err != nil {
			return nil, err
		}
	}
	private, err := base64.RawURLEncoding.Strict().DecodeString(record.PrivateKey)
	if err != nil || !validSigningKey(private) {
		clear(private)
		return nil, ErrScope
	}
	defer func() {
		if !retained {
			clear(private)
		}
	}()
	if record.Member == nil {
		digest, err := base64.RawURLEncoding.Strict().DecodeString(record.Bootstrap)
		if err != nil || len(digest) != sha256.Size {
			return nil, ErrScope
		}
	}
	server := record.Selection.ControlURL
	control, err := client(server)
	if err != nil {
		return nil, err
	}
	if control == nil {
		return nil, ErrScope
	}
	validMember := func(member controlv1.DeploymentPublisherIdentity) bool {
		return naming.ValidProjectKey(member.ProjectKey) && opaqueid.Valid(member.DeploymentId, "dpl_") &&
			(record.Selection.ProjectKey == "" || member.ProjectKey == record.Selection.ProjectKey && member.DeploymentId == record.Selection.DeploymentID) &&
			member.TeamId != "" && naming.ValidServiceName(member.DeploymentName) && member.DeploymentName != "local" &&
			opaqueid.Valid(member.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) &&
			opaqueid.Valid(member.KeyId, opaqueid.PublisherIdentityKeyPrefix)
	}
	if record.Member == nil {
		if secret == "" {
			var digest string
			secret, digest, err = loadBootstrap()
			if err != nil {
				return nil, err
			}
			if digest != record.Bootstrap {
				return nil, ErrScope
			}
		}
		member, err := control.RedeemScopedDeploymentPublisherEnrollment(ctx, secret, ed25519.PrivateKey(private).Public().(ed25519.PublicKey), record.Selection.DeploymentID, record.Selection.ProjectKey)
		if err != nil {
			return nil, err
		}
		if !validMember(member) {
			return nil, ErrScope
		}
		record.Member, record.Bootstrap = &member, ""
		record.Selection.ProjectKey, record.Selection.DeploymentID = member.ProjectKey, member.DeploymentId
		// persist a committed result before verifying it. a lost verification
		// reply can be retried without using bootstrap again.
		if err := writeEnrollmentRecord(ctx, files, record); err != nil {
			return nil, err
		}
	}
	member := *record.Member
	if !validMember(member) || record.Selection.ProjectKey == "" {
		return nil, ErrScope
	}
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.DeploymentId, server+"/v1/publisher/deployments/verify", private, time.Now())
	if err != nil {
		return nil, err
	}
	verified, err := control.VerifyDeploymentIdentity(ctx, controlv1.DeploymentPublisherLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, DeploymentId: member.DeploymentId, Assertion: assertion})
	if err != nil {
		return nil, err
	}
	current := verified.Member
	previous := member
	previous.DeploymentName = current.DeploymentName
	if previous != current || !naming.ValidServiceName(current.DeploymentName) || current.DeploymentName == "local" {
		return nil, ErrScope
	}
	if current != member {
		record.Member = &current
		if err := writeEnrollmentRecord(ctx, files, record); err != nil {
			return nil, err
		}
	}
	retained = true
	return &EnrolledIdentity{Member: current, Private: private, Server: server, lock: lock}, nil
}

func writeEnrollmentRecord(ctx context.Context, files EnrollmentFiles, record enrollmentRecord) error {
	data, err := json.Marshal(record)
	defer clear(data)
	if err != nil {
		return err
	}
	return files.Write(ctx, "identity.json", data)
}
