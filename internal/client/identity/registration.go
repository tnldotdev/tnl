// package identity owns application setup and exact signing-identity selection.
// it composes protected client state and control contracts, never publisher or
// connector runtimes. neither runtime can own setup for the other's capabilities.
package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrRegistration = failure.Wrap("register application", failure.PublisherSelectionInvalid, errors.New("select a name, ownership and exact application grants"))
var ErrRegistrationConflict = failure.Wrap("resume application registration", failure.ServerConflict, errors.New("application setup already captured another request for this output file"))
var ErrRegistrationExpired = failure.Wrap("export application credential", failure.PublisherGrantMismatch, errors.New("the captured application grants have expired; register a new application instead of renewing this retry"))

type Registrar interface {
	ControlURL() string
	RegisterApplication(context.Context, string, controlv1.RegisterApplicationRequest) (controlv1.RegisteredApplication, error)
}

type RegistrationSpec struct {
	TeamID    string                                        `json:"team_id"`
	Name      string                                        `json:"name"`
	Ownership controlv1.RegisterApplicationRequestOwnership `json:"ownership"`
	Grants    []controlv1.ApplicationGrantInput             `json:"grants"`
	ExpiresIn time.Duration                                 `json:"expires_in_ns"`
}

type registrationJournal struct {
	Version        int                                  `json:"version"`
	Spec           RegistrationSpec                     `json:"spec"`
	Request        controlv1.RegisterApplicationRequest `json:"request"`
	IdempotencyKey string                               `json:"idempotency_key"`
	PrivateKey     string                               `json:"private_key"`
	Result         *controlv1.RegisteredApplication     `json:"result,omitempty"`
}

func (registrationJournal) String() string   { return "protected application registration" }
func (registrationJournal) GoString() string { return "protected application registration" }

func (s RegistrationSpec) Valid() bool {
	if !naming.ValidServiceName(s.Name) || s.TeamID == "" || !s.Ownership.Valid() || len(s.Grants) < 1 || len(s.Grants) > 64 || s.ExpiresIn < 0 {
		return false
	}
	bindings := map[string]bool{}
	for _, grant := range s.Grants {
		if !grant.Operation.Valid() || grant.ExpiresAt != nil {
			return false
		}
		selected := 0
		resource := ""
		for _, entry := range []struct {
			id     *string
			prefix string
		}{{grant.PublicUrlId, opaqueid.PublicURLPrefix}, {grant.ServiceId, opaqueid.ServicePrefix}, {grant.DomainId, opaqueid.DomainPrefix}} {
			if entry.id == nil {
				continue
			}
			if !opaqueid.Valid(*entry.id, entry.prefix) {
				return false
			}
			selected++
			resource = *entry.id
		}
		binding := string(grant.Operation) + ":" + resource
		if selected != 1 || (grant.Operation == controlv1.ApplicationAllocate) != (grant.DomainId != nil) || bindings[binding] {
			return false
		}
		bindings[binding] = true
	}
	return true
}

// RegisterApplication persists one private key and the exact request before its
// first network effect. a lost reply reuses both; a captured reply is durable
// before the no-clobber file export. retries never enroll another signing key.
func RegisterApplication(ctx context.Context, store *clientstate.Store, client Registrar, output string, spec RegistrationSpec) (controlv1.RegisteredApplication, error) {
	if store == nil || client == nil || !spec.Valid() || output == "" {
		return controlv1.RegisteredApplication{}, ErrRegistration
	}
	server, err := naming.CanonicalControlURL(client.ControlURL())
	if err != nil || server != client.ControlURL() {
		return controlv1.RegisteredApplication{}, ErrRegistration
	}
	absolute, err := filepath.Abs(output)
	if err != nil {
		return controlv1.RegisteredApplication{}, ErrRegistration
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return controlv1.RegisteredApplication{}, credentialfile.ErrInvalid
	}
	output = filepath.Join(parent, filepath.Base(absolute))
	digest := sha256.Sum256([]byte(server + "\x00" + output))
	binding := "application:" + hex.EncodeToString(digest[:])
	lock, err := store.LockPublisherSigningIdentity(ctx, binding)
	if err != nil {
		return controlv1.RegisteredApplication{}, err
	}
	defer lock.Close()
	data, revision, err := store.PublisherProvision(ctx, "application", binding)
	if err != nil {
		return controlv1.RegisteredApplication{}, err
	}
	var pending registrationJournal
	if revision == 0 {
		if _, err := os.Lstat(output); err == nil {
			return controlv1.RegisteredApplication{}, credentialfile.ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return controlv1.RegisteredApplication{}, credentialfile.ErrInvalid
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return controlv1.RegisteredApplication{}, err
		}
		idempotency, err := opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			return controlv1.RegisteredApplication{}, err
		}
		request := controlv1.RegisterApplicationRequest{TeamId: spec.TeamID, Name: spec.Name, Ownership: spec.Ownership, PublicKey: base64.RawURLEncoding.EncodeToString(public), Grants: append([]controlv1.ApplicationGrantInput{}, spec.Grants...)}
		if spec.ExpiresIn > 0 {
			expires := time.Now().Add(spec.ExpiresIn).UTC().Truncate(time.Second)
			for index := range request.Grants {
				request.Grants[index].ExpiresAt = &expires
			}
		}
		pending = registrationJournal{Version: 1, Spec: spec, Request: request, IdempotencyKey: idempotency, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
		clear(private)
		if err := saveRegistration(ctx, store, binding, revision, pending); err != nil {
			return controlv1.RegisteredApplication{}, err
		}
		revision++
	} else if json.Unmarshal(data, &pending, json.RejectUnknownMembers(true), jsonv1.FormatDurationAsNano(true)) != nil || pending.Version != 1 || !reflect.DeepEqual(pending.Spec, spec) {
		return controlv1.RegisteredApplication{}, ErrRegistrationConflict
	}
	clear(data)
	private, err := base64.RawURLEncoding.Strict().DecodeString(pending.PrivateKey)
	if err != nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])) || base64.RawURLEncoding.EncodeToString(private[32:]) != pending.Request.PublicKey || !opaqueid.Valid(pending.IdempotencyKey, opaqueid.IdempotencyPrefix) {
		return controlv1.RegisteredApplication{}, ErrRegistrationConflict
	}
	defer clear(private)
	if pending.Result == nil {
		result, err := client.RegisterApplication(ctx, pending.IdempotencyKey, pending.Request)
		if err != nil {
			return controlv1.RegisteredApplication{}, err
		}
		if !registrationMatches(pending.Request, result) {
			return controlv1.RegisteredApplication{}, failure.Wrap("read application registration", failure.ServerResponseInvalid, errors.New("control returned another application or grant"))
		}
		if _, err := credentialfile.NewApplication(server, result, private); err != nil {
			return controlv1.RegisteredApplication{}, failure.Wrap("read application registration", failure.ServerResponseInvalid, err)
		}
		pending.Result = &result
		if err := saveRegistration(ctx, store, binding, revision, pending); err != nil {
			return controlv1.RegisteredApplication{}, err
		}
	}
	if !registrationMatches(pending.Request, *pending.Result) {
		return controlv1.RegisteredApplication{}, ErrRegistrationConflict
	}
	file, err := credentialfile.NewApplication(server, *pending.Result, private)
	if err != nil {
		return controlv1.RegisteredApplication{}, err
	}
	for _, grant := range file.Grants {
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(time.Now()) {
			return controlv1.RegisteredApplication{}, ErrRegistrationExpired
		}
	}
	if _, err := os.Lstat(output); err == nil {
		existing, err := credentialfile.Read(output)
		if err != nil {
			return controlv1.RegisteredApplication{}, err
		}
		if !reflect.DeepEqual(existing, file) {
			return controlv1.RegisteredApplication{}, credentialfile.ErrExists
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return controlv1.RegisteredApplication{}, credentialfile.ErrInvalid
	} else if err := credentialfile.Write(output, file); err != nil {
		return controlv1.RegisteredApplication{}, err
	}
	return *pending.Result, nil
}

func saveRegistration(ctx context.Context, store *clientstate.Store, binding string, revision int64, value registrationJournal) error {
	data, err := json.Marshal(value, jsonv1.FormatDurationAsNano(true))
	if err != nil {
		return err
	}
	defer clear(data)
	return store.AppendPublisherProvision(ctx, "application", binding, revision, data)
}

func registrationMatches(request controlv1.RegisterApplicationRequest, result controlv1.RegisteredApplication) bool {
	if result.TeamId != request.TeamId || result.Name != request.Name || string(result.Ownership) != string(request.Ownership) || len(result.Grants) != len(request.Grants) {
		return false
	}
	for index, grant := range result.Grants {
		input := request.Grants[index]
		if grant.Operation != input.Operation || !reflect.DeepEqual(grant.PublicUrlId, input.PublicUrlId) || !reflect.DeepEqual(grant.ServiceId, input.ServiceId) || !reflect.DeepEqual(grant.DomainId, input.DomainId) || !reflect.DeepEqual(grant.ExpiresAt, input.ExpiresAt) || grant.RevokedAt != nil {
			return false
		}
	}
	return true
}
