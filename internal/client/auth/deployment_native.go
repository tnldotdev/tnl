//go:build !js

package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// setup keeps the original key in protected client state before the HTTP call.
// a lost reply retries the same registration; neither retries nor exports rotate it.
func RegisterDeploymentCredential(ctx context.Context, store *clientstate.Store, control *clientcontrol.Client, server, teamID, teamName, project, requestKey string, request controlv1.RegisterDeploymentCredentialRequest) (DeploymentCredential, error) {
	if store == nil || control == nil || requestKey == "" || len(requestKey) > 128 {
		return DeploymentCredential{}, ErrDeploymentCredential
	}
	request.PublicKey = ""
	intent, err := json.Marshal([]any{teamID, project, requestKey, request})
	if err != nil {
		return DeploymentCredential{}, err
	}
	digest := sha256.Sum256(intent)
	selection := "deployment-credential:" + hex.EncodeToString(digest[:])
	lock, err := store.LockPublisherSigningIdentity(ctx, selection)
	if err != nil {
		return DeploymentCredential{}, err
	}
	defer lock.Close()
	pending, found, err := store.PendingPublisherEnrollmentForSelection(ctx, "project", selection)
	if err != nil {
		return DeploymentCredential{}, err
	}
	if !found {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return DeploymentCredential{}, err
		}
		pending = clientstate.PendingPublisherEnrollment{EnrollmentID: selection, SelectionKind: "project", SelectionKey: selection, PublicKey: public, SigningKey: private, ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
		if err := store.SavePendingPublisherEnrollment(ctx, pending); err != nil {
			return DeploymentCredential{}, err
		}
	}
	request.PublicKey = base64.RawURLEncoding.EncodeToString(pending.PublicKey)
	approval, err := control.RegisterDeploymentCredential(ctx, teamID, project, requestKey, request)
	if err != nil {
		return DeploymentCredential{}, err
	}
	if approval.TeamId != teamID || approval.ProjectKey != project {
		return DeploymentCredential{}, ErrDeploymentCredential
	}
	result := DeploymentCredential{Version: 1, ControlURL: server, Team: teamName, Approval: approval, PrivateKey: base64.RawURLEncoding.EncodeToString(pending.SigningKey)}
	if _, err := result.key(); err != nil {
		return DeploymentCredential{}, err
	}
	return result, nil
}
