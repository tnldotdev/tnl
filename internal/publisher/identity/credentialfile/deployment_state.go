package credentialfile

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	json "encoding/json/v2"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentReference struct {
	Member   controlv1.DeploymentPublisherIdentity `json:"member"`
	Instance string                                `json:"instance"`
}

type deploymentPin struct {
	Version   int                 `json:"version"`
	Reference deploymentReference `json:"reference"`
}

func deploymentStateName(ref deploymentReference) string {
	digest := sha256.Sum256([]byte(DeploymentSelection(ref.Member.ProjectKey, ref.Member.DeploymentId, ref.Instance) + ":" + ref.Member.PublisherIdentityId))
	return "deployment-" + hex.EncodeToString(digest[:]) + ".json"
}

func deploymentPinName(project, deployment, instance string) string {
	digest := sha256.Sum256([]byte(DeploymentSelection(project, deployment, instance)))
	return "deployment-pin-v1-" + hex.EncodeToString(digest[:]) + ".json"
}

func readDeploymentPin(directory *clientstate.PrivateDirectory, project, deployment, instance string) (deploymentReference, bool, error) {
	data, found, err := directory.Read(deploymentPinName(project, deployment, instance), maxDeploymentIdentityBytes)
	if err != nil || !found {
		return deploymentReference{}, found, err
	}
	var pin deploymentPin
	if json.Unmarshal(data, &pin, json.RejectUnknownMembers(true)) != nil || pin.Version != 1 || pin.Reference.Member.ProjectKey != project || pin.Reference.Member.DeploymentId != deployment || pin.Reference.Instance != instance {
		return deploymentReference{}, true, clientstate.ErrPublisherStateConflict
	}
	return pin.Reference, true, nil
}

func pinnedDeployment(directory *clientstate.PrivateDirectory, server, project, deployment, instance string) (DeploymentFile, bool, error) {
	ref, found, err := readDeploymentPin(directory, project, deployment, instance)
	if err != nil || !found {
		return DeploymentFile{}, found, err
	}
	value, err := readDeploymentReference(directory, server, ref)
	return value, true, err
}

func deploymentStateDirectory(profile *clientstate.Store, server string) (*clientstate.PrivateDirectory, error) {
	root, err := clientstate.OpenPrivateDirectory(profile.IdentityDirectory())
	if err != nil {
		return nil, err
	}
	return root.Scoped(server)
}

func deploymentReferences(directory *clientstate.PrivateDirectory) ([]deploymentReference, error) {
	data, found, err := directory.Read("deployments.json", 262144)
	if err != nil || !found {
		return nil, err
	}
	var refs []deploymentReference
	if json.Unmarshal(data, &refs, json.RejectUnknownMembers(true)) != nil || refs == nil || len(refs) > 256 {
		return nil, ErrInvalid
	}
	for _, ref := range refs {
		pin, found, err := readDeploymentPin(directory, ref.Member.ProjectKey, ref.Member.DeploymentId, ref.Instance)
		if err != nil {
			return nil, err
		}
		if !found || !SameDeploymentIdentity(pin.Member, ref.Member) {
			return nil, clientstate.ErrPublisherStateConflict
		}
	}
	return refs, nil
}

func readDeploymentReference(directory *clientstate.PrivateDirectory, server string, ref deploymentReference) (DeploymentFile, error) {
	data, found, err := directory.Read(deploymentStateName(ref), maxDeploymentIdentityBytes)
	defer clear(data)
	if err != nil {
		return DeploymentFile{}, err
	}
	if !found {
		return DeploymentFile{}, clientstate.ErrPublisherStateConflict
	}
	value, err := ParseDeployment(data)
	if err != nil {
		return DeploymentFile{}, err
	}
	if value.ControlURL != server || value.Instance != ref.Instance || !SameDeploymentIdentity(value.Member, ref.Member) {
		return DeploymentFile{}, clientstate.ErrPublisherStateConflict
	}
	return value, nil
}

// SavedDeployment reads a pinned immutable deployment ID, never a selector-derived secret
// filename. the public catalog also survives loss of the runtime database.
func SavedDeployment(profile *clientstate.Store, server, project, deploymentID, instance string) (DeploymentFile, bool, error) {
	directory, err := deploymentStateDirectory(profile, server)
	if err != nil {
		return DeploymentFile{}, false, err
	}
	if _, err := deploymentReferences(directory); err != nil {
		return DeploymentFile{}, false, err
	}
	return pinnedDeployment(directory, server, project, deploymentID, instance)
}

// ResolveSavedDeployment refreshes public identity references through control. no
// filename or exported friendly name is used to select signing authority.
func ResolveSavedDeployment(ctx context.Context, profile *clientstate.Store, client DeploymentVerifier, server, project, selector, instance string) (DeploymentFile, bool, error) {
	directory, err := deploymentStateDirectory(profile, server)
	if err != nil {
		return DeploymentFile{}, false, err
	}
	refs, err := deploymentReferences(directory)
	if err != nil {
		return DeploymentFile{}, false, err
	}
	var selected *deploymentReference
	for _, ref := range refs {
		if ref.Member.ProjectKey != project || ref.Instance != instance {
			continue
		}
		if opaqueid.Valid(selector, "dpl_") && selector != ref.Member.DeploymentId {
			continue
		}
		// a task's replica-private directory pins one member. an ambiguous
		// directory needs an explicit portable identity, never a secret scan.
		if selected != nil {
			return DeploymentFile{}, false, clientstate.ErrPublisherStateConflict
		}
		selected = &ref
	}
	if selected == nil {
		return DeploymentFile{}, false, nil
	}
	value, err := readDeploymentReference(directory, server, *selected)
	if err != nil {
		return DeploymentFile{}, true, err
	}
	value, err = ResolveDeployment(ctx, client, value, server, project, selector, instance)
	return value, true, err
}

// RetainDeployment pins one replica and refreshes only its current display name.
func RetainDeployment(ctx context.Context, profile *clientstate.Store, value DeploymentFile) error {
	private, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance)
	if err != nil {
		return err
	}
	directory, err := deploymentStateDirectory(profile, value.ControlURL)
	if err != nil {
		return err
	}
	lock, err := directory.Lock(ctx, "deployments.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	// a retired catalog entry keeps a selection pin and its original private
	// file. reactivation can reuse that authority, never silently replace it.
	pinned, exists, err := pinnedDeployment(directory, value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentId, value.Instance)
	if err != nil {
		return err
	}
	if exists && (!SameDeploymentIdentity(pinned.Member, value.Member) || subtle.ConstantTimeCompare([]byte(pinned.PrivateKey), []byte(value.PrivateKey)) != 1) {
		return clientstate.ErrPublisherStateConflict
	}
	refs, err := deploymentReferences(directory)
	if err != nil {
		return err
	}
	ref := deploymentReference{Member: value.Member, Instance: value.Instance}
	found := false
	for i, previous := range refs {
		if previous.Member.ProjectKey != value.Member.ProjectKey || previous.Member.DeploymentId != value.Member.DeploymentId || previous.Instance != value.Instance {
			continue
		}
		saved, err := readDeploymentReference(directory, value.ControlURL, previous)
		if err != nil {
			return err
		}
		key, err := saved.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance)
		if err != nil || !SameDeploymentIdentity(saved.Member, value.Member) || subtle.ConstantTimeCompare(key, private) != 1 {
			return clientstate.ErrPublisherStateConflict
		}
		refs[i], found = ref, true
	}
	if !found {
		if len(refs) >= 256 {
			return ErrInvalid
		}
		data, fileExists, err := directory.Read(deploymentStateName(ref), maxDeploymentIdentityBytes)
		defer clear(data)
		if err != nil {
			return err
		}
		if fileExists && !exists {
			return clientstate.ErrPublisherStateConflict
		}
		if fileExists {
			saved, err := ParseDeployment(data)
			if err != nil || saved.ControlURL != value.ControlURL || saved.Instance != value.Instance || !SameDeploymentIdentity(saved.Member, value.Member) || subtle.ConstantTimeCompare([]byte(saved.PrivateKey), []byte(value.PrivateKey)) != 1 {
				return clientstate.ErrPublisherStateConflict
			}
		}
		refs = append(refs, ref)
	}
	data, err := json.Marshal(value)
	defer clear(data)
	if err != nil {
		return ErrInvalid
	}
	if err := directory.Write(deploymentStateName(ref), data); err != nil {
		return err
	}
	pin, err := json.Marshal(deploymentPin{Version: 1, Reference: ref})
	if err != nil {
		return err
	}
	if err := directory.Write(deploymentPinName(value.Member.ProjectKey, value.Member.DeploymentId, value.Instance), pin); err != nil {
		return err
	}
	catalog, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	return directory.Write("deployments.json", catalog)
}

// RetireDeployment explicitly removes a joined replica from active name discovery.
// private identity/certificate files and the immutable selection pin remain.
// this reclaims catalog capacity without revoking or deleting issued authority.
func RetireDeployment(ctx context.Context, profile *clientstate.Store, value DeploymentFile) error {
	if _, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance); err != nil {
		return err
	}
	directory, err := deploymentStateDirectory(profile, value.ControlURL)
	if err != nil {
		return err
	}
	lock, err := directory.Lock(ctx, "deployments.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	refs, err := deploymentReferences(directory)
	if err != nil {
		return err
	}
	for i, ref := range refs {
		if ref.Member.ProjectKey != value.Member.ProjectKey || ref.Member.DeploymentId != value.Member.DeploymentId || ref.Instance != value.Instance {
			continue
		}
		saved, err := readDeploymentReference(directory, value.ControlURL, ref)
		if err != nil {
			return err
		}
		if !SameDeploymentIdentity(saved.Member, value.Member) || subtle.ConstantTimeCompare([]byte(saved.PrivateKey), []byte(value.PrivateKey)) != 1 {
			return clientstate.ErrPublisherStateConflict
		}
		refs = append(refs[:i], refs[i+1:]...)
		data, err := json.Marshal(refs)
		if err != nil {
			return err
		}
		return directory.Write("deployments.json", data)
	}
	return nil
}
