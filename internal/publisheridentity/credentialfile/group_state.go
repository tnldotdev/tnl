package credentialfile

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	json "encoding/json/v2"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type groupReference struct {
	Member   controlv1.PublisherGroupMember `json:"member"`
	Instance string                         `json:"instance"`
}

func groupStateName(ref groupReference) string {
	digest := sha256.Sum256([]byte(GroupSelection(ref.Member.ProjectKey, ref.Member.GroupId, ref.Instance) + ":" + ref.Member.PublisherIdentityId))
	return "group-" + hex.EncodeToString(digest[:]) + ".json"
}

func groupStateDirectory(profile *clientstate.Store, server string) (*clientstate.PrivateDirectory, error) {
	root, err := clientstate.OpenPrivateDirectory(profile.IdentityDirectory())
	if err != nil {
		return nil, err
	}
	return root.Scoped(server)
}

func groupReferences(directory *clientstate.PrivateDirectory) ([]groupReference, error) {
	data, found, err := directory.Read("groups.json", 262144)
	if err != nil || !found {
		return nil, err
	}
	var refs []groupReference
	if json.Unmarshal(data, &refs, json.RejectUnknownMembers(true)) != nil || len(refs) > 256 {
		return nil, ErrInvalid
	}
	return refs, nil
}

func readGroupReference(directory *clientstate.PrivateDirectory, server string, ref groupReference) (GroupFile, error) {
	data, found, err := directory.Read(groupStateName(ref), maxGroupIdentityBytes)
	defer clear(data)
	if err != nil {
		return GroupFile{}, err
	}
	if !found {
		return GroupFile{}, clientstate.ErrPublisherStateConflict
	}
	value, err := ParseGroup(data)
	if err != nil {
		return GroupFile{}, err
	}
	if value.ControlURL != server || value.Instance != ref.Instance || !SameGroupIdentity(value.Member, ref.Member) {
		return GroupFile{}, clientstate.ErrPublisherStateConflict
	}
	return value, nil
}

// SavedGroup reads a pinned immutable group ID, never a selector-derived secret
// filename. the public catalog also survives loss of the runtime database.
func SavedGroup(profile *clientstate.Store, server, project, groupID, instance string) (GroupFile, bool, error) {
	directory, err := groupStateDirectory(profile, server)
	if err != nil {
		return GroupFile{}, false, err
	}
	refs, err := groupReferences(directory)
	if err != nil {
		return GroupFile{}, false, err
	}
	for _, ref := range refs {
		if ref.Member.ProjectKey == project && ref.Member.GroupId == groupID && ref.Instance == instance {
			value, err := readGroupReference(directory, server, ref)
			return value, true, err
		}
	}
	return GroupFile{}, false, nil
}

// ResolveSavedGroup refreshes public identity references through control. no
// filename or exported friendly name is used to select signing authority.
func ResolveSavedGroup(ctx context.Context, profile *clientstate.Store, client GroupVerifier, server, project, selector, instance string) (GroupFile, bool, error) {
	directory, err := groupStateDirectory(profile, server)
	if err != nil {
		return GroupFile{}, false, err
	}
	refs, err := groupReferences(directory)
	if err != nil {
		return GroupFile{}, false, err
	}
	var selected *groupReference
	for _, ref := range refs {
		if ref.Member.ProjectKey != project || ref.Instance != instance {
			continue
		}
		// a task's replica-private directory pins one member. an ambiguous
		// directory needs an explicit portable identity, never a secret scan.
		if selected != nil {
			return GroupFile{}, false, clientstate.ErrPublisherStateConflict
		}
		selected = &ref
	}
	if selected == nil {
		return GroupFile{}, false, nil
	}
	value, err := readGroupReference(directory, server, *selected)
	if err != nil {
		return GroupFile{}, true, err
	}
	value, err = ResolveGroup(ctx, client, value, server, project, selector, instance)
	return value, true, err
}

// RetainGroup pins one replica and refreshes only its current display name.
func RetainGroup(ctx context.Context, profile *clientstate.Store, value GroupFile) error {
	private, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.GroupName, value.Instance)
	if err != nil {
		return err
	}
	directory, err := groupStateDirectory(profile, value.ControlURL)
	if err != nil {
		return err
	}
	lock, err := directory.Lock(ctx, "groups.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	refs, err := groupReferences(directory)
	if err != nil {
		return err
	}
	ref := groupReference{Member: value.Member, Instance: value.Instance}
	found := false
	for i, previous := range refs {
		if previous.Member.ProjectKey != value.Member.ProjectKey || previous.Member.GroupId != value.Member.GroupId || previous.Instance != value.Instance {
			continue
		}
		saved, err := readGroupReference(directory, value.ControlURL, previous)
		if err != nil {
			return err
		}
		key, err := saved.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.GroupName, value.Instance)
		if err != nil || !SameGroupIdentity(saved.Member, value.Member) || subtle.ConstantTimeCompare(key, private) != 1 {
			return clientstate.ErrPublisherStateConflict
		}
		refs[i], found = ref, true
	}
	if !found {
		if len(refs) >= 256 {
			return ErrInvalid
		}
		// recover a file synced before its catalog update without ever replacing
		// that pinned key after an interrupted first retention.
		data, exists, err := directory.Read(groupStateName(ref), maxGroupIdentityBytes)
		defer clear(data)
		if err != nil {
			return err
		}
		if exists {
			saved, err := ParseGroup(data)
			if err != nil || saved.ControlURL != value.ControlURL || saved.Instance != value.Instance || !SameGroupIdentity(saved.Member, value.Member) || subtle.ConstantTimeCompare([]byte(saved.PrivateKey), []byte(value.PrivateKey)) != 1 {
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
	if err := directory.Write(groupStateName(ref), data); err != nil {
		return err
	}
	catalog, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	return directory.Write("groups.json", catalog)
}
