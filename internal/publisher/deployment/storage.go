package deployment

import (
	"bytes"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
)

var ErrStorageTransition = errors.New("publisher storage binding is immutable; preserve the deployed storage and identity parameters")

// ValidateStorageTransition compares fully resolved deployment parameters, not
// UsePreviousValue placeholders. retain policies preserve old data but cannot
// prevent CloudFormation from mounting a newly replaced empty filesystem.
func ValidateStorageTransition(previous, next Parameters) error {
	if len(previous) == 0 || len(next) == 0 {
		return ErrStorageTransition
	}
	immutable := []string{ControlURLParameter, ProjectKeyParameter, TeamIDParameter, PublisherGroupIDParameter, DeploymentIDParameter, "VpcId", "ResourcePrefix", "EFSSecurityGroupName", "PublisherSecurityGroupName", "ExistingPublisherSecurityGroupId", "FileSystemKMSKeyArn", "MountSubnetCount"}
	for i := 1; i <= 6; i++ {
		immutable = append(immutable, fmt.Sprintf("MountSubnet%d", i))
	}
	for _, name := range immutable {
		// both snapshots must contain defaults explicitly. an omitted setting is
		// not evidence that an existing deployment used the current default.
		before, knownBefore := previous[name]
		after, knownAfter := next[name]
		if !knownBefore || !knownAfter || before != after || before == "REQUIRED" {
			return fmt.Errorf("%w: %s", ErrStorageTransition, name)
		}
	}
	for i := 1; i <= 8; i++ {
		prefix := fmt.Sprintf("Replica%d", i)
		if _, existed := previous[prefix+"PublisherIdentityID"]; !existed {
			continue
		}
		// scale-down retains authority and storage. re-adding a retired slot
		// must be checked against its last deployed parameter snapshot as well.
		if _, survives := next[prefix+"PublisherIdentityID"]; !survives {
			continue
		}
		for _, suffix := range []string{"PublisherIdentityID", "Instance", "IdentitySecretArn"} {
			name := prefix + suffix
			if previous[name] == "" || previous[name] == "REQUIRED" || previous[name] != next[name] {
				return fmt.Errorf("%w: %s", ErrStorageTransition, name)
			}
		}
	}
	return nil
}

// ReadParameters accepts the concrete AWS parameter-file form, without SDK
// credentials or cloud lookups. unknown members and duplicate keys are rejected.
func ReadParameters(path string) (Parameters, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	var values []Parameter
	if len(data) > MaxManifestBytes || json.Unmarshal(data, &values, json.RejectUnknownMembers(true)) != nil || len(values) == 0 || len(values) > 200 {
		return nil, ErrStorageTransition
	}
	result := Parameters{}
	for _, value := range values {
		if value.ParameterKey == "" || bytes.ContainsAny([]byte(value.ParameterValue), "\x00\r\n") {
			return nil, ErrStorageTransition
		}
		if _, exists := result[value.ParameterKey]; exists {
			return nil, ErrStorageTransition
		}
		result[value.ParameterKey] = value.ParameterValue
	}
	return result, nil
}

// StoragePolicy must be supplied as CloudFormation's stack policy at creation
// and preserved on update. it blocks replacement of storage and NFS dependencies;
// deleting the stack still uses the template's Retain policies.
func StoragePolicy() []byte {
	data, _ := encode(object{"Statement": []any{
		object{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
		object{"Effect": "Deny", "Action": "Update:Replace", "Principal": "*", "Resource": "*", "Condition": object{"StringEquals": object{"ResourceType": []string{"AWS::EFS::FileSystem", "AWS::EFS::AccessPoint", "AWS::EFS::MountTarget", "AWS::EC2::SecurityGroup"}}}},
		object{"Effect": "Deny", "Action": "Update:Delete", "Principal": "*", "Resource": "LogicalResourceId/IdentityFileSystem"},
	}})
	return data
}
