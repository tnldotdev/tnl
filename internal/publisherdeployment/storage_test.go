package publisherdeployment

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func storageParameters(t *testing.T) Parameters {
	t.Helper()
	b := testBundle(t, 2)
	var parameters []Parameter
	if err := json.Unmarshal(b.Files[b.Manifest.Publishers[0].ParametersExamplePath], &parameters); err != nil {
		t.Fatal(err)
	}
	result := Parameters{}
	for _, p := range parameters {
		value := p.ParameterValue
		if value == "REQUIRED" {
			value = "fixture-" + p.ParameterKey
		}
		result[p.ParameterKey] = value
	}
	return result
}

func TestStorageTransitionRejectsChangedKMSAndIdentityButAllowsTaskUpdates(t *testing.T) {
	previous := storageParameters(t)
	previous["FileSystemKMSKeyArn"] = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
	for _, name := range []string{"FileSystemKMSKeyArn", "MountSubnet1", "MountSubnetCount", "DeploymentID", "VpcId", "Replica1PublisherIdentityID", "Replica1Instance", "Replica1IdentitySecretArn"} {
		t.Run(name, func(t *testing.T) {
			next := maps.Clone(previous)
			next[name] += "-changed"
			if name == "FileSystemKMSKeyArn" {
				next[name] = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
			}
			if err := ValidateStorageTransition(previous, next); !errors.Is(err, ErrStorageTransition) {
				t.Fatal("unsafe storage transition accepted", err)
			}
		})
	}
	next := maps.Clone(previous)
	for _, name := range []string{"PublisherImage", "TaskCPU", "TaskMemory", "Group", "Replica1IdentitySecretVersion", "Replica1DesiredCount"} {
		next[name] += "-changed"
	}
	if err := ValidateStorageTransition(previous, next); err != nil {
		t.Fatal("ordinary runtime update changed storage binding", err)
	}
	delete(next, "FileSystemKMSKeyArn")
	if err := ValidateStorageTransition(previous, next); !errors.Is(err, ErrStorageTransition) {
		t.Fatal("omitted defaults treated as resolved previous values", err)
	}
}

func TestStoragePolicyProtectsActualTemplateReplacementBoundaries(t *testing.T) {
	b := testBundle(t, 2)
	p := b.Manifest.Publishers[0]
	if p.StoragePolicyPath == "" || digest(b.Files[p.StoragePolicyPath]) != p.StoragePolicySHA256 {
		t.Fatal("storage policy is not a hashed owned artifact")
	}
	var policy struct {
		Statement []struct {
			Effect    string
			Action    any
			Resource  string
			Condition struct {
				StringEquals struct{ ResourceType []string }
			}
		}
	}
	if err := json.Unmarshal(b.Files[p.StoragePolicyPath], &policy); err != nil {
		t.Fatal(err)
	}
	protected := map[string]bool{}
	for _, statement := range policy.Statement {
		if statement.Effect != "Deny" {
			continue
		}
		if statement.Action == "Update:Replace" {
			for _, kind := range statement.Condition.StringEquals.ResourceType {
				protected[kind] = true
			}
		}
	}
	for _, kind := range []string{"AWS::EFS::FileSystem", "AWS::EFS::AccessPoint", "AWS::EFS::MountTarget", "AWS::EC2::SecurityGroup"} {
		if !protected[kind] {
			t.Fatal("unprotected storage dependency", kind)
		}
	}
}

func TestStorageParameterFilesAreConcreteAndReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parameters.json")
	for _, invalid := range []string{`null`, `[]`, `[{"ParameterKey":"x","UsePreviousValue":true}]`, `[{"ParameterKey":"x","ParameterValue":"a"},{"ParameterKey":"x","ParameterValue":"b"}]`} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadParameters(path); err == nil {
			t.Fatal("ambiguous parameter file accepted")
		}
	}
	data, _ := json.Marshal(storageParameters(t).CloudFormation())
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadParameters(path)
	if err != nil || ValidateStorageTransition(got, got) != nil {
		t.Fatal("concrete file rejected", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("offline check rewrote deployment input")
	}
}
