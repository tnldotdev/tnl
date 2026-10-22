package awsbootstrap

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherprovision "github.com/tnldotdev/tnl/internal/publisher/setup"
)

type Request struct {
	Binding Binding
	Group   string
	Secret  Secret
}

// Reference is the only output of preparation. the private payload stays inside
// protected client state and Secrets Manager, never a deployment artifact.
type Reference struct {
	Binding             Binding `json:"binding"`
	Instance            string  `json:"instance"`
	PublisherIdentityID string  `json:"publisher_identity_id"`
	SecretARN           string  `json:"secret_arn"`
	SecretVersion       string  `json:"secret_version"`
	Ownership           string  `json:"ownership"`
}

type Preparer struct {
	Store     *clientstate.Store
	Secrets   Secrets
	Control   publisherprovision.Control
	Client    publisherprovision.Client
	Receipts  *clientstate.PrivateDirectory
	afterSave func(string) error
}

type operation struct {
	Binding     Binding
	Secret      Secret
	Stage       string
	CreateToken string
	ValueToken  string
	Proof       string
	ARN         string
	Identity    *credentialfile.GroupFile
}

func (operation) String() string   { return "protected AWS bootstrap operation" }
func (operation) GoString() string { return "protected AWS bootstrap operation" }

func randomToken() (string, error) {
	var data [32]byte
	_, err := rand.Read(data[:])
	return hex.EncodeToString(data[:]), err
}

func scopeOf(r Request) publisherprovision.Scope {
	b := r.Binding
	return publisherprovision.Scope{Server: b.ControlOrigin, Team: b.TeamID, Project: b.ProjectKey, GroupID: b.GroupID, Group: r.Group, Instance: b.Instance()}
}

func conflict(reason failure.Reason) error {
	return failure.Wrap("prepare publisher identity secret", reason, errScope)
}

// Prepare is sequential and context-bound. every mutating AWS call has a saved
// intent and idempotency token. a bootstrap-owned container first stores a random
// ownership proof; tags alone can never authorize writing a publisher key.
func (p Preparer) Prepare(ctx context.Context, r Request) (Reference, error) {
	b := r.Binding
	if err := b.validate(); err != nil {
		return Reference{}, err
	}
	if err := (Deployment{Name: b.DeploymentName, Publisher: r.Group, AccountID: b.AccountID, Region: b.Region, Secrets: map[string]Secret{b.ReplicaSlot: r.Secret}}).Validate(); err != nil {
		return Reference{}, err
	}
	if p.Store == nil || p.Secrets == nil || p.Control == nil || p.Client == nil || p.Receipts == nil {
		return Reference{}, invalid()
	}
	lock, err := p.Store.LockPublisherSigningIdentity(ctx, "aws-bootstrap:"+b.ID())
	if err != nil {
		return Reference{}, err
	}
	defer lock.Close()
	data, revision, err := p.Store.PublisherProvision(ctx, "aws", b.ID())
	if err != nil {
		return Reference{}, err
	}
	receiptName := b.ID() + ".json"
	_, receiptExists, err := p.Receipts.Read(receiptName, 65536)
	if err != nil {
		return Reference{}, err
	}
	if revision == 0 && receiptExists {
		return Reference{}, conflict(failure.AWSBootstrapStateLost)
	}
	j := operation{Binding: b, Secret: r.Secret, Stage: "planned"}
	if revision != 0 {
		j = operation{}
		if json.Unmarshal(data, &j) != nil || len(j.CreateToken) != 64 || len(j.ValueToken) != 64 || len(j.Proof) != 64 {
			return Reference{}, conflict(failure.AWSBootstrapStateLost)
		}
		if j.Binding != b {
			return Reference{}, conflict(failure.AWSBootstrapScope)
		}
		if j.Secret != r.Secret {
			return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
		}
	} else {
		// probe the exact resource before claiming the name or enrolling a key.
		description, err := p.describe(ctx, secretID(j))
		if err != nil {
			return Reference{}, err
		}
		if description != nil && r.Secret.ExistingARN == "" {
			return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
		}
		if r.Secret.ExistingARN != "" {
			if description == nil || aws.ToString(description.ARN) != r.Secret.ExistingARN || description.DeletedDate != nil {
				return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
			}
			if r.Secret.ExistingVersion == "" && len(description.VersionIdsToStages) != 0 {
				return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
			}
			j.ARN = r.Secret.ExistingARN
		}
		for _, token := range []*string{&j.CreateToken, &j.ValueToken, &j.Proof} {
			*token, err = randomToken()
			if err != nil {
				return Reference{}, err
			}
		}
		if err := p.save(ctx, &j, &revision, "planned"); err != nil {
			return Reference{}, err
		}
	}
	// the receipt is nonsecret loss detection, never authority to reuse a key.
	intent, _ := json.Marshal(struct {
		Binding Binding `json:"binding"`
		State   string  `json:"state"`
	}{b, "pending"})
	if err := p.Receipts.Write(receiptName, intent); err != nil {
		return Reference{}, err
	}
	if r.Secret.ExistingVersion != "" {
		return p.existing(ctx, r, &j, &revision, receiptName)
	}
	if j.Stage == "planned" || j.Stage == "creating" {
		if err := p.save(ctx, &j, &revision, "creating"); err != nil {
			return Reference{}, err
		}
		if r.Secret.ExistingARN == "" {
			description, err := p.describe(ctx, secretID(j))
			if err != nil {
				return Reference{}, err
			}
			if description == nil {
				marker := markerValue(j)
				input := &secretsmanager.CreateSecretInput{Name: aws.String(secretID(j)), ClientRequestToken: aws.String(j.CreateToken), SecretString: &marker, Tags: []types.Tag{{Key: aws.String("tnl:bootstrap"), Value: aws.String(b.ID())}, {Key: aws.String("tnl:owner"), Value: aws.String("bootstrap")}}}
				if j.Secret.KMSKeyID != "" {
					input.KmsKeyId = aws.String(j.Secret.KMSKeyID)
				}
				_, err = p.Secrets.CreateSecret(ctx, input)
				if err != nil {
					return Reference{}, awsError("create publisher identity container", err)
				}
				description, err = p.describe(ctx, secretID(j))
				if err != nil {
					return Reference{}, err
				}
			}
			if err := p.owned(ctx, &j, description); err != nil {
				return Reference{}, err
			}
		} else {
			description, err := p.describe(ctx, j.ARN)
			if err != nil {
				return Reference{}, err
			}
			if description == nil || aws.ToString(description.ARN) != j.ARN || description.DeletedDate != nil {
				return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
			}
			marker, err := p.get(ctx, j.ARN, j.CreateToken)
			if err != nil {
				return Reference{}, err
			}
			if marker == nil {
				if len(description.VersionIdsToStages) != 0 {
					return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
				}
				_, err = p.Secrets.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(j.ARN), ClientRequestToken: aws.String(j.CreateToken), SecretString: aws.String(markerValue(j)), VersionStages: []string{"tnl-" + j.CreateToken}})
				if err != nil {
					return Reference{}, awsError("claim external identity container", err)
				}
			}
			if err := p.owned(ctx, &j, description); err != nil {
				return Reference{}, err
			}
		}
		if err := p.save(ctx, &j, &revision, "container"); err != nil {
			return Reference{}, err
		}
	}
	if j.Stage == "enrolling" {
		// the shared owner committed its key before this transition. never allow
		// missing owner state to turn a response-loss retry into new enrollment.
		_, ownerRevision, err := p.Store.PublisherProvision(ctx, "group", credentialfile.GroupSelection(b.ProjectKey, b.GroupID, b.Instance()))
		if err != nil {
			return Reference{}, err
		}
		if ownerRevision == 0 {
			return Reference{}, conflict(failure.AWSBootstrapStateLost)
		}
	}
	if j.Stage == "container" || j.Stage == "enrolling" {
		description, err := p.describe(ctx, j.ARN)
		if err != nil {
			return Reference{}, err
		}
		if err := p.owned(ctx, &j, description); err != nil {
			return Reference{}, err
		}
		for version := range description.VersionIdsToStages {
			if version != j.CreateToken {
				return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
			}
		}
		identity, err := publisherprovision.Ensure(ctx, p.Store, p.Control, p.Client, scopeOf(r), func() error { return p.save(ctx, &j, &revision, "enrolling") })
		if err != nil {
			return Reference{}, err
		}
		j.Identity = &identity
		if err := p.save(ctx, &j, &revision, "enrolled"); err != nil {
			return Reference{}, err
		}
	}
	if j.Identity == nil || (j.Stage != "enrolled" && j.Stage != "putting" && j.Stage != "durable") {
		return Reference{}, conflict(failure.AWSBootstrapStateLost)
	}
	if err := p.verify(ctx, r, *j.Identity); err != nil {
		return Reference{}, err
	}
	description, err := p.describe(ctx, j.ARN)
	if err != nil {
		return Reference{}, err
	}
	if err := p.owned(ctx, &j, description); err != nil {
		return Reference{}, err
	}
	value, err := p.get(ctx, j.ARN, j.ValueToken)
	if err != nil {
		return Reference{}, err
	}
	if value == nil {
		if j.Stage == "durable" {
			return Reference{}, conflict(failure.AWSBootstrapVersionConflict)
		}
		// either kind of container may hold only our marker; another version
		// is not permission to overwrite it.
		for version := range description.VersionIdsToStages {
			if version != j.CreateToken {
				return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
			}
		}
		if err := p.save(ctx, &j, &revision, "putting"); err != nil {
			return Reference{}, err
		}
		payload, _ := json.Marshal(j.Identity)
		_, err = p.Secrets.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(j.ARN), ClientRequestToken: aws.String(j.ValueToken), SecretString: aws.String(string(payload)), VersionStages: []string{"tnl-" + j.ValueToken}})
		clear(payload)
		if err != nil {
			return Reference{}, awsError("store publisher identity version", err)
		}
		value, err = p.get(ctx, j.ARN, j.ValueToken)
		if err != nil {
			return Reference{}, err
		}
	}
	if err := matchVersion(value, j.ARN, j.ValueToken, *j.Identity); err != nil {
		return Reference{}, err
	}
	if err := p.verify(ctx, r, *j.Identity); err != nil {
		return Reference{}, err
	}
	if err := p.save(ctx, &j, &revision, "durable"); err != nil {
		return Reference{}, err
	}
	return p.finish(j, receiptName, j.ValueToken)
}

func secretID(j operation) string {
	if j.ARN != "" {
		return j.ARN
	}
	if j.Secret.ExistingARN != "" {
		return j.Secret.ExistingARN
	}
	if j.Secret.Name != "" {
		return j.Secret.Name
	}
	return "tnl/publishers/" + j.Binding.Instance()
}

func markerValue(j operation) string {
	data, _ := json.Marshal(struct {
		Binding string `json:"binding"`
		Proof   string `json:"proof"`
	}{j.Binding.ID(), j.Proof})
	return string(data)
}

func (p Preparer) save(ctx context.Context, j *operation, revision *int64, stage string) error {
	if j.Stage == stage && *revision != 0 {
		return nil
	}
	j.Stage = stage
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	defer clear(data)
	if err := p.Store.AppendPublisherProvision(ctx, "aws", j.Binding.ID(), *revision, data); err != nil {
		return err
	}
	*revision++
	if p.afterSave != nil {
		return p.afterSave(stage)
	}
	return nil
}

func (p Preparer) describe(ctx context.Context, id string) (*secretsmanager.DescribeSecretOutput, error) {
	value, err := p.Secrets.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(id)})
	if code(err) == "ResourceNotFoundException" {
		return nil, nil
	}
	if err != nil {
		return nil, awsError("inspect publisher identity container", err)
	}
	if value == nil {
		return nil, conflict(failure.AWSBootstrapSecretConflict)
	}
	return value, nil
}

func (p Preparer) get(ctx context.Context, arn, version string) (*secretsmanager.GetSecretValueOutput, error) {
	value, err := p.Secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(arn), VersionId: aws.String(version)})
	if code(err) == "ResourceNotFoundException" {
		return nil, nil
	}
	if err != nil {
		return nil, awsError("read publisher identity version", err)
	}
	if value == nil || aws.ToString(value.ARN) != arn || aws.ToString(value.VersionId) != version || value.SecretString == nil || len(*value.SecretString) > 8192 || len(value.SecretBinary) != 0 {
		return nil, conflict(failure.AWSBootstrapVersionConflict)
	}
	return value, nil
}

func (p Preparer) owned(ctx context.Context, j *operation, d *secretsmanager.DescribeSecretOutput) error {
	if d == nil || d.DeletedDate != nil || !secretARN(aws.ToString(d.ARN), j.Binding.AccountID, j.Binding.Region) || j.ARN != "" && j.ARN != aws.ToString(d.ARN) {
		return conflict(failure.AWSBootstrapSecretConflict)
	}
	expectedName := j.Secret.Name
	if expectedName == "" {
		expectedName = "tnl/publishers/" + j.Binding.Instance()
	}
	if j.Secret.ExistingARN == "" && aws.ToString(d.Name) != expectedName {
		return conflict(failure.AWSBootstrapSecretConflict)
	}
	tags := map[string]string{}
	for _, tag := range d.Tags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}
	if j.Secret.ExistingARN == "" && (tags["tnl:bootstrap"] != j.Binding.ID() || tags["tnl:owner"] != "bootstrap") {
		return conflict(failure.AWSBootstrapSecretConflict)
	}
	value, err := p.get(ctx, aws.ToString(d.ARN), j.CreateToken)
	if err != nil {
		return err
	}
	if value == nil || subtle.ConstantTimeCompare([]byte(aws.ToString(value.SecretString)), []byte(markerValue(*j))) != 1 {
		return conflict(failure.AWSBootstrapSecretConflict)
	}
	j.ARN = aws.ToString(d.ARN)
	return nil
}

func (p Preparer) verify(ctx context.Context, r Request, value credentialfile.GroupFile) error {
	scope := scopeOf(r)
	if value.Member.TeamId != scope.Team || value.Member.GroupId != scope.GroupID {
		return conflict(failure.AWSBootstrapScope)
	}
	return credentialfile.VerifyGroup(ctx, p.Client, value, scope.Server, scope.Project, scope.Group, scope.Instance)
}

func matchVersion(value *secretsmanager.GetSecretValueOutput, arn, version string, expected credentialfile.GroupFile) error {
	if value == nil || aws.ToString(value.ARN) != arn || aws.ToString(value.VersionId) != version {
		return conflict(failure.AWSBootstrapVersionConflict)
	}
	actual, err := credentialfile.ParseGroup([]byte(aws.ToString(value.SecretString)))
	if err != nil || actual.ControlURL != expected.ControlURL || actual.Instance != expected.Instance || !credentialfile.SameGroupIdentity(actual.Member, expected.Member) || subtle.ConstantTimeCompare([]byte(actual.PrivateKey), []byte(expected.PrivateKey)) != 1 {
		return conflict(failure.AWSBootstrapVersionConflict)
	}
	return nil
}

func (p Preparer) existing(ctx context.Context, r Request, j *operation, revision *int64, receipt string) (Reference, error) {
	d, err := p.describe(ctx, j.ARN)
	if err != nil {
		return Reference{}, err
	}
	if d == nil || aws.ToString(d.ARN) != j.ARN || d.DeletedDate != nil {
		return Reference{}, conflict(failure.AWSBootstrapSecretConflict)
	}
	v, err := p.get(ctx, j.ARN, j.Secret.ExistingVersion)
	if err != nil {
		return Reference{}, err
	}
	if v == nil {
		return Reference{}, conflict(failure.AWSBootstrapVersionConflict)
	}
	identity, err := credentialfile.ParseGroup([]byte(aws.ToString(v.SecretString)))
	if err != nil || identity.Member.PublisherIdentityId != j.Secret.PublisherIdentityID {
		return Reference{}, conflict(failure.AWSBootstrapVersionConflict)
	}
	if err := p.verify(ctx, r, identity); err != nil {
		return Reference{}, err
	}
	if j.Identity != nil {
		if err := matchVersion(v, j.ARN, j.Secret.ExistingVersion, *j.Identity); err != nil {
			return Reference{}, err
		}
	}
	scope := scopeOf(r)
	lock, err := p.Store.LockPublisherSigningIdentity(ctx, credentialfile.GroupSelection(scope.Project, scope.GroupID, scope.Instance))
	if err != nil {
		return Reference{}, err
	}
	defer lock.Close()
	if _, err := publisherprovision.Import(ctx, p.Store, p.Client, identity, scope); err != nil {
		return Reference{}, err
	}
	j.Identity = &identity
	if err := p.save(ctx, j, revision, "durable"); err != nil {
		return Reference{}, err
	}
	return p.finish(*j, receipt, j.Secret.ExistingVersion)
}

func (p Preparer) finish(j operation, receipt, version string) (Reference, error) {
	if j.Identity == nil || j.Stage != "durable" {
		return Reference{}, errors.New("publisher identity is not durable")
	}
	ref := Reference{Binding: j.Binding, Instance: j.Binding.Instance(), PublisherIdentityID: j.Identity.Member.PublisherIdentityId, SecretARN: j.ARN, SecretVersion: version, Ownership: "bootstrap"}
	if j.Secret.ExistingARN != "" {
		ref.Ownership = "external"
	}
	data, _ := json.Marshal(ref)
	if err := p.Receipts.Write(receipt, data); err != nil {
		return Reference{}, err
	}
	return ref, nil
}
