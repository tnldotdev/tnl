package deployment

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	"go.yaml.in/yaml/v3"
)

// this is a renderer for one fixed ECS/EFS topology, not an infrastructure DSL.
type object = map[string]any

type awsTemplate struct {
	Version     string                  `yaml:"AWSTemplateFormatVersion"`
	Description string                  `yaml:"Description"`
	Metadata    object                  `yaml:"Metadata"`
	Parameters  map[string]AWSParameter `yaml:"Parameters"`
	Conditions  object                  `yaml:"Conditions"`
	Rules       object                  `yaml:"Rules"`
	Resources   object                  `yaml:"Resources"`
	Outputs     object                  `yaml:"Outputs"`
}

// AWSParameter is the authoritative deploy-time input definition. defaults in
// this model also produce the example parameter file.
type AWSParameter struct {
	Type           string   `yaml:"Type"`
	Description    string   `yaml:"Description"`
	Default        *string  `yaml:"Default,omitempty"`
	AllowedPattern string   `yaml:"AllowedPattern,omitempty"`
	AllowedValues  []string `yaml:"AllowedValues,omitempty"`
	MaxLength      int      `yaml:"MaxLength,omitempty"`
}

func ref(name string) object                      { return object{"Ref": name} }
func sub(value string) object                     { return object{"Fn::Sub": value} }
func att(name, attribute string) object           { return object{"Fn::GetAtt": []string{name, attribute}} }
func choose(condition string, yes, no any) object { return object{"Fn::If": []any{condition, yes, no}} }
func eq(a, b any) object                          { return object{"Fn::Equals": []any{a, b}} }
func not(value any) object                        { return object{"Fn::Not": []any{value}} }
func and(values ...any) object                    { return object{"Fn::And": values} }
func condition(name string) object                { return object{"Condition": name} }
func noValue() object                             { return ref("AWS::NoValue") }
func resource(kind string, properties object) object {
	return object{"Type": kind, "Properties": properties}
}
func retained(kind string, properties object) object {
	r := resource(kind, properties)
	r["DeletionPolicy"], r["UpdateReplacePolicy"] = "Retain", "Retain"
	return r
}
func output(value any) object { return object{"Value": value} }
func allow(actions any, target any) object {
	return object{"Effect": "Allow", "Action": actions, "Resource": target}
}
func policy(name string, statements ...any) object {
	return object{"PolicyName": name, "PolicyDocument": object{"Version": "2012-10-17", "Statement": statements}}
}

func (t *awsTemplate) parameter(name, description, pattern string, max int, fallback *string, values ...string) {
	t.Parameters[name] = AWSParameter{Type: "String", Description: description, AllowedPattern: pattern, MaxLength: max, Default: fallback, AllowedValues: values}
}
func text(value string) *string { return &value }
func (t *awsTemplate) optional(name, description, pattern string, max int) {
	t.parameter(name, description, "("+pattern+")?", max, text(""))
	t.Conditions["Has"+name] = not(eq(ref(name), ""))
}
func (t *awsTemplate) named(name, suffix string) object {
	return choose("Has"+name, ref(name), choose("HasResourcePrefix", sub("${ResourcePrefix}"+suffix), noValue()))
}

func tags() []any {
	return []any{object{"Key": "tnl:deployment-id", "Value": ref(DeploymentIDParameter)}, object{"Key": "tnl:project-key", "Value": ref(ProjectKeyParameter)}, object{"Key": "tnl:publisher-group-id", "Value": ref(PublisherGroupIDParameter)}, object{"Key": "tnl:team-id", "Value": ref(TeamIDParameter)}}
}

const (
	identifierPattern = "[A-Za-z0-9][A-Za-z0-9_-]{0,127}"
	roleARNPattern    = "arn:[a-z0-9-]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+"
	kmsARNPattern     = "arn:[a-z0-9-]+:kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+"
	sgPattern         = "sg-[0-9a-f]{8,17}"
	secretARNPattern  = "arn:[a-z0-9-]+:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+"
)

// RenderAWS returns deterministic CloudFormation YAML and a nonsecret AWS
// parameter-file JSON example.
func RenderAWS(p Publisher, projectKey string, configurations ...config.TNL) ([]byte, []byte, error) {
	if p.Provider != "aws" || p.Name == "local" || !naming.ValidServiceName(p.Name) || !naming.ValidProjectKey(projectKey) {
		return nil, nil, errors.New("invalid AWS publisher or project identity")
	}
	if len(p.Replicas) < 1 || len(p.Replicas) > config.MaxPublisherReplicas {
		return nil, nil, errors.New("AWS replica count is outside the supported bound")
	}
	for i, r := range p.Replicas {
		if r != replica(i+1) {
			return nil, nil, errors.New("invalid AWS replica parameter contract")
		}
	}
	t := awsTemplate{Version: "2010-09-09", Description: "tnl publisher group: independent single-task replicas, pinned signing identities, durable private EFS identity files, task-local runtime state.", Metadata: object{"tnl:template-version": TemplateVersion, "tnl:parameter-contract-version": SchemaVersion}, Parameters: map[string]AWSParameter{}, Conditions: object{}, Rules: object{}, Resources: object{}, Outputs: object{}}
	t.parameter(ControlURLParameter, "HTTPS control origin supplied by bootstrap.", "https://[a-z0-9.-]+(:[0-9]+)?", 253, nil)
	t.parameter(ProjectKeyParameter, "Stable Git source project key; must match the provisioned identities.", "[a-z0-9][a-z0-9-]{0,62}", 63, nil)
	t.parameter(GroupParameter, "Configuration group selector; may change without changing replica storage paths.", "(?!local$)[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?", 32, nil)
	t.parameter(TeamIDParameter, "Actual team ID supplied by bootstrap; not a mutable team name.", identifierPattern, 128, nil)
	t.parameter(PublisherGroupIDParameter, "Actual immutable publisher group ID supplied by bootstrap.", identifierPattern, 128, nil)
	t.parameter(DeploymentIDParameter, "Immutable unique deployment ID from bootstrap. Preserve on every update; never reuse for another group.", "[a-z0-9][a-z0-9-]{0,47}", 48, nil)
	t.parameter(TemplateSHA256Parameter, "Exact template byte SHA-256 from manifest.json, supplied by the consumer (a template cannot hash itself).", "[a-f0-9]{64}", 64, nil)
	t.parameter("PublisherImage", "Publicly pullable image by digest, with /usr/local/bin/tnl and private /state owned by 65532. Private registry authentication is external.", "[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}", 512, nil)
	t.parameter("VpcId", "Existing VPC for tasks and EFS mount targets.", "vpc-[0-9a-f]{8,17}", 21, nil)
	t.Parameters["Subnets"] = AWSParameter{Type: "List<AWS::EC2::Subnet::Id>", Description: "Existing task subnets with DNS and outbound connectivity to control, relays, targets, EFS, registry, Secrets Manager and logs."}
	t.optional("ResourcePrefix", "Optional physical-name prefix. Empty uses CloudFormation-generated names; IAM names require CAPABILITY_NAMED_IAM. Must not produce an sg- security group name.", "(?![sS][gG](?:-|$))[A-Za-z][A-Za-z0-9-]{0,31}", 32)
	t.optional("ClusterName", "Optional new cluster name; overrides prefix.", "[A-Za-z0-9_-]+", 255)
	t.optional("ExistingClusterArn", "Existing cluster ARN; never owned or modified by this stack.", "arn:[a-z0-9-]+:ecs:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+", 512)
	t.optional("ExistingPublisherSecurityGroupId", "Existing task security group in VpcId; customer owns its egress and inbound rules.", sgPattern, 20)
	t.optional("PublisherSecurityGroupName", "Optional new task security group name; overrides resource prefix.", "(?!sg-)[A-Za-z0-9 ._:/()#,@\\[\\]+=;{}!$*-]+", 255)
	t.optional("EFSSecurityGroupName", "Optional new EFS security group name; overrides resource prefix.", "(?!sg-)[A-Za-z0-9 ._:/()#,@\\[\\]+=;{}!$*-]+", 255)
	for i := 1; i <= 4; i++ {
		t.optional(fmt.Sprintf("AdditionalSecurityGroup%d", i), "Additional task security group in VpcId. At most five groups including the primary.", sgPattern, 20)
	}
	t.optional("FileSystemKMSKeyArn", "Immutable storage binding. Preserve this value for the deployment's lifetime; changing it would replace EFS with an empty filesystem. EFS uses the key, not task roles.", kmsARNPattern, 256)
	t.optional("LogsKMSKeyArn", "Key for new log groups only. Key policy must allow logs.REGION.URLSuffix with kms:EncryptionContext:aws:logs:arn scoped to the log group ARN.", kmsARNPattern, 256)
	t.optional("PermissionsBoundaryArn", "Boundary for new IAM roles only; existing role policies and boundaries remain customer-owned.", "arn:[a-z0-9-]+:iam::[0-9]{12}:policy/[A-Za-z0-9+=,.@_/-]+", 512)
	t.parameter("LogRetentionDays", "Retention for new log groups; existing groups retain their settings.", "", 0, text("30"), "1", "3", "5", "7", "14", "30", "60", "90", "120", "150", "180", "365", "400", "545", "731", "1096", "1827", "2192", "2557", "2922", "3288", "3653")
	t.parameter("TaskCPU", "Fargate CPU units. Rules enforce supported memory combinations.", "", 0, text("256"), "256", "512", "1024", "2048", "4096")
	t.parameter("TaskMemory", "Fargate memory MiB. Rules enforce supported CPU combinations.", "", 0, text("512"), memoryValues(512, 30720, 512)...)
	t.parameter("CPUArchitecture", "Image architecture; the pinned digest must support this architecture.", "", 0, text("X86_64"), "X86_64", "ARM64")
	t.parameter("PlatformVersion", "Linux Fargate platform with EFS and pinned secret-version injection.", "", 0, text("1.4.0"), "1.4.0", "LATEST")
	t.parameter("AssignPublicIp", "Keep disabled for private subnets with NAT/endpoints; enable only with appropriate public routing.", "", 0, text("DISABLED"), "DISABLED", "ENABLED")
	t.parameter("MountSubnetCount", "Number of distinct AZ mount subnets, one per AZ. Never put two mount subnets in the same AZ.", "", 0, text("2"), "1", "2", "3", "4", "5", "6")
	t.Conditions["CreateCluster"] = not(condition("HasExistingClusterArn"))
	t.Conditions["CreatePublisherSecurityGroup"] = not(condition("HasExistingPublisherSecurityGroupId"))
	cluster := choose("HasExistingClusterArn", ref("ExistingClusterArn"), att("Cluster", "Arn"))
	taskSG := choose("HasExistingPublisherSecurityGroupId", ref("ExistingPublisherSecurityGroupId"), ref("PublisherSecurityGroup"))
	filesystem := ref("IdentityFileSystem")
	filesystemARN := object{"Fn::Sub": []any{"arn:${AWS::Partition}:elasticfilesystem:${AWS::Region}:${AWS::AccountId}:file-system/${FileSystem}", object{"FileSystem": filesystem}}}
	t.Resources["Cluster"] = object{"Type": "AWS::ECS::Cluster", "Condition": "CreateCluster", "Properties": object{"ClusterName": t.named("ClusterName", "-cluster"), "Tags": tags()}}
	t.Resources["PublisherSecurityGroup"] = object{"Type": "AWS::EC2::SecurityGroup", "Condition": "CreatePublisherSecurityGroup", "Properties": object{"VpcId": ref("VpcId"), "GroupDescription": "tnl publisher tasks: no inbound, standard outbound", "SecurityGroupEgress": []any{object{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}, object{"IpProtocol": "-1", "CidrIpv6": "::/0"}}, "Tags": tags()}}
	t.Resources["EFSSecurityGroup"] = retained("AWS::EC2::SecurityGroup", object{"VpcId": ref("VpcId"), "GroupDescription": "tnl identity EFS: NFS only from publisher tasks", "SecurityGroupIngress": []any{object{"IpProtocol": "tcp", "FromPort": 2049, "ToPort": 2049, "SourceSecurityGroupId": taskSG}}, "Tags": tags()})
	// retained mount targets keep both security-group dependencies available.
	t.Resources["PublisherSecurityGroup"].(object)["DeletionPolicy"] = "Retain"
	t.Resources["PublisherSecurityGroup"].(object)["UpdateReplacePolicy"] = "Retain"
	t.Resources["PublisherSecurityGroup"].(object)["Properties"].(object)["GroupName"] = t.named("PublisherSecurityGroupName", "-publisher")
	t.Resources["EFSSecurityGroup"].(object)["Properties"].(object)["GroupName"] = t.named("EFSSecurityGroupName", "-efs")
	fs := retained("AWS::EFS::FileSystem", object{"Encrypted": true, "KmsKeyId": choose("HasFileSystemKMSKeyArn", ref("FileSystemKMSKeyArn"), noValue()), "PerformanceMode": "generalPurpose", "ThroughputMode": "elastic", "BackupPolicy": object{"Status": "ENABLED"}, "FileSystemTags": tags(), "FileSystemPolicy": object{"Version": "2012-10-17", "Statement": []any{
		object{"Effect": "Deny", "Principal": "*", "Action": "elasticfilesystem:Client*", "Resource": "*", "Condition": object{"Bool": object{"aws:SecureTransport": "false"}}},
		object{"Effect": "Deny", "Principal": "*", "Action": "elasticfilesystem:Client*", "Resource": "*", "Condition": object{"StringEquals": object{"aws:PrincipalType": "Anonymous"}}},
	}}})
	t.Resources["IdentityFileSystem"] = fs
	for i := 1; i <= 6; i++ {
		name := fmt.Sprintf("MountSubnet%d", i)
		t.optional(name, "EFS mount subnet. Select exactly one subnet per AZ used by tasks; unused entries stay empty.", "subnet-[0-9a-f]{8,17}", 24)
		selected := eq(ref("MountSubnetCount"), fmt.Sprint(i))
		if i < 6 {
			values := []any{}
			for n := i; n <= 6; n++ {
				values = append(values, eq(ref("MountSubnetCount"), fmt.Sprint(n)))
			}
			selected = object{"Fn::Or": values}
		}
		create := fmt.Sprintf("CreateMountTarget%d", i)
		t.Conditions[create] = and(selected, condition("Has"+name))
		t.Rules[name+"Required"] = object{"RuleCondition": selected, "Assertions": []any{object{"Assert": not(eq(ref(name), "")), "AssertDescription": "supply every selected mount subnet; each must be in a different AZ"}}}
		mount := retained("AWS::EFS::MountTarget", object{"FileSystemId": ref("IdentityFileSystem"), "SubnetId": ref(name), "SecurityGroups": []any{ref("EFSSecurityGroup")}})
		mount["Condition"] = create
		t.Resources[fmt.Sprintf("MountTarget%d", i)] = mount
	}
	for _, pair := range []struct {
		cpu    string
		memory []string
	}{{"256", []string{"512", "1024", "2048"}}, {"512", memoryValues(1024, 4096, 1024)}, {"1024", memoryValues(2048, 8192, 1024)}, {"2048", memoryValues(4096, 16384, 1024)}, {"4096", memoryValues(8192, 30720, 1024)}} {
		t.Rules["MemoryForCPU"+pair.cpu] = object{"RuleCondition": eq(ref("TaskCPU"), pair.cpu), "Assertions": []any{object{"Assert": object{"Fn::Contains": []any{pair.memory, ref("TaskMemory")}}, "AssertDescription": "select a supported Fargate CPU and memory combination"}}}
	}
	t.Outputs["OutputSchemaVersion"] = output("1")
	t.Outputs["TemplateVersion"] = output(TemplateVersion)
	for _, name := range []string{DeploymentIDParameter, TemplateSHA256Parameter, TeamIDParameter, PublisherGroupIDParameter, ProjectKeyParameter, GroupParameter} {
		t.Outputs[name] = output(ref(name))
	}
	t.Outputs["ClusterArn"] = output(cluster)
	t.Outputs["PublisherSecurityGroupId"] = output(taskSG)
	t.Outputs["IdentityFileSystemId"] = output(filesystem)
	for i, r := range p.Replicas {
		t.addReplica(i+1, r, cluster, taskSG, filesystem, filesystemARN)
		if len(configurations) != 0 {
			statements := discoveryStatements(configurations[0], p.Name)
			role := t.Resources[fmt.Sprintf("Replica%dTaskRole", i+1)].(object)["Properties"].(object)
			if len(statements) != 0 {
				role["Policies"] = append(role["Policies"].([]any), policy("target-discovery", statements...))
			}
		}
		for j := 0; j < i; j++ {
			other := p.Replicas[j]
			t.Rules[fmt.Sprintf("IndependentReplicas%dAnd%d", j+1, i+1)] = object{"Assertions": []any{
				object{"Assert": not(eq(ref(r.IdentitySecretARNParameter), ref(other.IdentitySecretARNParameter))), "AssertDescription": "each replica requires its own identity secret container"},
				object{"Assert": not(eq(ref(r.InstanceParameter), ref(other.InstanceParameter))), "AssertDescription": "each replica requires its own instance name"},
				object{"Assert": not(eq(ref(r.PublisherIdentityIDParameter), ref(other.PublisherIdentityIDParameter))), "AssertDescription": "each replica requires its own publisher identity"},
			}}
		}
	}
	if len(t.Parameters) > 200 || len(t.Resources) > 500 || len(t.Outputs) > 200 {
		return nil, nil, errors.New("generated AWS template exceeds CloudFormation count limits")
	}
	var rendered bytes.Buffer
	encoder := yaml.NewEncoder(&rendered)
	encoder.SetIndent(2)
	if err := encoder.Encode(t); err != nil {
		return nil, nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, nil, err
	}
	data := rendered.Bytes()
	if len(data) > MaxArtifactBytes {
		return nil, nil, errors.New("generated AWS template exceeds the S3 template size limit")
	}
	example := Parameters{}
	for name, definition := range t.Parameters {
		if definition.Default != nil {
			example[name] = *definition.Default
		} else {
			example[name] = "REQUIRED"
		}
	}
	example[ProjectKeyParameter], example[GroupParameter], example[TemplateSHA256Parameter] = projectKey, p.Name, digest(data)
	// the default topology requires two operator-selected AZs.
	example["MountSubnet1"], example["MountSubnet2"] = "REQUIRED", "REQUIRED"
	for _, r := range p.Replicas {
		example[r.InstanceParameter] = r.Key
	}
	parameters, err := encode(example.CloudFormation())
	return data, parameters, err
}

// discovery stays on the publisher's normal AWS credential chain. generation
// scopes describe permissions to declared resources and never reads DB secrets.
func discoveryStatements(configuration config.TNL, publisher string) []any {
	result := []any{}
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(configuration.Services)) {
		service := configuration.Services[name]
		if config.PublisherGroupName(service) != publisher || service.Target == nil {
			continue
		}
		target := service.Target
		var action, resource string
		switch target.Type {
		case "eks":
			action, resource = "eks:DescribeCluster", "eks:"+*target.Region+":${AWS::AccountId}:cluster/"+*target.Cluster
		case "rds":
			if target.Instance != nil {
				action, resource = "rds:DescribeDBInstances", "rds:"+*target.Region+":${AWS::AccountId}:db:"+*target.Instance
			} else {
				action, resource = "rds:DescribeDBClusters", "rds:"+*target.Region+":${AWS::AccountId}:cluster:"+*target.Cluster
			}
		default:
			continue
		}
		key := action + resource
		if !seen[key] {
			result = append(result, allow(action, sub("arn:${AWS::Partition}:"+resource)))
			seen[key] = true
		}
	}
	return result
}

func memoryValues(start, end, step int) []string {
	result := []string{}
	for value := start; value <= end; value += step {
		result = append(result, fmt.Sprint(value))
	}
	return result
}

func (t *awsTemplate) addReplica(index int, r Replica, cluster, taskSG, filesystem, filesystemARN any) {
	prefix := fmt.Sprintf("Replica%d", index)
	suffix := fmt.Sprintf("-r%d", index)
	t.parameter(r.InstanceParameter, "Provisioned instance name; must match identity JSON. EFS paths use immutable replica keys.", "[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?", 32, nil)
	t.parameter(r.PublisherIdentityIDParameter, "Public publisher identity ID returned by bootstrap; never the signing key.", identifierPattern, 128, nil)
	t.parameter(r.IdentitySecretARNParameter, "Existing replica-private Secrets Manager SecretString containing provisioned group identity JSON; never shared with another replica.", secretARNPattern, 512, nil)
	t.parameter(r.IdentitySecretVersionParameter, "Pinned secret version ID injected at every task launch, including replacements.", "[A-Za-z0-9-]{32,64}", 64, nil)
	t.optional(prefix+"IdentityKMSKeyArn", "Customer-managed key for this replica secret; key policy must permit execution-role decrypt via Secrets Manager with SecretARN context.", kmsARNPattern, 256)
	t.optional(prefix+"ServiceName", "Optional ECS service physical name; overrides resource prefix.", "[A-Za-z0-9_-]+", 255)
	t.optional(prefix+"TaskFamily", "Optional task definition family; overrides resource prefix.", "[A-Za-z0-9_-]+", 255)
	t.optional(prefix+"LogGroupName", "Optional new log group name; overrides resource prefix.", "(?!aws/)[A-Za-z0-9_./#-]+", 512)
	t.optional(prefix+"ExistingLogGroupName", "Existing log group; customer owns retention and KMS policy.", "[A-Za-z0-9_./#-]+", 512)
	for _, role := range []string{"ExecutionRole", "TaskRole"} {
		t.optional(prefix+role+"Name", "Optional new role name; requires CAPABILITY_NAMED_IAM. Overrides resource prefix.", "[A-Za-z0-9+=,.@_-]+", 64)
		t.optional(prefix+"Existing"+role+"Arn", "Existing replica-private role. Customer must supply the same scoped policy as the generated role; stack never changes it.", roleARNPattern, 512)
		t.Conditions["Create"+prefix+role] = not(condition("Has" + prefix + "Existing" + role + "Arn"))
	}
	t.parameter(prefix+"DesiredCount", "One runs this independent replica; zero stops it without destroying identity state.", "", 0, text("1"), "0", "1")
	t.Conditions["Create"+prefix+"Logs"] = not(condition("Has" + prefix + "ExistingLogGroupName"))
	logs := choose("Has"+prefix+"ExistingLogGroupName", ref(prefix+"ExistingLogGroupName"), ref(prefix+"Logs"))
	logsARN := object{"Fn::Sub": []any{"arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:${LogGroup}:log-stream:*", object{"LogGroup": logs}}}
	logResource := retained("AWS::Logs::LogGroup", object{"LogGroupName": t.named(prefix+"LogGroupName", suffix+"-logs"), "RetentionInDays": ref("LogRetentionDays"), "KmsKeyId": choose("HasLogsKMSKeyArn", ref("LogsKMSKeyArn"), noValue()), "Tags": tags()})
	logResource["Condition"] = "Create" + prefix + "Logs"
	t.Resources[prefix+"Logs"] = logResource
	t.Resources[prefix+"IdentityAccessPoint"] = retained("AWS::EFS::AccessPoint", object{"FileSystemId": filesystem, "PosixUser": object{"Uid": "65532", "Gid": "65532"}, "RootDirectory": object{"Path": sub("/tnl/${DeploymentID}/" + r.Key), "CreationInfo": object{"OwnerUid": "65532", "OwnerGid": "65532", "Permissions": "0700"}}, "AccessPointTags": tags()})
	secretRead := allow("secretsmanager:GetSecretValue", ref(r.IdentitySecretARNParameter))
	secretRead["Condition"] = object{"StringEquals": object{"secretsmanager:VersionId": ref(r.IdentitySecretVersionParameter)}}
	decrypt := allow("kms:Decrypt", ref(prefix+"IdentityKMSKeyArn"))
	decrypt["Condition"] = object{"StringEquals": object{"kms:ViaService": sub("secretsmanager.${AWS::Region}.${AWS::URLSuffix}"), "kms:EncryptionContext:SecretARN": ref(r.IdentitySecretARNParameter)}}
	mount := allow([]string{"elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"}, filesystemARN)
	mount["Condition"] = object{"StringEquals": object{"elasticfilesystem:AccessPointArn": att(prefix+"IdentityAccessPoint", "Arn")}, "Bool": object{"aws:SecureTransport": "true", "elasticfilesystem:AccessedViaMountTarget": "true"}}
	for _, role := range []string{"ExecutionRole", "TaskRole"} {
		policies := []any{policy("private-identity-files", mount)}
		if role == "ExecutionRole" {
			policies = []any{policy("identity-and-logs", secretRead, allow([]string{"logs:CreateLogStream", "logs:PutLogEvents"}, logsARN), choose("Has"+prefix+"IdentityKMSKeyArn", decrypt, noValue()))}
		}
		t.Resources[prefix+role] = object{"Type": "AWS::IAM::Role", "Condition": "Create" + prefix + role, "Properties": object{"RoleName": t.named(prefix+role+"Name", suffix+"-"+strings.ToLower(role)), "PermissionsBoundary": choose("HasPermissionsBoundaryArn", ref("PermissionsBoundaryArn"), noValue()), "AssumeRolePolicyDocument": object{"Version": "2012-10-17", "Statement": []any{object{"Effect": "Allow", "Principal": object{"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole", "Condition": object{"StringEquals": object{"aws:SourceAccount": ref("AWS::AccountId")}, "ArnLike": object{"aws:SourceArn": sub("arn:${AWS::Partition}:ecs:${AWS::Region}:${AWS::AccountId}:*")}}}}}, "Policies": policies, "Tags": tags()}}
	}
	roleARN := func(role string) any {
		return choose("Has"+prefix+"Existing"+role+"Arn", ref(prefix+"Existing"+role+"Arn"), att(prefix+role, "Arn"))
	}
	t.Resources[prefix+"TaskDefinition"] = resource("AWS::ECS::TaskDefinition", object{
		"Family": t.named(prefix+"TaskFamily", suffix), "Cpu": ref("TaskCPU"), "Memory": ref("TaskMemory"), "NetworkMode": "awsvpc", "RequiresCompatibilities": []string{"FARGATE"}, "RuntimePlatform": object{"CpuArchitecture": ref("CPUArchitecture"), "OperatingSystemFamily": "LINUX"}, "ExecutionRoleArn": roleARN("ExecutionRole"), "TaskRoleArn": roleARN("TaskRole"), "Tags": tags(),
		"Volumes":              []any{object{"Name": "identity", "EFSVolumeConfiguration": object{"FilesystemId": filesystem, "TransitEncryption": "ENABLED", "AuthorizationConfig": object{"AccessPointId": ref(prefix + "IdentityAccessPoint"), "IAM": "ENABLED"}}}},
		"ContainerDefinitions": []any{object{"Name": "publisher", "Essential": true, "Image": ref("PublisherImage"), "User": "65532:65532", "EntryPoint": []string{"/usr/local/bin/tnl"}, "Command": []any{"--no-config", "publisher", "serve", "--server", ref(ControlURLParameter), "--project-key", ref(ProjectKeyParameter), "--group", ref(GroupParameter), "--state-dir", "/state", "--instance", ref(r.InstanceParameter), "--identity-dir", "/identity"}, "MountPoints": []any{object{"SourceVolume": "identity", "ContainerPath": "/identity", "ReadOnly": false}}, "Secrets": []any{object{"Name": "TNL_GROUP_IDENTITY", "ValueFrom": sub("${" + r.IdentitySecretARNParameter + "}:::${" + r.IdentitySecretVersionParameter + "}")}}, "LinuxParameters": object{"Capabilities": object{"Drop": []string{"ALL"}}}, "StopTimeout": 120, "LogConfiguration": object{"LogDriver": "awslogs", "Options": object{"awslogs-group": logs, "awslogs-region": ref("AWS::Region"), "awslogs-stream-prefix": "publisher"}}}},
	})
	container := t.Resources[prefix+"TaskDefinition"].(object)["Properties"].(object)["ContainerDefinitions"].([]any)[0].(object)
	container["Environment"] = []any{
		object{"Name": publisherprovenance.DeploymentIDEnv, "Value": ref(DeploymentIDParameter)},
		object{"Name": publisherprovenance.ProviderEnv, "Value": "aws"},
		object{"Name": publisherprovenance.ReplicaKeyEnv, "Value": r.Key},
		object{"Name": publisherprovenance.ImageEnv, "Value": ref("PublisherImage")},
		object{"Name": publisherprovenance.TemplateVersionEnv, "Value": TemplateVersion},
		object{"Name": publisherprovenance.TemplateSHA256Env, "Value": ref(TemplateSHA256Parameter)},
	}
	securityGroups := []any{taskSG}
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("AdditionalSecurityGroup%d", i)
		securityGroups = append(securityGroups, choose("Has"+name, ref(name), noValue()))
	}
	service := resource("AWS::ECS::Service", object{"ServiceName": t.named(prefix+"ServiceName", suffix), "Cluster": cluster, "TaskDefinition": ref(prefix + "TaskDefinition"), "DesiredCount": ref(prefix + "DesiredCount"), "LaunchType": "FARGATE", "PlatformVersion": ref("PlatformVersion"), "EnableExecuteCommand": false, "AvailabilityZoneRebalancing": "DISABLED", "DeploymentConfiguration": object{"MinimumHealthyPercent": 0, "MaximumPercent": 100, "DeploymentCircuitBreaker": object{"Enable": true, "Rollback": false}}, "NetworkConfiguration": object{"AwsvpcConfiguration": object{"AssignPublicIp": ref("AssignPublicIp"), "Subnets": ref("Subnets"), "SecurityGroups": securityGroups}}, "Tags": tags(), "PropagateTags": "SERVICE", "EnableECSManagedTags": true})
	// conditional references wait for every selected mount target without a
	// DependsOn reference to an unselected AZ.
	serviceTags := tags()
	for i := 1; i <= 6; i++ {
		name := fmt.Sprintf("MountTarget%d", i)
		serviceTags = append(serviceTags, choose("Create"+name, object{"Key": fmt.Sprintf("tnl:mount-target-%d", i), "Value": ref(name)}, noValue()))
	}
	service["Properties"].(object)["Tags"] = serviceTags
	t.Resources[prefix+"Service"] = service
	t.Outputs[prefix+"ServiceArn"] = output(ref(prefix + "Service"))
	t.Outputs[prefix+"TaskDefinitionArn"] = output(ref(prefix + "TaskDefinition"))
	t.Outputs[prefix+"LogGroupName"] = output(logs)
	t.Outputs[prefix+"IdentityAccessPointArn"] = output(att(prefix+"IdentityAccessPoint", "Arn"))
	t.Outputs[prefix+"PublisherIdentityID"] = output(ref(r.PublisherIdentityIDParameter))
	t.Outputs[prefix+"IdentitySecretArn"] = output(ref(r.IdentitySecretARNParameter))
	t.Outputs[prefix+"IdentitySecretVersion"] = output(ref(r.IdentitySecretVersionParameter))
	t.Outputs[prefix+"ExecutionRoleArn"] = output(roleARN("ExecutionRole"))
	t.Outputs[prefix+"TaskRoleArn"] = output(roleARN("TaskRole"))
}
