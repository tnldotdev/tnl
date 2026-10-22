package config

import (
	"errors"
	"regexp"
	"strings"
)

type RDSEndpoint string

const (
	RDSWriter        RDSEndpoint = "writer"
	RDSReader        RDSEndpoint = "reader"
	AWSRegionPattern             = `^[a-z]{2}(-[a-z]+)+-[0-9]+$`
	EKSNamePattern               = `^[A-Za-z][A-Za-z0-9_-]{0,99}$`
	RDSNamePattern               = `^[a-z][a-z0-9-]{0,62}$`
)

var (
	awsRegion = regexp.MustCompile(AWSRegionPattern)
	eksName   = regexp.MustCompile(EKSNamePattern)
	rdsName   = regexp.MustCompile(RDSNamePattern)
)

// CloudTarget is a pure selector, independent of provider credentials and wire
// descriptors. Normalize supplies the default RDS endpoint without changing input.
type CloudTarget struct {
	Type, Region, Cluster, Instance string
	Endpoint                        RDSEndpoint
}

func (t CloudTarget) Normalize(protocol string) (CloudTarget, error) {
	if len(t.Region) > 32 || !awsRegion.MatchString(t.Region) {
		return CloudTarget{}, errors.New("cloud targets require a valid region")
	}
	switch t.Type {
	case "eks":
		if protocol != "kubernetes" || !eksName.MatchString(t.Cluster) || t.Instance != "" || t.Endpoint != "" {
			return CloudTarget{}, errors.New("target.type eks requires protocol kubernetes, cluster, and region only")
		}
	case "rds":
		if protocol != "postgres" && protocol != "mysql" || (t.Instance == "") == (t.Cluster == "") {
			return CloudTarget{}, errors.New("target.type rds requires protocol postgres or mysql, region, and exactly one of instance or cluster")
		}
		name := t.Instance
		if name == "" {
			name = t.Cluster
		}
		if !rdsName.MatchString(name) || strings.HasSuffix(name, "-") || strings.Contains(name, "--") {
			return CloudTarget{}, errors.New("rds resource must be an exact resource identifier")
		}
		if t.Endpoint == "" {
			t.Endpoint = RDSWriter
		}
		if t.Endpoint != RDSWriter && t.Endpoint != RDSReader || t.Endpoint == RDSReader && t.Instance != "" {
			return CloudTarget{}, errors.New("rds endpoint must be writer (default), or reader for a cluster")
		}
	default:
		return CloudTarget{}, errors.New("cloud target type must be eks or rds")
	}
	return t, nil
}

// NormalizeCloudTarget preserves presence rules from source configuration and
// control descriptors before projecting them to the value-only selector.
func NormalizeCloudTarget(protocol string, target ServiceTarget) (CloudTarget, error) {
	if target.Region == nil || target.Address != nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil || target.TLS != nil {
		return CloudTarget{}, errors.New("cloud targets require region and an exact resource selector; discovered TLS and addresses belong to the publisher")
	}
	for _, value := range []*string{target.Cluster, target.Instance, target.Endpoint} {
		if value != nil && *value == "" {
			return CloudTarget{}, errors.New("cloud selectors must not be empty; omit optional fields")
		}
	}
	if target.Type == "eks" && (target.Instance != nil || target.Endpoint != nil) || target.Type == "rds" && (target.Instance == nil) == (target.Cluster == nil) {
		return CloudTarget{}, errors.New("cloud target requires exactly its declared resource selector")
	}
	value := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return (CloudTarget{Type: target.Type, Region: *target.Region, Cluster: value(target.Cluster), Instance: value(target.Instance), Endpoint: RDSEndpoint(value(target.Endpoint))}).Normalize(protocol)
}

// ValidateCloudTarget checks selectors without normalizing input or provider I/O.
func ValidateCloudTarget(protocol string, target ServiceTarget) error {
	_, err := NormalizeCloudTarget(protocol, target)
	return err
}
