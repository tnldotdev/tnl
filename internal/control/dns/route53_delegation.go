package dns

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

type route53DelegationAPI interface {
	GetReusableDelegationSet(context.Context, *route53.GetReusableDelegationSetInput, ...func(*route53.Options)) (*route53.GetReusableDelegationSetOutput, error)
}

type Route53DelegationProvider struct{ client route53DelegationAPI }

func NewRoute53DelegationProvider(client route53DelegationAPI) *Route53DelegationProvider {
	return &Route53DelegationProvider{client: client}
}

func (p *Route53DelegationProvider) DelegationNameservers(ctx context.Context, id string) ([]string, error) {
	output, err := p.client.GetReusableDelegationSet(ctx, &route53.GetReusableDelegationSetInput{Id: aws.String(id)})
	if err != nil {
		return nil, fmt.Errorf("read reusable Route 53 delegation set: %w", err)
	}
	if output == nil || delegationSetID(output.DelegationSet) != id || len(output.DelegationSet.NameServers) != 4 {
		return nil, terminalf("unexpected reusable Route 53 delegation set")
	}
	// canonicalNameservers sorts the AWS names, giving every replica and the
	// operator the same mapping to ns1 through ns4 regardless of API order.
	return canonicalNameservers(output.DelegationSet.NameServers)
}

func delegationSetID(set *types.DelegationSet) string {
	if set == nil {
		return ""
	}
	return strings.TrimPrefix(aws.ToString(set.Id), "/delegationset/")
}
