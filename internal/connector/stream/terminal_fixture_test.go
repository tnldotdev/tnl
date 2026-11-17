package stream

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

func connectorTestControlScope() tunnelv1.ConnectorControlScope {
	return tunnelv1.ConnectorControlScope{
		ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunID: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		PublisherIdentityID: "pub_aaaaaaaaaaaaaaaaaaaaaa", PairID: "cpp_aaaaaaaaaaaaaaaaaaaaaa",
	}
}
