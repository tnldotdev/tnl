package local

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"

	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

type applicationSource struct {
	selection authorityv1.IdentitySourceSelection
	assertion string
	reply     *authorityv1.IdentitySourceReply
}

func (applicationSource) String() string   { return "private application identity source" }
func (applicationSource) GoString() string { return "private application identity source" }

func applicationSourceProof(raw json.RawMessage, requireReply bool) (applicationSource, error) {
	var selector struct {
		Kind string `json:"kind"`
	}
	if jsonv2.Unmarshal(raw, &selector) != nil {
		return applicationSource{}, publisherprotocol.ErrApplicationAuthInvalid
	}
	var source applicationSource
	switch selector.Kind {
	case "oidc":
		proof, err := applicationOIDCProof(raw)
		if err != nil {
			return source, err
		}
		source.selection = authorityv1.IdentitySourceSelection{Kind: "oidc", MachineId: proof.MachineId}
		source.assertion = proof.Assertion
	case "registered_key":
		var proof localv1.ApplicationRegisteredKeyProof
		if jsonv2.Unmarshal(raw, &proof, jsonv2.RejectUnknownMembers(true)) != nil {
			return source, publisherprotocol.ErrApplicationAuthInvalid
		}
		source.selection = authorityv1.IdentitySourceSelection{Kind: "registered_key", MachineId: proof.MachineId, KeyId: proof.KeyId}
		source.reply = proof.Reply
		if requireReply {
			if proof.Reply == nil || proof.Reply.Schema != 1 || !publisheridentity.ValidApplicationAssertion(proof.Reply.Assertion) {
				return source, publisherprotocol.ErrApplicationAuthInvalid
			}
			source.assertion = proof.Reply.Assertion
			key, err := publisherproof.KeyID(source.assertion)
			if err != nil || key != proof.KeyId {
				return source, publisherprotocol.ErrApplicationAuthInvalid
			}
		}
	default:
		return source, publisherprotocol.ErrApplicationAuthInvalid
	}
	if !machineproof.ValidSource(source.selection) {
		return applicationSource{}, publisherprotocol.ErrApplicationAuthInvalid
	}
	return source, nil
}
