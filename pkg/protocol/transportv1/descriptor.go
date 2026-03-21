// Package transportv1 contains the versioned Tailcat transport descriptor
// defined by api/transport/v1/tailcat-descriptor.schema.json.
package transportv1

const TailcatDescriptorVersion = 1

type TailcatDescriptor struct {
	Version         int    `json:"version"`
	ServerPublicKey string `json:"server_public_key"`
	RelayProfile    string `json:"relay_profile"`
}
