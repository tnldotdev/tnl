package transportv1

const TailcatDescriptorVersion = 1

type TailcatDescriptor struct {
	Version            int    `json:"version"`
	PublisherPublicKey string `json:"publisher_public_key"`
	RelayRegion        string `json:"relay_region"`
}
