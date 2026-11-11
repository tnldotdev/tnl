package publisher

import "testing"

func TestConfiguredPublisherIdentityRequiresExplicitCapability(t *testing.T) {
	control := &publisherControlStub{}
	config := Config{Control: control, PublisherIdentityID: control.PublisherIdentityID()}
	if _, err := configuredPublisherIdentityID(config); err == nil {
		t.Fatal("control method or caller ID supplied an implicit identity capability")
	}
	config.Identity = control
	if id, err := configuredPublisherIdentityID(config); err != nil || id != control.PublisherIdentityID() {
		t.Fatal("explicit identity rejected", err)
	}
	config.PublisherIdentityID = "pub_abcdefghijkl0123456789"
	if _, err := configuredPublisherIdentityID(config); err == nil {
		t.Fatal("caller ID overrode the selected signed identity")
	}
}
