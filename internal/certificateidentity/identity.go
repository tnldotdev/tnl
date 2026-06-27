package certificateidentity

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
)

var subjectAlternativeNameOID = asn1.ObjectIdentifier{2, 5, 29, 17}

// DNSNamesOnly reports whether the certificate or CSR has exactly one SAN
// extension and every GeneralName in it is a dNSName parsed by x509.
func DNSNamesOnly(extensions []pkix.Extension, dnsNames []string) bool {
	var encoded []byte
	for _, extension := range extensions {
		if !extension.Id.Equal(subjectAlternativeNameOID) {
			continue
		}
		if encoded != nil {
			return false
		}
		encoded = extension.Value
	}
	if encoded == nil {
		return false
	}
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
		sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return false
	}
	parsed := make([]string, 0, len(dnsNames))
	for rest = sequence.Bytes; len(rest) != 0; {
		var name asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &name)
		if err != nil || name.Class != asn1.ClassContextSpecific || name.Tag != 2 || name.IsCompound || !ascii(name.Bytes) {
			return false
		}
		parsed = append(parsed, string(name.Bytes))
	}
	return slices.Equal(parsed, dnsNames)
}

func ascii(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}
