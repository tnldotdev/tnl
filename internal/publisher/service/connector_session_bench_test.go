package service

import "testing"

func BenchmarkConnectorAdmissionCheckUse(b *testing.B) {
	_, _, admission := connectorUseFixture(b)
	ctx := b.Context()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := admission.CheckUse(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
