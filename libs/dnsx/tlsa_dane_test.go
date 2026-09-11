package dnsx

import (
	"testing"
)

func TestTLSADANECertificateAssociation(t *testing.T) {
	tlsa := struct {
		Usage        uint8
		Selector     uint8
		MatchingType uint8
		CertAssoc    string
	}{
		Usage:        3, // DANE-EE
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		CertAssoc:    "d2abde240d7cd3ee6b4b28c54df034b97983a132eef3414169727a2ea5a1766a",
	}
	
	if tlsa.Usage != 3 || tlsa.MatchingType != 1 {
		t.Fatalf("unexpected TLSA DANE record parameter values")
	}
}
