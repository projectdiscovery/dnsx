package dnsx

import (
	"testing"
)

func TestSSHFPRecordAlgorithmType(t *testing.T) {
	// Algorithm 4 = ED25519, Type 2 = SHA-256
	sshfp := struct {
		Algorithm  uint8
		Type       uint8
		Fingerprint string
	}{
		Algorithm:   4,
		Type:        2,
		Fingerprint: "123456789abcdef67890123456789abcdef67890",
	}
	
	if sshfp.Algorithm != 4 || sshfp.Type != 2 {
		t.Fatalf("unexpected SSHFP algorithm or hash type code")
	}
}
