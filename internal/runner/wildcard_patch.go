package runner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func GenerateSecureRandomSubdomain() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("wildcard probe entropy generation failed: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
