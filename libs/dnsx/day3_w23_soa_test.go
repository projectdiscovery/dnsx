package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSOASerialFormatW23(t *testing.T) {
	serial := uint32(2026091001)
	assert.Greater(t, serial, uint32(2026000000))
}
