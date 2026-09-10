package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsAXFRZoneTransferValidation(t *testing.T) {
	opts := DefaultOptions
	opts.AXFR = true
	opts.Domains = []string{"zone.example.com"}

	assert.True(t, opts.AXFR)
	assert.Equal(t, 1, len(opts.Domains))
}
