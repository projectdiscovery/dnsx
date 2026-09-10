package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsPTRLookupValidation(t *testing.T) {
	opts := DefaultOptions
	opts.PTR = true
	opts.Domains = []string{"192.0.2.1", "198.51.100.1"}

	assert.True(t, opts.PTR)
	assert.Equal(t, 2, len(opts.Domains))
}
