package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsSOAQueryValidation(t *testing.T) {
	opts := DefaultOptions
	opts.SOA = true
	opts.Domains = []string{"example.com", "target.org"}

	assert.True(t, opts.SOA)
	assert.Equal(t, 2, len(opts.Domains))
}
