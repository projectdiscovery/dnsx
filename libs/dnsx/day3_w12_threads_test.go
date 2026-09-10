package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsThreadsConcurrencyValidation(t *testing.T) {
	opts := DefaultOptions
	opts.Threads = 50
	opts.MaxRetries = 3
	opts.Domains = []string{"domain1.com", "domain2.com"}

	assert.Equal(t, 50, opts.Threads)
	assert.Equal(t, 3, opts.MaxRetries)
	assert.Equal(t, 2, len(opts.Domains))
}
