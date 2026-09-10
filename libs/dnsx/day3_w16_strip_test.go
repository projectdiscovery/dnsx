package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsStripCommentsValidation(t *testing.T) {
	opts := DefaultOptions
	opts.Raw = false
	opts.Domains = []string{"strip.example.com"}

	assert.False(t, opts.Raw)
	assert.Equal(t, 1, len(opts.Domains))
}
