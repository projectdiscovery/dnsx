package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsRateLimitValidation(t *testing.T) {
	opts := DefaultOptions
	opts.RateLimit = 150
	opts.Domains = []string{"rate.example.com"}

	assert.Equal(t, 150, opts.RateLimit)
	assert.Equal(t, 1, len(opts.Domains))
}
