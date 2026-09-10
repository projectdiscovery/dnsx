package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsRetryBackoffValidation(t *testing.T) {
	opts := DefaultOptions
	opts.MaxRetries = 5
	opts.Domains = []string{"retry.example.com"}

	assert.Equal(t, 5, opts.MaxRetries)
	assert.Equal(t, 1, len(opts.Domains))
}
