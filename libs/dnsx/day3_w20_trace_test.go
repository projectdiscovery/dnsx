package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsTraceResolutionValidation(t *testing.T) {
	opts := DefaultOptions
	opts.Trace = true
	opts.Domains = []string{"trace.example.com"}

	assert.True(t, opts.Trace)
	assert.Equal(t, 1, len(opts.Domains))
}
