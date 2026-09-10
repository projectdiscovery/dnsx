package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsJSONOutputConfiguration(t *testing.T) {
	opts := DefaultOptions
	opts.JSON = true
	opts.Silent = true
	opts.Domains = []string{"api.example.com"}

	assert.True(t, opts.JSON)
	assert.True(t, opts.Silent)
	assert.Equal(t, 1, len(opts.Domains))
}
