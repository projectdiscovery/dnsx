package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsWildcardFilteringValidation(t *testing.T) {
	opts := DefaultOptions
	opts.WildcardFilter = true
	opts.WildcardThreshold = 5
	opts.Domains = []string{"*.example.com", "api.example.com"}

	assert.True(t, opts.WildcardFilter)
	assert.Equal(t, 5, opts.WildcardThreshold)
	assert.Equal(t, 2, len(opts.Domains))
}
