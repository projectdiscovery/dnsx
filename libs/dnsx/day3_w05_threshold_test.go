package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWildcardThresholdOptionsValidation(t *testing.T) {
	options := DefaultOptions
	options.WildcardThreshold = 5
	assert.Equal(t, 5, options.WildcardThreshold)
}
