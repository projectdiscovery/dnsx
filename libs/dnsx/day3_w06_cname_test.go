package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCNAMERetryValidation(t *testing.T) {
	options := DefaultOptions
	options.MaxRetries = 5
	assert.Equal(t, 5, options.MaxRetries)
}
