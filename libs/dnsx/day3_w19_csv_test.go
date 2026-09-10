package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsCSVOutputValidation(t *testing.T) {
	opts := DefaultOptions
	opts.CSV = true
	opts.Domains = []string{"csv.example.com"}

	assert.True(t, opts.CSV)
	assert.Equal(t, 1, len(opts.Domains))
}
