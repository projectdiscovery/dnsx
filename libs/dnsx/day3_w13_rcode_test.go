package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsResponseCodeFilterValidation(t *testing.T) {
	opts := DefaultOptions
	opts.ResponseCode = "NOERROR,NXDOMAIN"
	opts.Domains = []string{"test.example.com"}

	assert.Equal(t, "NOERROR,NXDOMAIN", opts.ResponseCode)
	assert.Equal(t, 1, len(opts.Domains))
}
