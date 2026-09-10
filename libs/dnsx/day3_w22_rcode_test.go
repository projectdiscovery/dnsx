package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsMultipleRCodeFilterValidation(t *testing.T) {
	opts := DefaultOptions
	opts.ResponseCode = "NOERROR,SERVFAIL,REFUSED"
	opts.Domains = []string{"filter.example.com"}

	assert.Equal(t, "NOERROR,SERVFAIL,REFUSED", opts.ResponseCode)
	assert.Equal(t, 1, len(opts.Domains))
}
