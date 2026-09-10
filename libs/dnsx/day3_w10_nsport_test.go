package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsCustomNameserverPortValidation(t *testing.T) {
	opts := DefaultOptions
	opts.BaseResolvers = []string{"127.0.0.1:8053", "1.1.1.1:53"}
	opts.Domains = []string{"example.com"}

	assert.Equal(t, 2, len(opts.BaseResolvers))
	assert.Contains(t, opts.BaseResolvers, "127.0.0.1:8053")
}
