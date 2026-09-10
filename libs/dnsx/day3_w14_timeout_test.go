package dnsx

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOptionsQueryTimeoutValidation(t *testing.T) {
	opts := DefaultOptions
	opts.Timeout = 10 * time.Second
	opts.Domains = []string{"timeout.example.com"}

	assert.Equal(t, 10*time.Second, opts.Timeout)
	assert.Equal(t, 1, len(opts.Domains))
}
