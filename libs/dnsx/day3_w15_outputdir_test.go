package dnsx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsOutputDirValidation(t *testing.T) {
	opts := DefaultOptions
	opts.OutputFile = "/tmp/dnsx_results.txt"
	opts.Domains = []string{"out.example.com"}

	assert.Equal(t, "/tmp/dnsx_results.txt", opts.OutputFile)
	assert.Equal(t, 1, len(opts.Domains))
}
