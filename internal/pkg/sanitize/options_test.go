package sanitize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldInstrument(t *testing.T) {
	type test struct {
		opts    Options
		allowed []string
		denied  []string
	}
	tests := []test{
		{
			opts: Options{
				Include: []string{"*"},
				Exclude: []string{},
			},
			allowed: []string{
				"github.com/pkg/a",
				"filepath",
				"os/exec",
			},
			denied: []string{},
		}, {
			opts: Options{
				Include: []string{"github.com/parse*"},
				Exclude: []string{"github.com/parse_tests*"},
			},
			allowed: []string{
				"github.com/parse/a",
				"github.com/parse/a/b",
				"github.com/parse_all",
				"github.com/parse_testimonial",
			},
			denied: []string{
				"filepath",
				"os/exec",
				"github.com/parse_tests",
				"github.com/parse_tests1",
				"github.com/parse_tests/a",
			},
		},
	}

	for _, tc := range tests {
		for _, pkg := range tc.allowed {
			assert.True(t, tc.opts.shouldSanitize(pkg))
		}
		for _, pkg := range tc.denied {
			assert.False(t, tc.opts.shouldSanitize(pkg))
		}
	}
}
