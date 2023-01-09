package sanitizers

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

type Sanitizers []string

// We implement the Value interface so that we can store the sanitizers
// values in a flag. See: https://github.com/spf13/pflag/blob/2e9d26c8c37aae03e3f9d4e90b7116f5accb7cab/flag.go#L187

func (s *Sanitizers) String() string {
	return fmt.Sprint(*s)
}

func (s *Sanitizers) Set(v string) error {
	for _, san := range strings.Split(v, ",") {
		if slices.Contains(AllSanitizers, san) {
			*s = append(*s, san)
		} else {
			return errors.New(fmt.Sprintf("possible values are: %s", strings.Join(AllSanitizers, ",")))
		}
	}
	return nil
}

func (s *Sanitizers) Type() string {
	return "Sanitizers"
}
