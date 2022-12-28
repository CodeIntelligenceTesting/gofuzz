package sanitize

import "strings"

type Options struct {
	Include          []string
	Exclude          []string
	BuildFlags       []string
	OverwriteSources bool
}

func (opts *Options) shouldSanitize(pkgPath string) bool {
	for _, incPath := range opts.Include {
		if matchPattern(incPath, pkgPath) {
			for _, excPath := range opts.Exclude {
				if matchPattern(excPath, pkgPath) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func matchPattern(pattern, path string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return strings.EqualFold(path, pattern)
}
