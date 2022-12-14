package detectors

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

var (
	dotDotPath         = filepath.Join("..", "..", "evil_path")
	PathTraversalError = errors.New("path traversal")
)

type PathTraversal struct {
	id   int    // numeric identifier to distinguish between the detectors for the various call sites
	path string // path passed to the file API function
}

// Make sure that the path traversal detector implements the Detector interface
var _ Detector = (*PathTraversal)(nil)

func (pt *PathTraversal) Detect() error {
	if strings.Contains(pt.path, dotDotPath) {
		return PathTraversalError
	}
	fuzzer.GuideTowardsContainment(pt.path, dotDotPath, pt.id)
	return nil
}

func NewPathTraversal(id int, path string) *PathTraversal {
	return &PathTraversal{
		id:   id,
		path: path,
	}
}
