package detectors

import (
	"path/filepath"
	"strings"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

var dotDotPath = filepath.Join("..", "..", "evil_path")

var _ Detector = (*PathTraversal)(nil)

type PathTraversal struct {
	id   int    // Numeric identifier to distinguish between the detectors for the various call sites
	path string // Path passed to a file API function
}

func (pt *PathTraversal) Detect() {
	if strings.Contains(pt.path, dotDotPath) {
		reporter.ReportFindingf("Path Traversal: vulnerable path %q", pt.path)
	}
	fuzzer.GuideTowardsContainment(pt.path, dotDotPath, pt.id)
}

func NewPathTraversal(id int, path string) *PathTraversal {
	return &PathTraversal{id, path}
}
