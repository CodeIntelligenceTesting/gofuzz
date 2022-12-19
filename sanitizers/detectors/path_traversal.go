package detectors

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

var (
	dotDotPath         string
	PathTraversalError = errors.New("path traversal")
)

func init() {
	dotDotPath = filepath.Join("..", "..", "evil_path")
}

func (dc *DetectorClass) DetectPathTraversal() {
	if strings.Contains(dc.cmd, dotDotPath) {
		dc.Report()
		return
	}
	fuzzer.GuideTowardsContainment(dc.cmd, dotDotPath, dc.id)
}
