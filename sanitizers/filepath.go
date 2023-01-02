package sanitizers

import (
	"io/fs"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func FilepathWalk(hookId int, root string, fn filepath.WalkFunc) error {
	detectors.NewPathTraversal(hookId, root).Detect()
	return filepath.Walk(root, fn)
}

func FilepathWalkDir(hookId int, root string, fn fs.WalkDirFunc) error {
	detectors.NewPathTraversal(hookId, root).Detect()
	return filepath.WalkDir(root, fn)
}
