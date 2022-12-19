package sanitizers

import (
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
	"io/fs"
	"path/filepath"
)

func FilepathWalk(hookId int, root string, fn filepath.WalkFunc) error {
	detectors.PTDect.New(hookId, root, nil, nil).Detect()
	return filepath.Walk(root, fn)
}

func FilepathWalkDir(hookId int, root string, fn fs.WalkDirFunc) error {
	detectors.PTDect.New(hookId, root, nil, nil).Detect()
	return filepath.WalkDir(root, fn)
}
