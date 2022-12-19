package sanitizers

import (
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
	"io/fs"
	"path/filepath"
)

var pt_fp detectors.Detectors = detectors.PathTraversal

func FilepathWalk(hookId int, root string, fn filepath.WalkFunc) error {
	pt_fp.New(hookId, root, nil, nil).Detect()
	return filepath.Walk(root, fn)
}

func FilepathWalkDir(hookId int, root string, fn fs.WalkDirFunc) error {
	pt_fp.New(hookId, root, nil, nil).Detect()
	return filepath.WalkDir(root, fn)
}
