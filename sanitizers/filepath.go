package sanitizers

import (
	"io/fs"
	"path/filepath"
)

func FilepathWalk(hookId int, root string, fn filepath.WalkFunc) error {
	checkForPathTraversal(hookId, root)
	return filepath.Walk(root, fn)
}

func FilepathWalkDir(hookId int, root string, fn fs.WalkDirFunc) error {
	checkForPathTraversal(hookId, root)
	return filepath.WalkDir(root, fn)
}
