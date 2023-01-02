package sanitizers

import (
	"io/fs"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func FsFileInfoToDirEntry(hookId int, info fs.FileInfo) fs.DirEntry {
	detectors.NewPathTraversal(hookId, info.Name()).Detect()
	return fs.FileInfoToDirEntry(info)
}

func FsReadDir(hookId int, fsys fs.FS, name string) ([]fs.DirEntry, error) {
	detectors.NewPathTraversal(hookId, name).Detect()
	return fs.ReadDir(fsys, name)
}

func FsReadFile(hookId int, fsys fs.FS, name string) ([]byte, error) {
	detectors.NewPathTraversal(hookId, name).Detect()
	return fs.ReadFile(fsys, name)
}

func FsStat(hookId int, fsys fs.FS, name string) (fs.FileInfo, error) {
	detectors.NewPathTraversal(hookId, name).Detect()
	return fs.Stat(fsys, name)
}

func FsSub(hookId int, fsys fs.FS, dir string) (fs.FS, error) {
	detectors.NewPathTraversal(hookId, dir).Detect()
	return fs.Sub(fsys, dir)
}

func FsWalkDir(hookId int, fsys fs.FS, root string, fn fs.WalkDirFunc) error {
	detectors.NewPathTraversal(hookId, root).Detect()
	return fs.WalkDir(fsys, root, fn)
}

func FsOpen(hookId int, fsys fs.FS, name string) (fs.File, error) {
	detectors.NewPathTraversal(hookId, name).Detect()
	return fsys.Open(name)
}
