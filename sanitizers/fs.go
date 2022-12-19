package sanitizers

import (
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
	"io/fs"
)

func FsFileInfoToDirEntry(hookId int, info fs.FileInfo) fs.DirEntry {
	detectors.PTDect.New(hookId, info.Name(), nil, nil)
	return fs.FileInfoToDirEntry(info)
}

func FsReadDir(hookId int, fsys fs.FS, name string) ([]fs.DirEntry, error) {
	detectors.PTDect.New(hookId, name, nil, nil)
	return fs.ReadDir(fsys, name)
}

func FsReadFile(hookId int, fsys fs.FS, name string) ([]byte, error) {
	detectors.PTDect.New(hookId, name, nil, nil)
	return fs.ReadFile(fsys, name)
}

func FsStat(hookId int, fsys fs.FS, name string) (fs.FileInfo, error) {
	detectors.PTDect.New(hookId, name, nil, nil)
	return fs.Stat(fsys, name)
}

func FsSub(hookId int, fsys fs.FS, dir string) (fs.FS, error) {
	detectors.PTDect.New(hookId, dir, nil, nil)
	return fs.Sub(fsys, dir)
}

func FsWalkDir(hookId int, fsys fs.FS, root string, fn fs.WalkDirFunc) error {
	detectors.PTDect.New(hookId, root, nil, nil)
	return fs.WalkDir(fsys, root, fn)
}

func FsOpen(hookId int, fsys fs.FS, name string) (fs.File, error) {
	detectors.PTDect.New(hookId, name, nil, nil)
	return fsys.Open(name)
}
