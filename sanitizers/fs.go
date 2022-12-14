package sanitizers

import "io/fs"

func FsFileInfoToDirEntry(hookId int, info fs.FileInfo) fs.DirEntry {
	checkForPathTraversal(hookId, info.Name())
	return fs.FileInfoToDirEntry(info)
}

func FsReadDir(hookId int, fsys fs.FS, name string) ([]fs.DirEntry, error) {
	checkForPathTraversal(hookId, name)
	return fs.ReadDir(fsys, name)
}

func FsReadFile(hookId int, fsys fs.FS, name string) ([]byte, error) {
	checkForPathTraversal(hookId, name)
	return fs.ReadFile(fsys, name)
}

func FsStat(hookId int, fsys fs.FS, name string) (fs.FileInfo, error) {
	checkForPathTraversal(hookId, name)
	return fs.Stat(fsys, name)
}

func FsSub(hookId int, fsys fs.FS, dir string) (fs.FS, error) {
	checkForPathTraversal(hookId, dir)
	return fs.Sub(fsys, dir)
}

func FsWalkDir(hookId int, fsys fs.FS, root string, fn fs.WalkDirFunc) error {
	checkForPathTraversal(hookId, root)
	return fs.WalkDir(fsys, root, fn)
}

func FsOpen(hookId int, fsys fs.FS, name string) (fs.File, error) {
	checkForPathTraversal(hookId, name)
	return fsys.Open(name)
}
