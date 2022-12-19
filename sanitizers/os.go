package sanitizers

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func OsChdir(hookId int, dir string) error {
	checkForPathTraversal(hookId, dir)
	return os.Chdir(dir)
}

func OsChmod(hookId int, name string, mode os.FileMode) error {
	checkForPathTraversal(hookId, name)
	return os.Chmod(name, mode)
}

func OsChown(hookId int, name string, uid, gid int) error {
	checkForPathTraversal(hookId, name)
	return os.Chown(name, uid, gid)
}

func OsLchown(hookId int, name string, uid, gid int) error {
	checkForPathTraversal(hookId, name)
	return os.Lchown(name, uid, gid)
}

func OsCreate(hookId int, name string) (*os.File, error) {
	checkForPathTraversal(hookId, name)
	return os.Create(name)
}

func OsCreateTemp(hookId int, dir, pattern string) (*os.File, error) {
	checkForPathTraversal(hookId, dir)
	return os.CreateTemp(dir, pattern)
}

func OsDirFs(hookId int, dir string) fs.FS {
	checkForPathTraversal(hookId, dir)
	return os.DirFS(dir)
}

func OsChtimes(hookId int, name string, atime time.Time, mtime time.Time) error {
	checkForPathTraversal(hookId, name)
	return os.Chtimes(name, atime, mtime)
}

func OsLink(hookId int, oldname, newname string) error {
	checkForPathTraversal(hookId, oldname)
	checkForPathTraversal(hookId*31, newname)
	return os.Link(oldname, newname)
}

func OsLstat(hookId int, name string) (os.FileInfo, error) {
	checkForPathTraversal(hookId, name)
	return os.Lstat(name)
}

func OsMkdirTemp(hookId int, dir, pattern string) (string, error) {
	checkForPathTraversal(hookId, dir)
	return os.MkdirTemp(dir, pattern)
}

func OsMkdir(hookId int, name string, perm os.FileMode) error {
	checkForPathTraversal(hookId, name)
	return os.Mkdir(name, perm)
}

func OsMkdirAll(hookId int, name string, perm os.FileMode) error {
	checkForPathTraversal(hookId, name)
	return os.MkdirAll(name, perm)
}

func OsNewFile(hookId int, fd uintptr, name string) *os.File {
	checkForPathTraversal(hookId, name)
	return os.NewFile(fd, name)
}

func OsOpen(hookId int, name string) (*os.File, error) {
	checkForPathTraversal(hookId, name)
	return os.Open(name)
}

func OsOpenFile(hookId int, name string, flag int, perm os.FileMode) (*os.File, error) {
	checkForPathTraversal(hookId, name)
	return os.OpenFile(name, flag, perm)
}

func OsReadFile(hookId int, name string) ([]byte, error) {
	checkForPathTraversal(hookId, name)
	return os.ReadFile(name)
}

func OsReadDir(hookId int, name string) ([]os.DirEntry, error) {
	checkForPathTraversal(hookId, name)
	return os.ReadDir(name)
}

func OsReadLink(hookId int, name string) (string, error) {
	checkForPathTraversal(hookId, name)
	return os.Readlink(name)
}

func OsRename(hookId int, oldpath, newpath string) error {
	checkForPathTraversal(hookId, oldpath)
	checkForPathTraversal(hookId*31, newpath)
	return os.Rename(oldpath, newpath)
}

func OsRemove(hookId int, name string) error {
	checkForPathTraversal(hookId, name)
	return os.Remove(name)
}

func OsRemoveAll(hookId int, path string) error {
	checkForPathTraversal(hookId, path)
	return os.RemoveAll(path)
}

func OsStat(hookId int, name string) (os.FileInfo, error) {
	checkForPathTraversal(hookId, name)
	return os.Stat(name)
}

func OsSymlink(hookId int, oldname, newname string) error {
	checkForPathTraversal(hookId, oldname)
	checkForPathTraversal(hookId*31, newname)
	return os.Symlink(oldname, newname)
}

func OsTruncate(hookId int, name string, size int64) error {
	checkForPathTraversal(hookId, name)
	return os.Truncate(name, size)
}

func OsWriteFile(hookId int, name string, data []byte, perm os.FileMode) error {
	checkForPathTraversal(hookId, name)
	return os.WriteFile(name, data, perm)
}

func checkForPathTraversal(hookId int, path string) {
	err := detectors.NewPathTraversal(hookId, path).Detect()
	if errors.Is(err, detectors.PathTraversalError) {
		ReportFinding("Path Traversal")
	}
}
