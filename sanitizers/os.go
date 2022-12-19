package sanitizers

import (
	"io/fs"
	"os"
	"time"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

var pt_os detectors.Detectors = detectors.PathTraversal

func OsChdir(hookId int, dir string) error {
	pt_os.New(hookId, dir, nil, nil).Detect()
	return os.Chdir(dir)
}

func OsChmod(hookId int, name string, mode os.FileMode) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Chmod(name, mode)
}

func OsChown(hookId int, name string, uid, gid int) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Chown(name, uid, gid)
}

func OsLchown(hookId int, name string, uid, gid int) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Lchown(name, uid, gid)
}

func OsCreate(hookId int, name string) (*os.File, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Create(name)
}

func OsCreateTemp(hookId int, dir, pattern string) (*os.File, error) {
	pt_os.New(hookId, dir, nil, nil).Detect()
	return os.CreateTemp(dir, pattern)
}

func OsDirFs(hookId int, dir string) fs.FS {
	pt_os.New(hookId, dir, nil, nil).Detect()
	return os.DirFS(dir)
}

func OsChtimes(hookId int, name string, atime time.Time, mtime time.Time) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Chtimes(name, atime, mtime)
}

func OsLink(hookId int, oldname, newname string) error {
	pt_os.New(hookId, oldname, nil, nil).Detect()
	pt_os.New(hookId*31, newname, nil, nil).Detect()
	return os.Link(oldname, newname)
}

func OsLstat(hookId int, name string) (os.FileInfo, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Lstat(name)
}

func OsMkdirTemp(hookId int, dir, pattern string) (string, error) {
	pt_os.New(hookId, dir, nil, nil).Detect()
	return os.MkdirTemp(dir, pattern)
}

func OsMkdir(hookId int, name string, perm os.FileMode) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Mkdir(name, perm)
}

func OsMkdirAll(hookId int, name string, perm os.FileMode) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.MkdirAll(name, perm)
}

func OsNewFile(hookId int, fd uintptr, name string) *os.File {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.NewFile(fd, name)
}

func OsOpen(hookId int, name string) (*os.File, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Open(name)
}

func OsOpenFile(hookId int, name string, flag int, perm os.FileMode) (*os.File, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.OpenFile(name, flag, perm)
}

func OsReadFile(hookId int, name string) ([]byte, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.ReadFile(name)
}

func OsReadDir(hookId int, name string) ([]os.DirEntry, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.ReadDir(name)
}

func OsReadLink(hookId int, name string) (string, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Readlink(name)
}

func OsRename(hookId int, oldpath, newpath string) error {
	pt_os.New(hookId, oldpath, nil, nil).Detect()
	pt_os.New(hookId*31, newpath, nil, nil).Detect()
	return os.Rename(oldpath, newpath)
}

func OsRemove(hookId int, name string) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Remove(name)
}

func OsRemoveAll(hookId int, path string) error {
	pt_os.New(hookId, path, nil, nil).Detect()
	return os.RemoveAll(path)
}

func OsStat(hookId int, name string) (os.FileInfo, error) {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Stat(name)
}

func OsSymlink(hookId int, oldname, newname string) error {
	pt_os.New(hookId, oldname, nil, nil).Detect()
	pt_os.New(hookId*31, newname, nil, nil).Detect()
	return os.Symlink(oldname, newname)
}

func OsTruncate(hookId int, name string, size int64) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.Truncate(name, size)
}

func OsWriteFile(hookId int, name string, data []byte, perm os.FileMode) error {
	pt_os.New(hookId, name, nil, nil).Detect()
	return os.WriteFile(name, data, perm)
}
