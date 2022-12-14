package sanitizers

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

/*
Some functions of interest take two path parameters that we need to check for path traversal.
To that end, we need to provide unique hook IDs so that they appear as two distinct string comparisons
to libFuzzer. Since these IDs are generated when instrumenting the code and each hook gets
a single ID, we need to mutate this ID for the second path parameter. Under the hoods, we call
libFuzzer hooks which can use the caller's PC (the hookId parameter in our case) to compute
1) an array index to store the comparison and 2) a value to store in the value profile map
(https://github.com/llvm/llvm-project/blob/3ec6c997c67d685c533b8c9c2cffde31d834b821/compiler-rt/lib/fuzzer/FuzzerTracePC.cpp#L374).
For the second parameter we multiply the original hook ID by 31. We choose 31 because it is a prime number
and that helps to get fewer collisions. It also has the advantage that the corresponding multiplication
can be efficiently computed 31 * i == (i << 5) - i, which is the actual code that the Go compiler emits
for this multiplication
(See https://stackoverflow.com/questions/299304/why-does-javas-hashcode-in-string-use-31-as-a-multiplier).
*/

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

func OsDirFS(hookId int, dir string) fs.FS {
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
		ReportFindingf("Path Traversal: vulnerable path %q", path)
	}
}
