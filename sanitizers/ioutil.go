package sanitizers

import (
	"io/fs"
	"io/ioutil"
	"os"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func IoutilReadDir(hookId int, dirname string) ([]fs.FileInfo, error) {
	detectors.NewPathTraversal(hookId, dirname).Detect()
	return ioutil.ReadDir(dirname)
}

func IoutilReadFile(hookId int, filename string) ([]byte, error) {
	detectors.NewPathTraversal(hookId, filename).Detect()
	return ioutil.ReadFile(filename)
}

func IoutilWriteFile(hookId int, filename string, data []byte, perm fs.FileMode) error {
	detectors.NewPathTraversal(hookId, filename).Detect()
	return ioutil.WriteFile(filename, data, perm)
}

func IoutilTempFile(hookId int, dir, pattern string) (*os.File, error) {
	detectors.NewPathTraversal(hookId, dir).Detect()
	return ioutil.TempFile(dir, pattern)
}

func IoutilTempDir(hookId int, dir, pattern string) (string, error) {
	detectors.NewPathTraversal(hookId, dir).Detect()
	return ioutil.TempDir(dir, pattern)
}
