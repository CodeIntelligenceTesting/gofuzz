package sanitizers

import (
	"io/fs"
	"io/ioutil"
	"os"
)

func IoutilReadDir(hookId int, dirname string) ([]fs.FileInfo, error) {
	checkForPathTraversal(hookId, dirname)
	return ioutil.ReadDir(dirname)
}

func IoutilReadFile(hookId int, filename string) ([]byte, error) {
	checkForPathTraversal(hookId, filename)
	return ioutil.ReadFile(filename)
}

func IoutilWriteFile(hookId int, filename string, data []byte, perm fs.FileMode) error {
	checkForPathTraversal(hookId, filename)
	return ioutil.WriteFile(filename, data, perm)
}

func IoutilTempFile(hookId int, dir, pattern string) (*os.File, error) {
	checkForPathTraversal(hookId, dir)
	return ioutil.TempFile(dir, pattern)
}

func IoutilTempDir(hookId int, dir, pattern string) (string, error) {
	checkForPathTraversal(hookId, dir)
	return ioutil.TempDir(dir, pattern)
}
