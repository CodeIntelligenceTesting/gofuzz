package initial

import (
	"io/fs"
	"os"
	"path/filepath"
)

func walkDir(dir, name string) (int, error) {
	var count int
	fsys := os.DirFS(dir)
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if filepath.Ext(p) == ".go" {
			count++
		}
		return nil
	})
	_, err := fsys.Open(name)
	return count, err
}
