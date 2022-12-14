package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"io/fs"
	"path/filepath"
)

func walkDir(dir, name string) (int, error) {
	var count int
	fsys := goSanitizers.OsDirFS(0, dir)
	_ = goSanitizers.FsWalkDir(0, fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if filepath.Ext(p) == ".go" {
			count++
		}
		return nil
	})
	_, err := goSanitizers.FsOpen(0, fsys, name)
	return count, err
}
