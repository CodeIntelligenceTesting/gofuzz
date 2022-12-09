package initial

import (
	"fmt"
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"io/fs"
	"path/filepath"
)

func traversPath(root, subDirToSkip string) error {
	err := goSanitizers.FilepathWalk(0, root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("prevent panic by handling failure accessing a path %q: %v\n", path, err)
			return err
		}
		if info.IsDir() && info.Name() == subDirToSkip {
			fmt.Printf("skipping a dir without errors: %+v \n", info.Name())
			return filepath.SkipDir
		}
		fmt.Printf("visited file or dir: %q\n", path)
		return nil
	})
	if err != nil {
		fmt.Printf("error walking the path %q: %v\n", root, err)
	}
	return err
}
