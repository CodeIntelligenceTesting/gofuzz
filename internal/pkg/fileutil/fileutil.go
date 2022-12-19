package fileutil

import (
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
)

func SaveASTFile(file *ast.File, fSet *token.FileSet, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(path), 0o755)
		if err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	return printer.Fprint(f, fSet, file)
}
