package fileutil

import (
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
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

func RelativePathInModule(module, file string) (string, error) {
	rel, err := filepath.Rel(module, file)
	if strings.HasPrefix(rel, "..") {
		return "", errors.Errorf("Failed to make %q relative to %q", file, module)
	}
	return rel, err
}
