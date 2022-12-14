package hook_test

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/sanitize"
	"github.com/CodeIntelligenceTesting/gofuzz/pkg/hook"
)

func mockFakePC(n ast.Node, file string, fSet *token.FileSet) *ast.BasicLit {
	return &ast.BasicLit{
		Kind:  token.INT,
		Value: "0",
	}
}

func TestTransformer(t *testing.T) { packagestest.TestAll(t, testTransformer) }

func testTransformer(t *testing.T, exporter packagestest.Exporter) {
	hook.RegisterDefaultHooks()
	hook.RegisterFunctionHook("Println", "fmt", "FakePrintln")

	load := func(name string) string {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			return strings.Replace(string(data), "\r\n", "\n", -1)
		}
		return string(data)
	}
	exported := packagestest.Export(t, exporter, []packagestest.Module{
		{
			Name: "github.com/initial",
			Files: map[string]interface{}{
				"cmd.go":      load("testdata/github.com/initial/cmd.go"),
				"filepath.go": load("testdata/github.com/initial/filepath.go"),
				"fs.go":       load("testdata/github.com/initial/fs.go"),
				"open.go":     load("testdata/github.com/initial/open.go"),
				"path.go":     load("testdata/github.com/initial/path.go"),
				"sql.go":      load("testdata/github.com/initial/sql.go"),
				"template.go": load("testdata/github.com/initial/template.go"),
			},
		},
		{
			Name: "github.com/transformed",
			Files: map[string]interface{}{
				"cmd.go":      load("testdata/github.com/transformed/cmd.go"),
				"filepath.go": load("testdata/github.com/transformed/filepath.go"),
				"fs.go":       load("testdata/github.com/transformed/fs.go"),
				"open.go":     load("testdata/github.com/transformed/open.go"),
				"path.go":     load("testdata/github.com/transformed/path.go"),
				"sql.go":      load("testdata/github.com/transformed/sql.go"),
				"template.go": load("testdata/github.com/transformed/template.go"),
			},
		},
	})
	defer exported.Cleanup()

	exported.Config.Mode = sanitize.NeededLoadMode()
	pkgs, err := packages.Load(exported.Config, "github.com/initial")
	assert.NoError(t, err)
	assert.NotNil(t, pkgs)

	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			origFile := filepath.Base(pkg.CompiledGoFiles[i])

			transformer := hook.NewTransformer(file, pkg.Fset, origFile, pkg.TypesInfo, mockFakePC)
			transformed := transformer.TransformFile()
			assert.Equal(t, transformed, transformed)

			var after bytes.Buffer
			err = format.Node(&after, pkg.Fset, file)
			assert.NoError(t, err)

			transformedFile := exported.File("github.com/transformed", origFile)
			assert.Equal(t, load(transformedFile), after.String())
		}
	}
}
