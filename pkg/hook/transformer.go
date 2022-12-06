package hook

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"

	"golang.org/x/tools/go/ast/astutil"
)

type Transformer struct {
	file               *ast.File
	fileSet            *token.FileSet
	filePath           string
	typeInfo           *types.Info
	transformedImports map[string]string
	hookIdFn           IdFunction
	numAddedHooks      int
}

func NewTransformer(file *ast.File, fileSet *token.FileSet, filePath string, typeInfo *types.Info, hookIdFn IdFunction) *Transformer {
	return &Transformer{
		file:               file,
		fileSet:            fileSet,
		filePath:           filePath,
		typeInfo:           typeInfo,
		transformedImports: make(map[string]string),
		hookIdFn:           hookIdFn,
		numAddedHooks:      0,
	}
}

func (t *Transformer) TransformFile() int {
	astutil.Apply(t.file, nil, func(cursor *astutil.Cursor) bool {
		callExpr, ok := cursor.Node().(*ast.CallExpr)
		if !ok {
			return true
		}

		selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		receiver := selectorExpr.X

		if pkgName, pkgPath, ok := importedPackage(receiver, t.file); ok {
			if h := MatchingFunctionHook(selectorExpr.Sel.Name, pkgPath); h != nil {
				selectorExpr.Sel.Name = h.HookName
				selectorExpr.X = &ast.Ident{
					Name: sanitizersPackageName,
				}
				callExpr.Args = append([]ast.Expr{t.hookIdFn(callExpr, t.filePath, t.fileSet)}, callExpr.Args...)

				astutil.AddNamedImport(t.fileSet, t.file, sanitizersPackageName, sanitizersPackagePath)

				t.transformedImports[pkgPath] = pkgName
				t.numAddedHooks += 1
			}
		} else if receiverType := t.typeInfo.Types[receiver]; receiverType.IsValue() {
			if h := MatchingMethodHook(selectorExpr.Sel.Name, receiverType.Type.String()); h != nil {
				selectorExpr.Sel.Name = h.HookName
				selectorExpr.X = &ast.Ident{
					Name: sanitizersPackageName,
				}
				callExpr.Args = append([]ast.Expr{t.hookIdFn(callExpr, t.filePath, t.fileSet), receiver}, callExpr.Args...)
				astutil.AddNamedImport(t.fileSet, t.file, sanitizersPackageName, sanitizersPackagePath)
				t.numAddedHooks += 1
			}
		}

		return true
	})

	if t.numAddedHooks > 0 {
		t.removeUnusedImport()
	}
	return t.numAddedHooks
}

func (t *Transformer) removeUnusedImport() {
	for path, name := range t.transformedImports {
		if !astutil.UsesImport(t.file, path) {
			astutil.DeleteNamedImport(t.fileSet, t.file, name, path)
		}
	}
}

func importedPackage(expr ast.Expr, file *ast.File) (name string, path string, found bool) {
	// the package part of function call expressions (e.g., os.Open()) is an identifier
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	// package identifiers should top-level unresolved identifiers
	if ident.Obj != nil {
		return "", "", false
	}

	for _, importSpec := range file.Imports {
		// remove the quotations from the AST string value of the import path
		importPath, err := strconv.Unquote(importSpec.Path.Value)
		if err != nil {
			return "", "", false
		}

		var importName string
		if importSpec.Name != nil {
			// handle named imports: import newMyPkg "github.com/myMod/myPkg".
			// In this case importSpec.Name = "newMyPkg" and newMyPkg will be the identifier
			// used to call functions exported by the package: newMyPkg.Foo()
			importName = importSpec.Name.Name
			name = importName
		} else {
			// handle unnamed imports: import "github.com/myMod/myPkg"
			// In this case myPkg will be the identifier used to call functions exported
			// by the package: myPkg.Foo()
			importName = filepath.Base(importPath)
			name = ""
		}

		if ident.Name == importName {
			found = true
			path = importPath
			return
		}

	}
	return "", "", false
}
