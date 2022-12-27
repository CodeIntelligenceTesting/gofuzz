package hook

import (
	"go/ast"
	"go/token"
)

const (
	sanitizersPackageName = "goSanitizers"
)

var sanitizersPackagePath = "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"

type FunctionHook struct {
	FunctionName string
	PackagePath  string
	HookName     string
}

type MethodHook struct {
	MethodName   string
	ReceiverType string
	HookName     string
}

type Hooks struct {
	Functions []FunctionHook
	Methods   []MethodHook
}

type IdFunction = func(n ast.Node, file string, fSet *token.FileSet) *ast.BasicLit

func SetSanitizersPackagePath(pkgPath string) {
	sanitizersPackagePath = pkgPath
}
