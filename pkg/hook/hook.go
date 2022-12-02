package hook

const (
	sanitizersPackagePath = "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	sanitizersPackageName = "goSanitizers"
)

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
