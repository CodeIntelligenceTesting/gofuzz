package hook

var hooks = Hooks{
	Functions: []FunctionHook{},
	Methods:   []MethodHook{},
}

func RegisterFunctionHook(functionName, packagePath, hookName string) {
	hooks.Functions = append(hooks.Functions, FunctionHook{
		FunctionName: functionName,
		PackagePath:  packagePath,
		HookName:     hookName,
	})
}

func RegisterMethodHook(methodName, receiverType, hookName string) {
	hooks.Methods = append(hooks.Methods, MethodHook{
		MethodName:   methodName,
		ReceiverType: receiverType,
		HookName:     hookName,
	})
}

func RegisterDefaultHooks() {
	RegisterMethodHook("Run", "*os/exec.Cmd", "CommandRunHook")
}
