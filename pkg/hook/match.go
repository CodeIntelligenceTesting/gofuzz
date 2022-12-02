package hook

func MatchingFunctionHook(function, pkg string) *FunctionHook {
	for _, hook := range hooks.Functions {
		if hook.PackagePath == pkg && hook.FunctionName == function {
			return &hook
		}
	}
	return nil
}

func MatchingMethodHook(method, receiverType string) *MethodHook {
	for _, hook := range hooks.Methods {
		if hook.MethodName == method && hook.ReceiverType == receiverType {
			return &hook
		}
	}
	return nil
}
