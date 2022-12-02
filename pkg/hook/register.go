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
	// Hooks for SQL injection bugs
	RegisterMethodHook("ExecContext", "*database/sql.Conn", "ConnExecContext")
	RegisterMethodHook("PrepareContext", "*database/sql.Conn", "ConnPrepareContext")
	RegisterMethodHook("QueryContext", "*database/sql.Conn", "ConnQueryContext")
	RegisterMethodHook("QueryRowContext", "*database/sql.Conn", "ConnQueryRowContext")

	RegisterMethodHook("Exec", "*database/sql.DB", "DbExec")
	RegisterMethodHook("ExecContext", "*database/sql.DB", "DbExecContext")
	RegisterMethodHook("Prepare", "*database/sql.DB", "DbPrepare")
	RegisterMethodHook("PrepareContext", "*database/sql.DB", "DbPrepareContext")
	RegisterMethodHook("Query", "*database/sql.DB", "DbQuery")
	RegisterMethodHook("QueryContext", "*database/sql.DB", "DbQueryContext")
	RegisterMethodHook("QueryRow", "*database/sql.DB", "DbQueryRow")
	RegisterMethodHook("QueryRowContext", "*database/sql.DB", "DbQueryRowContext")

	RegisterMethodHook("Exec", "*database/sql.Stmt", "StmtExec")
	RegisterMethodHook("ExecContext", "*database/sql.Stmt", "StmtExecContext")
	RegisterMethodHook("Query", "*database/sql.Stmt", "StmtQuery")
	RegisterMethodHook("QueryContext", "*database/sql.Stmt", "StmtQueryContext")
	RegisterMethodHook("QueryRow", "*database/sql.Stmt", "StmtQueryRow")
	RegisterMethodHook("QueryRowContext", "*database/sql.Stmt", "StmtQueryRowContext")

	RegisterMethodHook("Exec", "*database/sql.Tx", "TxExec")
	RegisterMethodHook("ExecContext", "*database/sql.Tx", "TxExecContext")
	RegisterMethodHook("Prepare", "*database/sql.Tx", "TxPrepare")
	RegisterMethodHook("PrepareContext", "*database/sql.Tx", "TxPrepareContext")
	RegisterMethodHook("Query", "*database/sql.Tx", "TxQuery")
	RegisterMethodHook("QueryContext", "*database/sql.Tx", "TxQueryContext")
	RegisterMethodHook("QueryRow", "*database/sql.Tx", "TxQueryRow")
	RegisterMethodHook("QueryRowContext", "*database/sql.Tx", "TxQueryRowContext")

	// Hooks for command injections bugs
	RegisterMethodHook("CombinedOutput", "*os/exec.Cmd", "CmdCombinedOutput")
	RegisterMethodHook("Output", "*os/exec.Cmd", "CmdOutput")
	RegisterMethodHook("Run", "*os/exec.Cmd", "CmdRun")
	RegisterMethodHook("Start", "*os/exec.Cmd", "CmdStart")
}
