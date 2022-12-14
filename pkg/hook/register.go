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

	RegisterFunctionHook("StartProcess", "os", "OsStartProcess")

	// Hooks for template injection bugs
	RegisterMethodHook("Execute", "*html/template.Template", "HtmlTemplateExecute")
	RegisterMethodHook("ExecuteTemplate", "*html/template.Template", "HtmlTemplateExecuteTemplate")
	RegisterMethodHook("Execute", "*text/template.Template", "TextTemplateExecute")
	RegisterMethodHook("ExecuteTemplate", "*text/template.Template", "TextTemplateExecuteTemplate")

	// Hooks for path traversal bugs
	RegisterFunctionHook("Chdir", "os", "OsChdir")
	RegisterFunctionHook("Chmod", "os", "OsChmod")
	RegisterFunctionHook("Chown", "os", "OsChown")
	RegisterFunctionHook("Chtimes", "os", "OsChtimes")
	RegisterFunctionHook("Create", "os", "OsCreate")
	RegisterFunctionHook("CreateTemp", "os", "OsCreateTemp")
	RegisterFunctionHook("DirFS", "os", "OsDirFS")
	RegisterFunctionHook("Lchown", "os", "OsLchown")
	RegisterFunctionHook("Link", "os", "OsLink")
	RegisterFunctionHook("Lstat", "os", "OsLstat")
	RegisterFunctionHook("Mkdir", "os", "OsMkdir")
	RegisterFunctionHook("MkdirAll", "os", "OsMkdirAll")
	RegisterFunctionHook("MkdirTemp", "os", "OsMkdirTemp")
	RegisterFunctionHook("NewFile", "os", "OsNewFile")
	RegisterFunctionHook("Open", "os", "OsOpen")
	RegisterFunctionHook("OpenFile", "os", "OsOpenFile")
	RegisterFunctionHook("ReadDir", "os", "OsReadDir")
	RegisterFunctionHook("ReadFile", "os", "OsReadFile")
	RegisterFunctionHook("Readlink", "os", "OsReadlink")
	RegisterFunctionHook("Remove", "os", "OsRemove")
	RegisterFunctionHook("RemoveAll", "os", "OsRemoveAll")
	RegisterFunctionHook("Rename", "os", "OsRename")
	RegisterFunctionHook("Stat", "os", "OsStat")
	RegisterFunctionHook("Symlink", "os", "OsSymlink")
	RegisterFunctionHook("Truncate", "os", "OsTruncate")
	RegisterFunctionHook("WriteFile", "os", "OsWriteFile")
}
