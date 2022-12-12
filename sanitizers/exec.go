package sanitizers

import (
	"os"
	"os/exec"
	"path/filepath"
)

const evilCommand = "evil_command"

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	checkForEvilCommandAndGuideFuzzer(hookId, cmd.Path)
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	checkForEvilCommandAndGuideFuzzer(hookId, cmd.Path)
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	checkForEvilCommandAndGuideFuzzer(hookId, cmd.Path)
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	checkForEvilCommandAndGuideFuzzer(hookId, cmd.Path)
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	checkForEvilCommandAndGuideFuzzer(hookId, name)
	return os.StartProcess(name, argv, attr)
}

func checkForEvilCommandAndGuideFuzzer(hookId int, path string) {
	baseCommand := filepath.Base(path)
	if baseCommand == evilCommand {
		ReportFinding("Command Injection")
	} else {
		GuideTowardsEquality(baseCommand, evilCommand, hookId)
	}
}
