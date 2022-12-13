package sanitizers

import (
	"errors"
	"os"
	"os/exec"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	err := detectors.NewCommandInjection(hookId, cmd.Path).Detect()
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding("Command Injection")
	}
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	err := detectors.NewCommandInjection(hookId, cmd.Path).Detect()
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding("Command Injection")
	}
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	err := detectors.NewCommandInjection(hookId, cmd.Path).Detect()
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding("Command Injection")
	}
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	err := detectors.NewCommandInjection(hookId, cmd.Path).Detect()
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding("Command Injection")
	}
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	err := detectors.NewCommandInjection(hookId, name).Detect()
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding("Command Injection")
	}
	return os.StartProcess(name, argv, attr)
}
