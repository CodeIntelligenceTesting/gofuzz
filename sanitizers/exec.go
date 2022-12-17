package sanitizers

import (
	"os"
	"os/exec"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

var ci detectors.Detectors = detectors.CommandInjection

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	ci.New(hookId, cmd, nil, nil).Detect()
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	ci.New(hookId, cmd, nil, nil).Detect()
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	ci.New(hookId, cmd, nil, nil).Detect()
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	ci.New(hookId, cmd, nil, nil).Detect()
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	ci.New(hookId, name, nil, nil).Detect()
	return os.StartProcess(name, argv, attr)
}
