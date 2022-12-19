package sanitizers

import (
	"os"
	"os/exec"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	detectors.CIDect.New(hookId, cmd, nil, nil).Detect()
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	detectors.CIDect.New(hookId, cmd, nil, nil).Detect()
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	detectors.CIDect.New(hookId, cmd, nil, nil).Detect()
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	detectors.CIDect.New(hookId, cmd, nil, nil).Detect()
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	detectors.CIDect.New(hookId, name, nil, nil).Detect()
	return os.StartProcess(name, argv, attr)
}
