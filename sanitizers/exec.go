package sanitizers

import (
	"errors"
	"os"
	"os/exec"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func reportOnDetectionCI(hookId int, cmd interface{}) {
	var err error
	switch v := cmd.(type) {
	case string:
		err = detectors.NewCommandInjection(hookId, v).Detect()
	case *exec.Cmd:
		err = detectors.NewCommandInjection(hookId, v.Path).Detect()
	}
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding(err.Error())
	}
}

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	reportOnDetectionCI(hookId, cmd)
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	reportOnDetectionCI(hookId, cmd)
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	reportOnDetectionCI(hookId, cmd)
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	reportOnDetectionCI(hookId, cmd)
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	reportOnDetectionCI(hookId, name)
	return os.StartProcess(name, argv, attr)
}
