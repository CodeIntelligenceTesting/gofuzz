package sanitizers

import (
	"errors"
	"os"
	"os/exec"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func reportOnDetection(hookId int, cmd interface{}) {
	var err error
	var detectorFaultType string
	switch v := cmd.(type) {
	case string:
		detectorFaultType, err = detectors.NewCommandInjection(hookId, v).Detect()
	case *exec.Cmd:
		detectorFaultType, err = detectors.NewCommandInjection(hookId, v.Path).Detect()
	}
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding(detectorFaultType)
	}
}

func CmdCombinedOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	reportOnDetection(hookId, cmd)
	return cmd.CombinedOutput()
}

func CmdOutput(hookId int, cmd *exec.Cmd) ([]byte, error) {
	reportOnDetection(hookId, cmd)
	return cmd.Output()
}

func CmdRun(hookId int, cmd *exec.Cmd) error {
	reportOnDetection(hookId, cmd)
	return cmd.Run()
}

func CmdStart(hookId int, cmd *exec.Cmd) error {
	reportOnDetection(hookId, cmd)
	return cmd.Start()
}

func OsStartProcess(hookId int, name string, argv []string, attr *os.ProcAttr) (*os.Process, error) {
	reportOnDetection(hookId, name)
	return os.StartProcess(name, argv, attr)
}
