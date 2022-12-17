package detectors

import (
	"errors"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilCommand = "evil_command"

var CommandInjectionError = errors.New("Command injection error")

func (dc *DetectorClass) DetectCommandInjection() {
	baseCommand := filepath.Base(dc.cmd)
	if baseCommand == evilCommand {
		dc.ReportCommandInjection()
		return
	}
	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, dc.id)

}

func (dc *DetectorClass) ReportCommandInjection() {
	reporter.ReportFinding(CommandInjectionError.Error())
}
