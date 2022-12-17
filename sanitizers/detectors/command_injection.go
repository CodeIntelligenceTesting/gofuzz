package detectors

import (
	"errors"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilCommand = "evil_command"

var CommandInjectionError = errors.New("Command injection error")

func (dc *DetectorClass) DetectCommandInjection() *DetectorClass {
	baseCommand := filepath.Base(dc.cmd)
	if baseCommand == evilCommand {
		dc.detect = true
	}
	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, dc.id)
	return dc
}

func (dc *DetectorClass) ReportCommandInjection() {
	if dc.detect {
		reporter.ReportFinding(CommandInjectionError.Error())
	}
}
