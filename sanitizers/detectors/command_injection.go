package detectors

import (
	"errors"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

const evilCommand = "evil_command"

var CommandInjectionError = errors.New("Command injection error")

func (dc *DetectorClass) DetectCommandInjection() {
	baseCommand := filepath.Base(dc.cmd)
	if baseCommand == evilCommand {
		dc.Report()
		return
	}
	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, dc.id)

}
