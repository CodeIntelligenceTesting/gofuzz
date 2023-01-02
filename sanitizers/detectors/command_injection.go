package detectors

import (
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilCommand = "evil_command"

var _ Detector = (*CommandInjection)(nil)

type CommandInjection struct {
	id   int    // Numeric identifier to distinguish between the detectors for the various call sites
	path string // Path of the command being executed
}

func (ci *CommandInjection) Detect() {
	baseCommand := filepath.Base(ci.path)
	if baseCommand == evilCommand {
		reporter.ReportFinding("Command Injection")
	}
	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, ci.id)
}

func NewCommandInjection(id int, path string) *CommandInjection {
	return &CommandInjection{id, path}
}
