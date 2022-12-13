package detectors

import (
	"errors"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

const evilCommand = "evil_command"

var CommandInjectionError = errors.New("command injection error")

type CommandInjection struct {
	id   int    // numeric identifier to distinguish between the detectors for the various call sites
	path string // path of the command being executed
}

// Make sure that the command injection detector implements the Detector interface
var _ Detector = (*CommandInjection)(nil)

func (ci *CommandInjection) Detect() error {
	baseCommand := filepath.Base(ci.path)
	if baseCommand == evilCommand {
		return CommandInjectionError
	}

	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, ci.id)
	return nil
}

func NewCommandInjection(id int, path string) *CommandInjection {
	return &CommandInjection{
		id:   id,
		path: path,
	}
}
