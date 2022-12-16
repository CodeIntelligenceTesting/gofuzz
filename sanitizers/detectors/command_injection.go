package detectors

import (
	"errors"
	"os/exec"
	"path/filepath"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilCommand = "evil_command"

var CommandInjectionError = errors.New("Command injection error")

type CommandInjection struct {
	DetectorClass
}

func (ci *CommandInjection) Detect() *CommandInjection {
	baseCommand := filepath.Base(ci.cmd)
	if baseCommand == evilCommand {
		ci.detect = true
	}
	fuzzer.GuideTowardsEquality(baseCommand, evilCommand, ci.id)
	return ci
}

func (ci *CommandInjection) Report() {
	if ci.detect {
		reporter.ReportFinding(CommandInjectionError.Error())
	}
}

func NewCommandInjection(id int, ctype interface{}) *CommandInjection {
	var c string
	switch v := ctype.(type) {
	case string:
		c = v
	case *exec.Cmd:
		c = v.Path
	}
	return &CommandInjection{
		DetectorClass: DetectorClass{
			id:     id,
			detect: false,
			cmd:    c,
			tree:   nil,
			err:    nil,
		},
	}
}
