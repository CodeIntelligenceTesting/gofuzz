package sanitizers

import (
	"os/exec"
	"path/filepath"
)

const evilCommand = "evil_command"

func CommandRunHook(hookId int, cmd *exec.Cmd) error {
	if filepath.Base(cmd.Path) == evilCommand {
		ReportFinding("Command Injection")
	} else {
		GuideTowardsEquality(cmd.Path, evilCommand, hookId)
	}
	return cmd.Run()
}
