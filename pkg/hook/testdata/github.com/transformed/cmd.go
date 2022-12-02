package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"os/exec"
)

func ExecuteArbitraryCommand(data []byte, shouldWait bool) error {
	cmd := exec.Command(string(data))
	if shouldWait {
		return goSanitizers.CmdRun(0, cmd)
	} else {
		return goSanitizers.CmdStart(0, cmd)
	}
}

func ExecuteArbitraryCommandOutput(data []byte, shouldCombineOutput bool) ([]byte, error) {
	cmd := exec.Command(string(data))
	if shouldCombineOutput {
		return goSanitizers.CmdCombinedOutput(0, cmd)
	} else {
		return goSanitizers.CmdOutput(0, cmd)
	}
}
