package initial

import (
	"os/exec"
)

func ExecuteArbitraryCommand(data []byte, shouldWait bool) error {
	cmd := exec.Command(string(data))
	if shouldWait {
		return cmd.Run()
	} else {
		return cmd.Start()
	}
}

func ExecuteArbitraryCommandOutput(data []byte, shouldCombineOutput bool) ([]byte, error) {
	cmd := exec.Command(string(data))
	if shouldCombineOutput {
		return cmd.CombinedOutput()
	} else {
		return cmd.Output()
	}
}
