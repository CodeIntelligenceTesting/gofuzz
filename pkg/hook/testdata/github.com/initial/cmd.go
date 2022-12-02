package initial

import (
	"os/exec"
)

func ExecuteArbitraryCommand(data []byte) bool {
	cmd := exec.Command(string(data))
	return cmd.Run() != nil
}
