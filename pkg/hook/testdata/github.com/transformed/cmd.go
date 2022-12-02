package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"os/exec"
)

func ExecuteArbitraryCommand(data []byte) bool {
	cmd := exec.Command(string(data))
	return goSanitizers.CommandRunHook(0, cmd) != nil
}
