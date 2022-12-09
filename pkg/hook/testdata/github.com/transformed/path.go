package initial

import (
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	"os"
)

func openFile(name string) {
	if _, err := goSanitizers.OsOpenFile(0, name, os.O_RDWR, 0); err != nil {
		panic(err)
	}
}

func readFile(name string, useIoutil bool) ([]byte, error) {
	if useIoutil {
		return goSanitizers.IoutilReadFile(0, name)
	} else {
		return goSanitizers.OsReadFile(0, name)
	}
}

func writeFile(name string, data []byte, perm os.FileMode, useIoutil bool) error {
	if useIoutil {
		return goSanitizers.IoutilWriteFile(0, name, data, perm)
	} else {
		return goSanitizers.OsWriteFile(0, name, data, perm)
	}
}
