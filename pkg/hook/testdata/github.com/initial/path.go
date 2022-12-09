package initial

import (
	"io/ioutil"
	"os"
)

func openFile(name string) {
	if _, err := os.OpenFile(name, os.O_RDWR, 0); err != nil {
		panic(err)
	}
}

func readFile(name string, useIoutil bool) ([]byte, error) {
	if useIoutil {
		return ioutil.ReadFile(name)
	} else {
		return os.ReadFile(name)
	}
}

func writeFile(name string, data []byte, perm os.FileMode, useIoutil bool) error {
	if useIoutil {
		return ioutil.WriteFile(name, data, perm)
	} else {
		return os.WriteFile(name, data, perm)
	}
}
