package initial

import (
	"fmt"
)

func PrintFormatted(format string, data []byte) {
	if format == "" {
		fmt.Println(string(data))
	} else {
		fmt.Printf(format, string(data))
	}
}
