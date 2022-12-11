package log

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func log(logType string, a ...any) {
	s := fmt.Sprint(a...)
	if logType != "" {
		s = logType + ": " + s
	}
	if len(s) == 0 || s[len(s)-1] != '\n' {
		s += "\n"
	}
	_, _ = fmt.Fprint(os.Stderr, s)
}

// Successf highlights a message as successful
func Successf(format string, a ...any) {
	Success(fmt.Sprintf(format, a...))
}

func Success(a ...any) {
	log("SUCCESS", a...)
}

// Warnf highlights a message as a warning
func Warnf(format string, a ...any) {
	Warn(fmt.Sprintf(format, a...))
}

func Warn(a ...any) {
	log("WARN", a...)
}

// Errorf highlights a message as an error and shows the stack strace if the --verbose flag is active
func Errorf(err error, format string, a ...any) {
	Error(err, fmt.Sprintf(format, a...))
}

func Error(err error, a ...any) {
	// If no message is provided, print the message of the error
	if len(a) == 0 {
		a = []any{err.Error()}
	}
	log("ERROR", a...)

	if viper.GetBool("verbose") {
		type stackTracer interface {
			StackTrace() errors.StackTrace
		}
		var st stackTracer
		if errors.As(err, &st) {
			log("", fmt.Sprintf("%+v", st.StackTrace()))
		}
	}
}

func Infof(format string, a ...any) {
	Info(fmt.Sprintf(format, a...))
}

func Info(a ...any) {
	log("INFO", a...)
}

// Debugf outputs additional information when the --verbose flag is active
func Debugf(format string, a ...any) {
	Debug(fmt.Sprintf(format, a...))
}

func Debug(a ...any) {
	if viper.GetBool("verbose") {
		log("DEBUG", a...)
	}
}
