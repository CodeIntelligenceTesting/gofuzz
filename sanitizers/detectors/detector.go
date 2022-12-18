package detectors

import (
	"errors"
	"fmt"
	"os/exec"
	"text/template/parse"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

type Detectors int64

const (
	SQLInjection Detectors = iota
	TemplateInjection
	PathTraversal
	CommandInjection
)

func (d Detectors) String() string {
	return []string{"SQLInjection", "TemplateInjection", "PathTraversal", "CommandInjection"}[d]
}

type DetectorClass struct {
	d         Detectors   // Concrete Detector for this instance
	id        int         // Numeric identifier to distinguish between the detectors for the various call sites
	cmd       string      // The tampered with SQL query/cmd/path/...
	tree      *parse.Tree // Template injection specific field
	err       error       // Generic error handler
	extraArgs []any       // Any amount of extra parameters that are necessary for detection logic/report verbosity
}

func GetCommand(CmdType interface{}) string {
	var c string
	switch v := CmdType.(type) {
	case string:
		c = v
	case *exec.Cmd:
		c = v.Path
	default:
		c = ""
	}
	return c
}

func (d Detectors) New(id int, cmdType interface{}, treeType interface{}, err error, args ...any) *DetectorClass {
	var dc = DetectorClass{
		d:         d,
		id:        id,
		cmd:       GetCommand(cmdType),
		tree:      GetTree(treeType, args),
		err:       err,
		extraArgs: args,
	}
	return &dc
}

func (dc *DetectorClass) Detect() *DetectorClass {
	switch dc.d {
	case SQLInjection:
		dc.DetectSQLI()
	case TemplateInjection:
		dc.DetectTemplateInjection()
	case CommandInjection:
		dc.DetectCommandInjection()
	}
	return dc
}

func (dc *DetectorClass) Report() {
	var reportErr = fmt.Sprint("%s error", dc.d)
	switch dc.d {
	case SQLInjection:
		if errors.Is(dc.err, SQLInjectionError) {
			if len(dc.cmd) > 0 {
				reporter.ReportFindingf(": query %s, args [%s]", dc.cmd, fmt.Sprint(dc.extraArgs...))
			} else {
				reporter.ReportFindingf(": args [%s]", fmt.Sprint(dc.extraArgs...))
			}
		}
	case TemplateInjection, CommandInjection:
		reporter.ReportFinding(reportErr)
	}
}
