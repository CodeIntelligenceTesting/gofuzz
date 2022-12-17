package detectors

import (
	"os/exec"
	"text/template/parse"
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
		dc.ReportTemplateInjection()
	case CommandInjection:
		dc.DetectCommandInjection()
	}

	return dc
}

func (dc *DetectorClass) Report() {
	switch dc.d {
	case SQLInjection:
		dc.ReportSQLI()
	case TemplateInjection:
		dc.ReportTemplateInjection()
	case CommandInjection:
		dc.ReportCommandInjection()
	}
}
