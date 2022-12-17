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
	d      Detectors   // Concrete Detector for this instance
	id     int         // numeric identifier to distinguish between the detectors for the various call sites
	detect bool        // Is toggled on when a bug was detected
	cmd    string      // the tampered with SQL query/cmd/path/...
	tree   *parse.Tree // Template injection specific field
	err    error       // Generic error handler
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
		d:      d,
		id:     id,
		detect: false,
		cmd:    GetCommand(cmdType),
		tree:   GetTree(treeType, args),
		err:    err,
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

func (dc *DetectorClass) Report(args ...any) {
	switch dc.d {
	case SQLInjection:
		dc.ReportSQLI()
	case TemplateInjection:
		dc.ReportTemplateInjection()
	case CommandInjection:
		dc.ReportCommandInjection()
	}
}
