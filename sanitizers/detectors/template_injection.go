package detectors

import (
	"errors"
	htmlTemplate "html/template"
	"strings"
	textTemplate "text/template"
	"text/template/parse"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilTemplateAction = "{{ .EvilAction }}"

var TemplateInjectionError = errors.New("Template injection error")

type TemplateInjection struct {
	DetectorClass
}

func (ti *TemplateInjection) Detect() *TemplateInjection {
	tmplText := ti.tree.Root.String()
	if strings.Contains(tmplText, evilTemplateAction) {
		ti.detect = true
	} else {
		fuzzer.GuideTowardsContainment(tmplText, evilTemplateAction, ti.id)
	}
	return ti
}

func (ti *TemplateInjection) Report() {
	reporter.ReportFinding(TemplateInjectionError.Error())
}

func NewTemplateInjection(id int, ttype interface{}, args ...any) *TemplateInjection {
	var tree *parse.Tree
	switch v := ttype.(type) {
	case *htmlTemplate.Template, *textTemplate.Template:
		if len(args) == 0 {
			tree = v.Tree
		} else {
			tree = v.Lookup(args[0]).Tree
		}
	}
	return &TemplateInjection{
		DetectorClass: DetectorClass{
			id:     id,
			detect: false,
			cmd:    "",
			tree:   tree,
			err:    nil,
		},
	}
}
