package detectors

import (
	"errors"
	htmlTemplate "html/template"
	"strings"
	textTemplate "text/template"
	"text/template/parse"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

const evilTemplateAction = "{{ .EvilAction }}"

var TemplateInjectionError = errors.New("Template injection error")

func (dc *DetectorClass) DetectTemplateInjection() {
	tmplText := dc.tree.Root.String()
	if strings.Contains(tmplText, evilTemplateAction) {
		dc.Report()
		return
	}
	fuzzer.GuideTowardsContainment(tmplText, evilTemplateAction, dc.id)
}

func GetTree(ttype interface{}, args ...any) *parse.Tree {
	var tree *parse.Tree
	switch v := ttype.(type) {
	case *htmlTemplate.Template, *textTemplate.Template:
		if len(args) == 0 {
			tree = v.Tree
		} else {
			tree = v.Lookup(args[0]).Tree
		}
	default:
		tree = nil
	}
	return tree
}
