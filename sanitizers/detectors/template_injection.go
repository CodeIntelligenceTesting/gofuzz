package detectors

import (
	"strings"
	"text/template/parse"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/reporter"
)

const evilTemplateAction = "{{ .EvilAction }}"

var _ Detector = (*TemplateInjection)(nil)

type TemplateInjection struct {
	id   int         // Numeric identifier to distinguish between the detectors for the various call sites
	tree *parse.Tree // Representation of a parsed template

}

func (ti *TemplateInjection) Detect() {
	tmplText := ti.tree.Root.String()
	if strings.Contains(tmplText, evilTemplateAction) {
		reporter.ReportFinding("Template Injection")
	}
	fuzzer.GuideTowardsContainment(tmplText, evilTemplateAction, ti.id)
}

func NewTemplateInjection(id int, tree *parse.Tree) *TemplateInjection {
	return &TemplateInjection{id, tree}
}
