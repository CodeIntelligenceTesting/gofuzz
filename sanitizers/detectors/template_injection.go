package detectors

import (
	"errors"
	"strings"
	"text/template/parse"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/fuzzer"
)

const evilTemplateAction = "{{ .EvilAction }}"

var TemplateInjectionError = errors.New("template injection error")

type TemplateInjection struct {
	id   int         // numeric identifier to distinguish between the detectors for the various call sites
	tree *parse.Tree // representation of the parsed template
}

// Make sure that the template injection detector implements the Detector interface
var _ Detector = (*TemplateInjection)(nil)

func (ti *TemplateInjection) Detect() error {
	tmplText := ti.tree.Root.String()
	if strings.Contains(tmplText, evilTemplateAction) {
		return TemplateInjectionError
	} else {
		fuzzer.GuideTowardsContainment(tmplText, evilTemplateAction, ti.id)
	}
	return nil
}

func NewTemplateInjection(id int, tree *parse.Tree) *TemplateInjection {
	return &TemplateInjection{
		id:   id,
		tree: tree,
	}
}
