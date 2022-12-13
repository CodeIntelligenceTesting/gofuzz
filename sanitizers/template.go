package sanitizers

import (
	"errors"
	htmlTemplate "html/template"
	"io"
	textTemplate "text/template"

	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
)

func HtmlTemplateExecute(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, data any) error {
	err := detectors.NewTemplateInjection(hookId, tmpl.Tree).Detect()
	if errors.Is(err, detectors.TemplateInjectionError) {
		ReportFinding("Template Injection")
	}
	return tmpl.Execute(wr, data)
}

func HtmlTemplateExecuteTemplate(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, name string, data any) error {
	err := detectors.NewTemplateInjection(hookId, tmpl.Lookup(name).Tree).Detect()
	if errors.Is(err, detectors.TemplateInjectionError) {
		ReportFinding("Template Injection")
	}
	return tmpl.ExecuteTemplate(wr, name, data)
}

func TextTemplateExecute(hookId int, tmpl *textTemplate.Template, wr io.Writer, data any) error {
	err := detectors.NewTemplateInjection(hookId, tmpl.Tree).Detect()
	if errors.Is(err, detectors.TemplateInjectionError) {
		ReportFinding("Template Injection")
	}
	return tmpl.Execute(wr, data)
}

func TextTemplateExecuteTemplate(hookId int, tmpl *textTemplate.Template, wr io.Writer, name string, data any) error {
	err := detectors.NewTemplateInjection(hookId, tmpl.Lookup(name).Tree).Detect()
	if errors.Is(err, detectors.TemplateInjectionError) {
		ReportFinding("Template Injection")
	}
	return tmpl.ExecuteTemplate(wr, name, data)

}
