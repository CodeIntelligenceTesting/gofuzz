package sanitizers

import (
	"errors"
	"github.com/CodeIntelligenceTesting/gofuzz/sanitizers/detectors"
	htmlTemplate "html/template"
	"io"
	textTemplate "text/template"
)

func reportOnDetectionTI(hookId int, tmpl interface{}, args ...any) {
	var err error
	switch v := tmpl.(type) {
	case *htmlTemplate.Template, *textTemplate.Template:
		if len(args) == 0 {
			// Direct call to `.Tree`
			err = detectors.NewTemplateInjection(hookId, v.Tree).Detect()
		} else {
			// Call `.Lookup()` first to resolve `name` before calling `.Tree`
			err = detectors.NewTemplateInjection(hookId, v.Lookup(args[0]).Tree).Detect()
		}
	}
	if errors.Is(err, detectors.CommandInjectionError) {
		ReportFinding(err.Error())
	}
}

func HtmlTemplateExecute(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, data any) error {
	reportOnDetectionTI(hookId, tmpl)
	return tmpl.Execute(wr, data)
}

func HtmlTemplateExecuteTemplate(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, name string, data any) error {
	reportOnDetectionTI(hookId, tmpl, name)
	return tmpl.ExecuteTemplate(wr, name, data)
}

func TextTemplateExecute(hookId int, tmpl *textTemplate.Template, wr io.Writer, data any) error {
	reportOnDetectionTI(hookId, tmpl)
	return tmpl.Execute(wr, data)
}

func TextTemplateExecuteTemplate(hookId int, tmpl *textTemplate.Template, wr io.Writer, name string, data any) error {
	reportOnDetectionTI(hookId, tmpl, name)
	return tmpl.ExecuteTemplate(wr, name, data)

}
