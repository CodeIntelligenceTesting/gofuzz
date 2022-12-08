package sanitizers

import (
	htmlTemplate "html/template"
	"io"
	"strings"
	textTemplate "text/template"
	"text/template/parse"
)

const evilTemplateCommand = "{{ .EvilCommand }}"

func HtmlTemplateExecute(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, data any) error {
	checkForEvilActionAndGuideFuzzer(hookId, tmpl.Tree)
	return tmpl.Execute(wr, data)
}

func HtmlTemplateExecuteTemplate(hookId int, tmpl *htmlTemplate.Template, wr io.Writer, name string, data any) error {
	checkForEvilActionAndGuideFuzzer(hookId, tmpl.Lookup(name).Tree)
	return tmpl.ExecuteTemplate(wr, name, data)
}

func TextTemplateExecute(hookId int, tmpl *textTemplate.Template, wr io.Writer, data any) error {
	checkForEvilActionAndGuideFuzzer(hookId, tmpl.Tree)
	return tmpl.Execute(wr, data)
}

func TextTemplateExecuteTemplate(hookId int, tmpl *textTemplate.Template, wr io.Writer, name string, data any) error {
	checkForEvilActionAndGuideFuzzer(hookId, tmpl.Lookup(name).Tree)
	return tmpl.ExecuteTemplate(wr, name, data)

}

func checkForEvilActionAndGuideFuzzer(hookId int, tree *parse.Tree) {
	tmplText := tree.Root.String()
	if strings.Contains(tmplText, evilTemplateCommand) {
		ReportFinding("Template Injection")
	} else {
		GuideTowardsContainment(tmplText, evilTemplateCommand, hookId)
	}
}
