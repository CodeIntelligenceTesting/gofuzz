package initial

import (
	"fmt"
	goSanitizers "github.com/CodeIntelligenceTesting/gofuzz/sanitizers"
	htmlTemplate "html/template"
	"io"
	textTemplate "text/template"
)

type Todo struct {
	Name        string
	Description string
}

func printTodoItemHtml(todo Todo, name, item string, writer io.Writer) error {
	t, err := htmlTemplate.New("todos").Parse(fmt.Sprintf("Your task named \"{{ .Name }}\" has item %q", item))
	if err != nil {
		return err
	}

	if name == "" {
		return goSanitizers.HtmlTemplateExecute(0, t, writer, todo)
	} else {
		return goSanitizers.HtmlTemplateExecuteTemplate(0, t, writer, name, todo)
	}
}

func printTodoItemText(todo Todo, name, item string, writer io.Writer) error {
	t, err := textTemplate.New("todos").Parse(fmt.Sprintf("Your task named \"{{ .Name }}\" has item %q", item))
	if err != nil {
		return err
	}

	if name == "" {
		return goSanitizers.TextTemplateExecute(0, t, writer, todo)
	} else {
		return goSanitizers.TextTemplateExecuteTemplate(0, t, writer, name, todo)
	}
}
