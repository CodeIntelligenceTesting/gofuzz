package initial

import (
	"fmt"
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
		return t.Execute(writer, todo)
	} else {
		return t.ExecuteTemplate(writer, name, todo)
	}
}

func printTodoItemText(todo Todo, name, item string, writer io.Writer) error {
	t, err := textTemplate.New("todos").Parse(fmt.Sprintf("Your task named \"{{ .Name }}\" has item %q", item))
	if err != nil {
		return err
	}

	if name == "" {
		return t.Execute(writer, todo)
	} else {
		return t.ExecuteTemplate(writer, name, todo)
	}
}
