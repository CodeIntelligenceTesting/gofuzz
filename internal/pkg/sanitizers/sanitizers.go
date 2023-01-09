package sanitizers

const (
	CommandInjection  = "command_injection"
	PathTraversal     = "path_traversal"
	SQLInjection      = "sql_injection"
	TemplateInjection = "template_injection"
)

var AllSanitizers = []string{
	CommandInjection,
	PathTraversal,
	SQLInjection,
	TemplateInjection,
}
