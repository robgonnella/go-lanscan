package version

import (
	"html/template"
	"os"
	"path/filepath"
)

type TemplateGenerator struct {
	outFile      string
	outDir       string
	templatePath string
	templateName string
}

func NewTemplateGenerator(outFile, templatePath string) *TemplateGenerator {
	return &TemplateGenerator{
		outFile:      outFile,
		outDir:       filepath.Dir(outFile),
		templatePath: templatePath,
		templateName: filepath.Base(templatePath),
	}
}

func (t *TemplateGenerator) Generate(data VersionData) error {
	if err := os.MkdirAll(t.outDir, 0751); err != nil {
		return err
	}

	file, err := os.Create(t.outFile)

	if err != nil {
		return err
	}

	defer file.Close()

	template, err := template.New(t.templateName).ParseFiles(t.templatePath)

	if err != nil {
		return err
	}

	return template.Execute(file, data)
}
