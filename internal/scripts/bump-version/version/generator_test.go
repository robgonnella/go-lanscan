// SPDX-License-Identifier: GPL-3.0-or-later

package version_test

import (
	"io"
	"os"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/scripts/bump-version/version"
	"github.com/stretchr/testify/assert"
)

func TestTemplateGenerator(t *testing.T) {
	outFile := "test.go"
	templatePath := "test.go.tmpl"

	reset := func() {
		os.RemoveAll(outFile)
		os.RemoveAll(templatePath)
	}

	templateStr := `
	package info

	var Version = {{ .VERSION }}
	`

	err := os.WriteFile(templatePath, []byte(templateStr), 0644)

	assert.NoError(t, err)

	generator := version.NewTemplateGenerator(outFile, templatePath)

	data := version.VersionData{
		VERSION: "v2.2.2",
	}

	defer reset()

	t.Run("generates template", func(st *testing.T) {
		defer reset()

		err := generator.Generate(data)

		assert.NoError(st, err)

		info, err := os.Stat(outFile)

		assert.NoError(st, err)

		file, err := os.Open(info.Name())

		assert.NoError(st, err)

		contents, err := io.ReadAll(file)

		assert.NoError(st, err)

		assert.Contains(st, string(contents), "var Version = v2.2.2")
	})
}
