// SPDX-License-Identifier: GPL-3.0-or-later

package version_test

import (
	"fmt"
	"testing"

	mock_version "github.com/robgonnella/go-lanscan/internal/mock/scripts/bump-version/version"
	"github.com/robgonnella/go-lanscan/internal/scripts/bump-version/version"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestBumpVersion(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	t.Run("returns error if version does not start with v", func(st *testing.T) {
		mockVc := mock_version.NewMockVersionControl(ctrl)
		mockVg := mock_version.NewMockVersionGenerator(ctrl)

		versionStr := "2.2.2"
		outFile := "outfile.go"
		templatePath := "outfile.go.tmpl"

		execData := version.BumpData{
			Version:      versionStr,
			OutFile:      outFile,
			TemplatePath: templatePath,
		}

		err := version.Bump(execData, mockVg, mockVc)

		assert.Error(st, err)
	})

	t.Run("it bumps version", func(st *testing.T) {
		mockVc := mock_version.NewMockVersionControl(ctrl)
		mockVg := mock_version.NewMockVersionGenerator(ctrl)

		versionStr := "v2.2.2"
		outFile := "outfile.go"
		templatePath := "outfile.go.tmpl"

		execData := version.BumpData{
			Version:      versionStr,
			OutFile:      outFile,
			TemplatePath: templatePath,
		}

		data := version.VersionData{
			VERSION: versionStr,
		}

		message := fmt.Sprintf("Bump version %s", execData.Version)

		mockVg.EXPECT().Generate(data)
		mockVc.EXPECT().Add(outFile)
		mockVc.EXPECT().Commit(message)
		mockVc.EXPECT().Tag(versionStr)

		err := version.Bump(execData, mockVg, mockVc)

		assert.NoError(st, err)
	})
}
