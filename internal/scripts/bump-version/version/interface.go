// SPDX-License-Identifier: GPL-3.0-or-later

package version

type VersionData struct {
	VERSION string
}

//go:generate mockgen -destination=../../../mock/scripts/bump-version/version/version.go -package=mock_version . VersionControl,VersionGenerator

type VersionControl interface {
	Add(filePath string) error
	Commit(message string) error
	Tag(version string) error
}

type VersionGenerator interface {
	Generate(data VersionData) error
}
