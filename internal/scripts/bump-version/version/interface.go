// SPDX-License-Identifier: GPL-3.0-or-later

package version

// Data represents the version data passed to template generator
type Data struct {
	VERSION string
}

//go:generate mockgen -destination=../../../mock/scripts/bump-version/version/version.go -package=mock_version . VersionControl,VersionGenerator

// nolint:revive
// VersionControl interface representing a version control system
type VersionControl interface {
	Add(filePath string) error
	Commit(message string) error
	Tag(version string) error
}

// nolint:revive
// VersionGenerator interface representing a generator of version files
// for this library
type VersionGenerator interface {
	Generate(data Data) error
}
