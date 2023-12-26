// SPDX-License-Identifier: GPL-3.0-or-later

package version

import "os/exec"

// Git implementation of the VersionControl interface using git
type Git struct{}

// NewGit returns a new instance of Git
func NewGit() *Git {
	return &Git{}
}

// Add implements the Add method using git
func (g *Git) Add(filePath string) error {
	cmd := exec.Command("git", "add", filePath)
	return cmd.Run()
}

// Commit implements the Commit method using git
func (g *Git) Commit(message string) error {
	cmd := exec.Command("git", "commit", "-m", message)
	return cmd.Run()
}

// Tag implements the tag method using git
func (g *Git) Tag(version string) error {
	cmd := exec.Command("git", "tag", "-m", version, version)
	return cmd.Run()
}
