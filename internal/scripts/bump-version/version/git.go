package version

import "os/exec"

type Git struct{}

func NewGit() *Git {
	return &Git{}
}

func (g *Git) Add(filePath string) error {
	cmd := exec.Command("git", "add", filePath)
	return cmd.Run()
}

func (g *Git) Commit(message string) error {
	cmd := exec.Command("git", "commit", "-m", message)
	return cmd.Run()
}

func (g *Git) Tag(version string) error {
	cmd := exec.Command("git", "tag", "-m", version, version)
	return cmd.Run()
}
