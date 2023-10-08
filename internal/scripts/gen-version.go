package main

import (
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

func main() {
	listCmd := exec.Command("git", "rev-list", "--tags", "--max-count=1")

	listOutput, err := listCmd.Output()

	if err != nil {
		log.Fatal(err)
	}

	sha := strings.Trim(string(listOutput), "\n")

	describeCmd := exec.Command("git", "describe", "--tags", sha)

	describeOutput, err := describeCmd.Output()

	if err != nil {
		log.Fatal(err)
	}

	version := strings.Trim(string(describeOutput), "\n")

	info := struct{ VERSION string }{
		VERSION: string(version),
	}

	if err := os.MkdirAll("internal/info", 0751); err != nil {
		log.Fatal(err)
	}

	file, err := os.Create("internal/info/version.go")

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	tmpl, err := template.
		New("version.go.tmpl").
		ParseFiles("internal/templates/version.go.tmpl")

	if err != nil {
		log.Fatal(err)
	}

	if err := tmpl.Execute(file, info); err != nil {
		log.Fatal(err)
	}
}
