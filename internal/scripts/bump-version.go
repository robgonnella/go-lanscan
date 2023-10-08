package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"
)

func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		log.Fatal(errors.New("must provide version as argument"))
	}

	version := args[0]

	if string(version[0]) != "v" {
		log.Fatal(errors.New("version must begin with a \"v\""))
	}

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

	addCmd := exec.Command("git", "add", "internal/info")

	if err := addCmd.Run(); err != nil {
		log.Fatal(err)
	}

	commitCmd := exec.Command(
		"git",
		"commit",
		"-m",
		fmt.Sprintf("Bump version %s", version),
	)

	if err := commitCmd.Run(); err != nil {
		log.Fatal(err)
	}

	tagCmd := exec.Command("git", "tag", "-m", version, version)

	if err := tagCmd.Run(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully bumped version to %s\n", version)

	fmt.Println("To deploy run: \"git push <repo> <branch> --tags\"")
}
