package version

import (
	"errors"
	"fmt"
)

type BumpData struct {
	Version      string
	OutFile      string
	TemplatePath string
}

func Bump(data BumpData, vg VersionGenerator, vc VersionControl) error {
	if string(data.Version[0]) != "v" {
		return errors.New("version must begin with a \"v\"")
	}

	info := struct{ VERSION string }{
		VERSION: string(data.Version),
	}

	if err := vg.Generate(info); err != nil {
		return err
	}

	if err := vc.Add(data.OutFile); err != nil {
		return err
	}

	message := fmt.Sprintf("Bump version %s", data.Version)

	if err := vc.Commit(message); err != nil {
		return err
	}

	return vc.Tag(data.Version)
}
