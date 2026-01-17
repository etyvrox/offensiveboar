package gcs

import (
	"strings"

	"github.com/etyvrox/offensiveboar/v3/pkg/tui/common"
	"github.com/etyvrox/offensiveboar/v3/pkg/tui/components/textinputs"
)

type gcsCmdModel struct {
	textinputs.Model
}

func GetFields() gcsCmdModel {
	projectId := textinputs.InputConfig{
		Label:       "Project ID",
		Key:         "project-id",
		Required:    true,
		Placeholder: "offensiveboar-testing",
	}

	return gcsCmdModel{textinputs.New([]textinputs.InputConfig{projectId})}
}

func (m gcsCmdModel) Cmd() string {
	var command []string
	command = append(command, "offensiveboar", "gcs")

	inputs := m.GetInputs()

	command = append(command, "--project-id="+inputs["project-id"].Value)

	command = append(command, "--cloud-environment")
	return strings.Join(command, " ")
}

func (m gcsCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"project-id"}
	return common.SummarizeSource(keys, inputs, labels)
}
