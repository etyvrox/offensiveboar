package circleci

import (
	"strings"

	"github.com/etyvrox/offensiveboar/v3/pkg/tui/common"
	"github.com/etyvrox/offensiveboar/v3/pkg/tui/components/textinputs"
)

type circleCiCmdModel struct {
	textinputs.Model
}

func GetFields() circleCiCmdModel {
	token := textinputs.InputConfig{
		Label:       "API Token",
		Key:         "token",
		Required:    true,
		Placeholder: "top secret token",
	}

	return circleCiCmdModel{textinputs.New([]textinputs.InputConfig{token})}
}

func (m circleCiCmdModel) Cmd() string {
	var command []string
	command = append(command, "offensiveboar", "circleci")

	inputs := m.GetInputs()
	command = append(command, "--token="+inputs["token"].Value)

	return strings.Join(command, " ")
}

func (m circleCiCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"token"}

	return common.SummarizeSource(keys, inputs, labels)
}
