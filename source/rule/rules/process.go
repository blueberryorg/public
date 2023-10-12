package rules

import (
	"path/filepath"
	"strings"
)

type Process struct {
	adapter  string
	process  string
	nameOnly bool
}

func (ps *Process) RuleType() RuleType {
	if ps.nameOnly {
		return RuleTypeProcess
	}

	return RuleTypeProcessPath
}

func (ps *Process) Match(metadata *Metadata) bool {
	if ps.nameOnly {
		return strings.EqualFold(filepath.Base(metadata.ProcessPath), ps.process)
	}

	return strings.EqualFold(metadata.ProcessPath, ps.process)
}

func (ps *Process) Adapter() string {
	return ps.adapter
}

func (ps *Process) Payload() string {
	return ps.process
}

func (ps *Process) ShouldResolveIP() bool {
	return false
}

func (ps *Process) ShouldFindProcess() bool {
	return true
}

func NewProcess(process string, adapter string, nameOnly bool) (*Process, error) {
	return &Process{
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
	}, nil
}
