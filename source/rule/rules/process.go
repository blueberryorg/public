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

func (p *Process) Clash() (string, bool) {
	if p.nameOnly {
		return "PROCESS-NAME", true
	}
	return "PROCESS-PATH", true
}

func (p *Process) QuanX() (string, bool) {
	return "", false
}

func (p *Process) RuleType() RuleType {
	if p.nameOnly {
		return RuleTypeProcess
	}

	return RuleTypeProcessPath
}

func (p *Process) Match(metadata *Metadata) bool {
	if p.nameOnly {
		return strings.EqualFold(filepath.Base(metadata.ProcessPath), p.process)
	}

	return strings.EqualFold(metadata.ProcessPath, p.process)
}

func (p *Process) Adapter() string {
	return p.adapter
}

func (p *Process) Payload() string {
	return p.process
}

func (p *Process) ShouldResolveIP() bool {
	return false
}

func (p *Process) ShouldFindProcess() bool {
	return true
}

func NewProcess(process string, adapter string, nameOnly bool) (*Process, error) {
	return &Process{
		adapter:  adapter,
		process:  process,
		nameOnly: nameOnly,
	}, nil
}
