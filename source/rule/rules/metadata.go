package rules

import (
	"net"
)

type Metadata struct {
	SrcIP       net.IP `json:"sourceIP"`
	DstIP       net.IP `json:"destinationIP"`
	SrcPort     uint64 `json:"sourcePort"`
	DstPort     uint64 `json:"destinationPort"`
	Host        string `json:"host"`
	ProcessPath string `json:"processPath"`
}
