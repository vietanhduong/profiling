package perf

import "github.com/cilium/ebpf"

type AttachPerfEventSpec struct {
	Prog       *ebpf.Program
	SampleRate uint64
}
