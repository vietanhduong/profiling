// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package profiler

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type ProfilerStackT struct {
	Pid           uint32
	_             [4]byte
	UserStackId   uint64
	KernelStackId uint64
}

// LoadProfiler returns the embedded CollectionSpec for Profiler.
func LoadProfiler() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProfilerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Profiler: %w", err)
	}

	return spec, err
}

// LoadProfilerObjects loads Profiler and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*ProfilerObjects
//	*ProfilerPrograms
//	*ProfilerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadProfilerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadProfiler()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// ProfilerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ProfilerSpecs struct {
	ProfilerProgramSpecs
	ProfilerMapSpecs
}

// ProfilerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ProfilerProgramSpecs struct {
	DoPerfEvent *ebpf.ProgramSpec `ebpf:"do_perf_event"`
}

// ProfilerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ProfilerMapSpecs struct {
	Histogram   *ebpf.MapSpec `ebpf:"histogram"`
	StackTraces *ebpf.MapSpec `ebpf:"stack_traces"`
}

// ProfilerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadProfilerObjects or ebpf.CollectionSpec.LoadAndAssign.
type ProfilerObjects struct {
	ProfilerPrograms
	ProfilerMaps
}

func (o *ProfilerObjects) Close() error {
	return _ProfilerClose(
		&o.ProfilerPrograms,
		&o.ProfilerMaps,
	)
}

// ProfilerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadProfilerObjects or ebpf.CollectionSpec.LoadAndAssign.
type ProfilerMaps struct {
	Histogram   *ebpf.Map `ebpf:"histogram"`
	StackTraces *ebpf.Map `ebpf:"stack_traces"`
}

func (m *ProfilerMaps) Close() error {
	return _ProfilerClose(
		m.Histogram,
		m.StackTraces,
	)
}

// ProfilerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadProfilerObjects or ebpf.CollectionSpec.LoadAndAssign.
type ProfilerPrograms struct {
	DoPerfEvent *ebpf.Program `ebpf:"do_perf_event"`
}

func (p *ProfilerPrograms) Close() error {
	return _ProfilerClose(
		p.DoPerfEvent,
	)
}

func _ProfilerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed profiler_bpfel_x86.o
var _ProfilerBytes []byte