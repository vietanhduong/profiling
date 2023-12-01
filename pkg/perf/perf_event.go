package perf

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vietanhduong/profiling/pkg/cpuonline"
	"golang.org/x/sys/unix"
)

type perfEvent struct {
	fd   int
	link *link.RawLink
}

type PerfEvent struct {
	attached map[int][]*perfEvent
}

func New() *PerfEvent {
	return &PerfEvent{
		attached: make(map[int][]*perfEvent),
	}
}

func (p *PerfEvent) AttachPerfEvent(spec *AttachPerfEventSpec) error {
	if spec == nil || spec.Prog == nil {
		return fmt.Errorf("spec or spec.prog is nil")
	}

	if _, ok := p.attached[spec.Prog.FD()]; ok {
		return fmt.Errorf("program %d already attached", spec.Prog.FD())
	}

	cpus, err := cpuonline.Get()
	if err != nil {
		return fmt.Errorf("get cpu online: %w", err)
	}

	events := make([]*perfEvent, len(cpus))

	for _, cpu := range cpus {
		events[cpu], err = attachPerfEventOnCpu(spec.Prog, int(cpu), spec.SampleRate)
		if err != nil {
			for _, pe := range events {
				pe.Close()
			}
			return fmt.Errorf("attach perf event on cpu %d: %w", cpu, err)
		}
	}

	p.attached[spec.Prog.FD()] = events
	return nil
}

func (p *PerfEvent) DetachPerfEvent(prodFd int) {
	if events, ok := p.attached[prodFd]; ok {
		for _, pe := range events {
			pe.Close()
		}
		delete(p.attached, prodFd)
	}
}

func (p *PerfEvent) Close() {
	for prodFd := range p.attached {
		p.DetachPerfEvent(prodFd)
	}
}

func attachPerfEventOnCpu(prog *ebpf.Program, cpu int, sameRate uint64) (*perfEvent, error) {
	fd, err := openPerfEventCpu(cpu, sameRate)
	if err != nil {
		return nil, err
	}
	pe := &perfEvent{fd: fd}
	if pe.link, err = attachPerfEventLink(fd, prog); err == nil {
		return pe, nil
	}
	if err = attachPerfEventIoctl(fd, prog); err != nil {
		pe.Close()
		return nil, err
	}
	return pe, nil
}

func openPerfEventCpu(cpu int, sampleRate uint64) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: sampleRate,
	}
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("unix perf event open: %w", err)
	}
	return fd, nil
}

func attachPerfEventLink(fd int, prog *ebpf.Program) (*link.RawLink, error) {
	opts := link.RawLinkOptions{
		Target:  fd,
		Program: prog,
		Attach:  ebpf.AttachPerfEvent,
	}
	link, err := link.AttachRawLink(opts)
	if err != nil {
		return nil, fmt.Errorf("attach raw link: %w", err)
	}
	return link, nil
}

func attachPerfEventIoctl(fd int, prog *ebpf.Program) error {
	err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD())
	if err != nil {
		return fmt.Errorf("setting perf event bpf program: %w", err)
	}
	if err = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return fmt.Errorf("enable perf event: %w", err)
	}
	return nil
}

func (p *perfEvent) Close() {
	if p == nil {
		return
	}
	_ = syscall.Close(p.fd)
	if p.link != nil {
		_ = p.link.Close()
	}
}
