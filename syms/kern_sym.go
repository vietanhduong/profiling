package syms

import (
	"fmt"
	"sort"

	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/proc"
)

type KernSym struct {
	path    string
	symbols []Symbol
	base    uint64
}

func NewKernSym() (*KernSym, error) {
	this := &KernSym{path: proc.HostProcPath("kallsyms")}
	var err error
	if this.symbols, err = parseKallsyms(this.path); err != nil {
		return nil, fmt.Errorf("parse kallsym: %w", err)
	}
	return this, nil
}

func (s *KernSym) Refresh() {
	if len(s.symbols) != 0 {
		return
	}
	symbols, err := parseKallsyms(s.path)
	if err != nil {
		glog.Warningf("KernSym refresh: failed to parse kallsym(path=%s): %v", s.path, err)
		return
	}
	s.symbols = symbols
}

func (s *KernSym) Rebase(base uint64) { s.base = base }

func (s *KernSym) Cleanup() { s.symbols = s.symbols[:0] }

func (s *KernSym) Resolve(addr uint64) Symbol {
	s.Refresh()
	var empty Symbol
	if len(s.symbols) == 0 {
		return empty
	}
	addr -= s.base
	if addr < s.symbols[0].Start {
		return empty
	}
	i := sort.Search(len(s.symbols), func(i int) bool { return addr < s.symbols[i].Start })
	i--
	return s.symbols[i]
}
