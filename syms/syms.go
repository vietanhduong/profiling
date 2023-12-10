package syms

type Resolver interface {
	Resolve(addr uint64) Symbol
	Cleanup()
	Refresh()
}

func NewResolver(pid int, opts *SymbolOptions) (Resolver, error) {
	if pid < 0 {
		return NewKernSym()
	}
	return NewProcSymbol(pid, opts)
}
