package elf

import (
	"debug/elf"
	"fmt"
	"sort"

	"github.com/ianlancetaylor/demangle"
	"github.com/vietanhduong/profiling/pkg/syms/gosym"
)

type SymbolTable struct {
	Index struct {
		Links  []elf.SectionHeader
		Names  []Name
		Values gosym.PCIndex
	}
	File *MMapedFile

	opts []demangle.Option
}

func (f *MMapedFile) NewSymbolTable(opts *SymbolOptions) (*SymbolTable, error) {
	sym, err := f.getSymbols(elf.SHT_SYMTAB, opts)
	if err != nil {
		return nil, fmt.Errorf("get symbol section %s: %w", elf.SHT_SYMTAB.String(), err)
	}

	dynsym, err := f.getSymbols(elf.SHT_DYNSYM, opts)
	if err != nil {
		return nil, fmt.Errorf("get symbol section %s: %w", elf.SHT_DYNSYM.String(), err)
	}

	total := len(dynsym.symbols) + len(sym.symbols)
	if total == 0 {
		return nil, nil
	}

	all := make([]SymbolIndex, 0, total)
	all = append(all, sym.symbols...)
	all = append(all, dynsym.symbols...)

	sort.Slice(all, func(i, j int) bool {
		if all[i].Value == all[j].Value {
			return all[i].Name < all[j].Name
		}
		return all[i].Value < all[j].Value
	})

	ret := &SymbolTable{
		File: f,
		opts: opts.DemangleOpts,
	}

	ret.Index.Links = []elf.SectionHeader{
		f.Sections[sym.data.Header.Link],
		f.Sections[dynsym.data.Header.Link],
	}
	ret.Index.Names = make([]Name, total)
	ret.Index.Values = gosym.NewPCIndex(total)
	for i := range all {
		ret.Index.Names[i] = all[i].Name
		ret.Index.Values.Set(i, all[i].Value)
	}
	return ret, nil
}

func (s *SymbolTable) IsDead() bool { return s.File.IsDead() }

func (s *SymbolTable) Size() int { return len(s.Index.Names) }

func (s *SymbolTable) Resolve(addr uint64) string {
	if len(s.Index.Names) == 0 {
		return ""
	}
	if i := s.Index.Values.FindIndex(addr); i != -1 {
		return s.symbolName(i)
	}
	return ""
}

func (s *SymbolTable) Cleanup() { s.File.Close() }

func (s *SymbolTable) symbolName(index int) string {
	secidx := s.Index.Names[index].SectionIndex()
	header := &s.Index.Links[secidx]
	name := s.Index.Names[index].Name()
	return s.File.getString(int(name)+int(header.Offset), s.opts...)
}
