package elf

import (
	"debug/elf"
	"fmt"

	"github.com/vietanhduong/profiling/pkg/syms/gosym"
)

type GoTable struct {
	Index gosym.FlatFuncIndex

	File          *MMapedFile
	gopclnSection elf.SectionHeader
	funcOffset    uint64
	fallback      FallbackResolver
}

func (g *GoTable) IsDead() bool { return g.File.IsDead() }

func (g *GoTable) Resolve(addr uint64) string {
	if symbol := g.resolve(addr); symbol != "" {
		return symbol
	}
	return g.fallback.Resolve(addr)
}

func (g *GoTable) Cleanup() {
	g.File.Close()
	g.fallback.Cleanup()
}

func (g *GoTable) Size() int { return len(g.Index.Name) + g.fallback.Size() }

func (g *GoTable) resolve(addr uint64) string {
	if len(g.Index.Name) == 0 {
		return ""
	}
	if addr >= g.Index.End {
		return ""
	}
	if i := g.Index.Entry.FindIndex(addr); i != -1 {
		return g.resolveSymbol(i)
	}
	return ""
}

func (g *GoTable) resolveSymbol(index int) string {
	if index >= len(g.Index.Name) {
		return ""
	}
	return g.File.getString(int(g.gopclnSection.Offset) + int(g.funcOffset) + int(g.Index.Name[index]))
}

func (mf *MMapedFile) NewGoTable(fallback FallbackResolver) (*GoTable, error) {
	if mf.IsDead() || mf.f == nil {
		return nil, fmt.Errorf("proc is dead or not open yet")
	}
	text := mf.FindSection(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	pclntab := mf.FindSection(".gopclntab")
	if pclntab == nil {
		return nil, fmt.Errorf("no .gopclntab section")
	}
	reader := gosym.NewFilePCLNData(mf.f, int(pclntab.Offset))
	pclntabHeader := make([]byte, 64)
	if err := reader.ReadAt(pclntabHeader, 0); err != nil {
		return nil, fmt.Errorf("read pclntab header: %w", err)
	}
	textstart := gosym.ParseRuntimeTextFromPclntab18(pclntabHeader)
	if textstart == 0 {
		// for older versions text.Addr is enough
		// https://github.com/golang/go/commit/b38ab0ac5f78ac03a38052018ff629c03e36b864
		textstart = text.Addr
	}
	if textstart < text.Addr || textstart >= text.Addr+text.Size {
		return nil, fmt.Errorf("runtime.text of of .text bounds %d %d %d", textstart, text.Addr, text.Size)
	}
	pcln := gosym.NewLineTableStreaming(reader, textstart)
	if !pcln.IsGo12() {
		return nil, fmt.Errorf("go symtab too old")
	}
	if pcln.IsFailed() {
		return nil, fmt.Errorf("parse go symtab failed")
	}
	funcs := pcln.Go12Funcs()
	if len(funcs.Name) == 0 || funcs.Entry.Length() == 0 || funcs.End == 0 {
		return nil, fmt.Errorf("no symbol found")
	}
	if funcs.Entry.Length() != len(funcs.Name) {
		return nil, fmt.Errorf("parse go symtab failed")
	}
	if fallback == nil {
		fallback = &emptyFallback{}
	}
	return &GoTable{
		Index:         funcs,
		File:          mf,
		gopclnSection: *pclntab,
		funcOffset:    pcln.FuncNameOffset(),
		fallback:      fallback,
	}, nil
}
