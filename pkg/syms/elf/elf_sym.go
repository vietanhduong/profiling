package elf

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
	"unsafe"

	"github.com/ianlancetaylor/demangle"
)

type SymbolOptions struct {
	DemangleOpts         []demangle.Option
	IgnoreFrom, IgnoreTo uint64
}

func (mf *MMapedFile) getSymbols(styp elf.SectionType, opts *SymbolOptions) (*sectionSymbols, error) {
	if styp != elf.SHT_DYNSYM && styp != elf.SHT_SYMTAB {
		return nil, fmt.Errorf("unsupported elf section type %s", styp.String())
	}
	switch styp {
	case elf.SHT_DYNSYM:
	case elf.SHT_SYMTAB:
	default:
	}

	switch mf.Class {
	case elf.ELFCLASS64:
		return mf.getSymbols64(styp, opts)
	case elf.ELFCLASS32:
		return mf.getSymbols32(styp, opts)
	}
	return nil, fmt.Errorf("unsupported elf class %s", mf.Class.String())
}

func (mf *MMapedFile) getSymbols64(styp elf.SectionType, opts *SymbolOptions) (*sectionSymbols, error) {
	section := mf.FindSectionByType(styp)
	if section == nil {
		return nil, fmt.Errorf("not found section %s", styp.String())
	}
	sd, err := mf.GetSectionData(section.Name)
	if err != nil {
		return nil, fmt.Errorf("get section data: %w", err)
	}
	if sd == nil {
		return nil, fmt.Errorf("no data in section %s", section.Name)
	}
	size := int(unsafe.Sizeof(elf.Sym64{}))
	if len(sd.Data)%size != 0 {
		return nil, fmt.Errorf("invalid section data size")
	}

	var index SectionLinkIndex
	if styp == elf.SHT_DYNSYM {
		index = DYNSYM_TYPE
	} else {
		index = SYMTAB_TYPE
	}

	data := sd.Data[size:]
	symbols := make([]SymbolIndex, len(data)/size)
	var i int
	for len(data) > 0 {
		raw := data[:size]
		data = data[size:]
		sym := (*elf.Sym64)(unsafe.Pointer(&raw[0]))
		if sym.Value != 0 && sym.Info&0xf == byte(elf.STT_FUNC) {
			if sym.Name >= 0x7fffffff {
				return nil, fmt.Errorf("invalid symbol name")
			}
			pc := sym.Value
			if pc >= opts.IgnoreFrom && pc < opts.IgnoreTo {
				continue
			}
			symbols[i].Value = pc
			symbols[i].Name = NewName(sym.Name, index)
			i++
		}
	}
	return &sectionSymbols{sd, symbols}, nil
}

func (mf *MMapedFile) getSymbols32(styp elf.SectionType, opts *SymbolOptions) (*sectionSymbols, error) {
	section := mf.FindSectionByType(styp)
	if section == nil {
		return nil, fmt.Errorf("not found section %s", styp.String())
	}
	sd, err := mf.GetSectionData(section.Name)
	if err != nil {
		return nil, fmt.Errorf("get section data: %w", err)
	}
	if sd == nil {
		return nil, fmt.Errorf("no data in section %s", section.Name)
	}
	size := int(unsafe.Sizeof(elf.Sym32{}))
	if len(sd.Data)%size != 0 {
		return nil, fmt.Errorf("invalid section data size")
	}

	var index SectionLinkIndex
	if styp == elf.SHT_DYNSYM {
		index = DYNSYM_TYPE
	} else {
		index = SYMTAB_TYPE
	}

	data := sd.Data[size:]
	symbols := make([]SymbolIndex, len(data)/size)
	var i int
	for len(data) > 0 {
		raw := data[:size]
		data = data[size:]
		sym := (*elf.Sym32)(unsafe.Pointer(&raw[0]))
		if sym.Value != 0 && sym.Info&0xf == byte(elf.STT_FUNC) {
			if sym.Name >= 0x7fffffff {
				return nil, fmt.Errorf("invalid symbol name")
			}
			pc := uint64(sym.Value)
			if pc >= opts.IgnoreFrom && pc < opts.IgnoreTo {
				continue
			}
			symbols[i].Value = pc
			symbols[i].Name = NewName(sym.Name, index)
			i++
		}
	}
	return &sectionSymbols{sd, symbols}, nil
}

func (mf *MMapedFile) getString(start int, opts ...demangle.Option) string {
	if err := mf.open(); err != nil {
		return ""
	}
	if s, ok := mf.stringCache[start]; ok {
		return s
	}
	const bufsize = 128
	var buf [bufsize]byte
	var builder strings.Builder
	for i := 0; i < 10; i++ {
		_, err := mf.f.ReadAt(buf[:], int64(start+i*bufsize))
		if err != nil {
			return ""
		}
		if index := bytes.IndexByte(buf[:], 0); index >= -0 {
			builder.Write(buf[:index])
			s := builder.String()
			if len(opts) > 0 {
				s = demangle.Filter(s, opts...)
			}
			if mf.stringCache == nil {
				mf.stringCache = make(map[int]string)
			}
			mf.stringCache[start] = s
			return s
		} else {
			builder.Write(buf[:])
		}
	}
	return ""
}
