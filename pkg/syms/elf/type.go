package elf

import "debug/elf"

type BuildType string

const (
	GNU BuildType = "GNU"
	GO  BuildType = "GO"
)

type BuildId struct {
	Id   string
	Type BuildType
}

func GoBuildId(id string) BuildId {
	return BuildId{id, GO}
}

func GnuBuildId(id string) BuildId {
	return BuildId{id, GNU}
}

func (id BuildId) GNU() bool { return id.Type == GNU }

type SectionData struct {
	Data   []byte
	Header *elf.SectionHeader
}

type (
	Name             uint32
	SectionLinkIndex uint8
)

type SymbolIndex struct {
	Name  Name
	Value uint64
}

const (
	SYMTAB_TYPE SectionLinkIndex = 0
	DYNSYM_TYPE SectionLinkIndex = 1
)

func NewName(name uint32, index SectionLinkIndex) Name {
	return Name((name & 0x7fffffff) | uint32(index)<<31)
}

func (n Name) Name() uint32                   { return uint32(n) & 0x7fffffff }
func (n Name) SectionIndex() SectionLinkIndex { return SectionLinkIndex(n >> 31) }

func (i SectionLinkIndex) ElfSection() elf.SectionType {
	switch i {
	case SYMTAB_TYPE:
		return elf.SHT_SYMTAB
	case DYNSYM_TYPE:
		return elf.SHT_DYNSYM
	}
	return elf.SHT_NULL
}

type sectionSymbols struct {
	data    *SectionData
	symbols []SymbolIndex
}
