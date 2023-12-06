package elf

import (
	"debug/elf"
	"fmt"
	"os"
	"runtime"
)

type MMapedFile struct {
	elf.FileHeader
	Sections []elf.SectionHeader
	Progs    []elf.ProgHeader

	fpath       string
	f           *os.File
	stringCache map[int]string
}

func NewMMapedFile(fpath string) (*MMapedFile, error) {
	this := &MMapedFile{fpath: fpath}
	if err := this.open(); err != nil {
		this.Close()
		return nil, err
	}

	e, err := elf.NewFile(this.f)
	if err != nil {
		this.Close()
		return nil, fmt.Errorf("elf new file: %w", err)
	}
	this.Progs = make([]elf.ProgHeader, len(e.Progs))
	this.Sections = make([]elf.SectionHeader, len(e.Sections))
	for i := range e.Progs {
		this.Progs = append(this.Progs, e.Progs[i].ProgHeader)
	}
	for i := range e.Sections {
		this.Sections = append(this.Sections, e.Sections[i].SectionHeader)
	}
	this.FileHeader = e.FileHeader
	runtime.SetFinalizer(this, (*MMapedFile).Close)
	return this, nil
}

func (mf *MMapedFile) FindSection(name string) *elf.SectionHeader {
	for i := range mf.Sections {
		if s := mf.Sections[i]; s.Name == name {
			return &s
		}
	}
	return nil
}

func (mf *MMapedFile) GetSectionData(name string) (*SectionData, error) {
	section := mf.FindSection(name)
	if section == nil {
		return nil, nil
	}
	if err := mf.open(); err != nil {
		return nil, fmt.Errorf("mmaped open: %w", err)
	}

	data := make([]byte, section.Size)
	if _, err := mf.f.ReadAt(data, int64(section.Offset)); err != nil {
		return nil, fmt.Errorf("os file read at: %w", err)
	}
	return &SectionData{data, section}, nil
}

func (mf *MMapedFile) FilePath() string { return mf.fpath }

func (mf *MMapedFile) Close() {
	if mf.f != nil {
		mf.f.Close()
		mf.f = nil
	}
	mf.stringCache = nil
	mf.Sections = nil
}

func (mf *MMapedFile) IsDead() bool {
	_, err := os.Stat(mf.fpath)
	return err != nil
}

func (mf *MMapedFile) open() error {
	if mf.f != nil {
		return nil
	}
	var err error
	mf.f, err = open(mf.fpath)
	return err
}

func (mf *MMapedFile) findSectionByType(styp elf.SectionType) *elf.SectionHeader {
	for i := range mf.Sections {
		if s := &mf.Sections[i]; s.Type == styp {
			return s
		}
	}
	return nil
}

func open(fpath string) (*os.File, error) {
	fd, err := os.OpenFile(fpath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open elf file %s: %w", fpath, err)
	}
	return fd, nil
}
