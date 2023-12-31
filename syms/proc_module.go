package syms

import (
	delf "debug/elf"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/proc"
	"github.com/vietanhduong/profiling/syms/elf"
)

type ProcModule struct {
	name    string
	loaded  bool
	typ     ProcModuleType
	table   SymbolTable
	path    *procPath
	opts    *SymbolOptions
	base    uint64
	procmap *proc.Map
}

func NewProcModule(name string, procmap *proc.Map, path *procPath, opts *SymbolOptions) *ProcModule {
	if opts == nil {
		opts = defaultSymbolOpts
	}
	this := &ProcModule{
		name:    name,
		path:    path,
		opts:    opts,
		procmap: procmap,
		typ:     getElfType(name, path),
		table:   &emptyTable{},
		base:    0,
	}
	return this
}

func (m *ProcModule) Cleanup() {
	m.table.Cleanup()
	m.path.Close()
	if m.typ == VDSO {
		vstatus.Cleanup()
	}
}

func (m *ProcModule) Resolve(addr uint64) string {
	if !m.loaded {
		m.load()
	}

	addr -= m.base
	if sym := m.table.Resolve(addr); sym != "" {
		return sym
	}

	if !m.table.IsDead() {
		return ""
	}

	glog.Info("Retry table=%s type=%s", m.name, m.typ)
	m.loaded = false
	m.load()
	return m.table.Resolve(addr)
}

func (m *ProcModule) findbase(mf *elf.MMapedElfFile) bool {
	if mf.FileHeader.Type == delf.ET_EXEC {
		m.base = 0
		return true
	}
	for _, prog := range mf.Progs {
		if prog.Type == delf.PT_LOAD && (prog.Flags&delf.PF_X != 0) {
			if uint64(m.procmap.FileOffset) == prog.Off {
				m.base = m.procmap.StartAddr - prog.Vaddr
				return true
			}
		}
	}
	return false
}

func (m *ProcModule) load() {
	defer func() {
		// This will ensure no nil pointer error when we call table to resolve symbol
		if m.table == nil {
			m.table = &emptyTable{}
		}
		glog.V(5).Infof("Loaded symbol table (name=%s path=%s) has size: %d", m.name, m.path.GetPath(), m.table.Size())
	}()
	if m.loaded || m.typ == UNKNOWN {
		return
	}
	m.loaded = true

	if m.typ == SO || m.typ == EXEC {
		mf, err := elf.NewMMapedElfFile(m.path.GetPath())
		if err != nil {
			glog.Errorf("Failed to open mmaped file %s: %v", m.path.GetPath(), err)
			return
		}
		defer mf.Close()

		if !m.findbase(mf) {
			glog.Warningf("Unable to determine base of elf path %s", m.path.GetPath())
			return
		}

		opts := &elf.SymbolOptions{
			DemangleOpts: m.opts.DemangleType.ToOptions(),
		}

		if m.opts.UseDebugFile {
			if debugfile := m.findDebugFile(mf); debugfile != "" {
				debugmf, err := elf.NewMMapedElfFile(debugfile)
				if err != nil {
					glog.Errorf("Failed to open mmaped debug file %s: %v", debugfile, err)
					return
				}
				defer debugmf.Close()
				m.table = createSymbolTable(debugmf, opts)
			}
			return
		}

		m.table = createSymbolTable(mf, opts)
	}

	if m.typ == VDSO {
		var err error
		m.table, err = buildVDSOResolver()
		if err != nil {
			glog.Warningf("Failed to create vDSO resolver: %v", err)
		}
	}
}

func (m *ProcModule) findDebugFile(mf *elf.MMapedElfFile) string {
	id, _ := mf.BuildId()
	if debugfile := m.findDebugFileViaBuildId(id); debugfile != "" {
		return debugfile
	}
	return m.findDebugFileViaLink(mf)
}

func (m *ProcModule) findDebugFileViaBuildId(id elf.BuildId) string {
	if len(id.Id) < 3 || !id.GNU() {
		return ""
	}
	debugfile := fmt.Sprintf("/usr/lib/debug/.build-id/%s/%s.debug", id.Id[:2], id.Id[2:])
	_, err := os.Stat(filepath.Join(m.path.procRootPath, debugfile))
	if err == nil {
		return debugfile
	}
	return ""
}

func (m *ProcModule) findDebugFileViaLink(mf *elf.MMapedElfFile) string {
	data, err := mf.GetSectionData(".gnu_debuglink")
	if err != nil || data == nil || len(data.Data) < 6 {
		return ""
	}
	debuglink := cstring(data.Data)

	dir := filepath.Dir(mf.FilePath())
	paths := []string{
		// /usr/bin/ls.debug
		filepath.Join(dir, debuglink),
		// /usr/bin/.debug/ls.debug
		filepath.Join(dir, ".debug", debuglink),
		// /usr/bin/debug/usr/bin/ls.debug
		filepath.Join("/usr/lib/debug", dir, debuglink),
	}
	for _, p := range paths {
		if _, err = os.Stat(filepath.Join(m.path.procRootPath, p)); err == nil {
			return p
		}
	}
	return ""
}

func createSymbolTable(mf *elf.MMapedElfFile, opts *elf.SymbolOptions) SymbolTable {
	gotbl, _ := mf.NewGoTable(nil)

	if gotbl != nil && gotbl.Index.Entry.Length() > 0 {
		opts.FilterFrom = gotbl.Index.Entry.Get(0)
		opts.FilterTo = gotbl.Index.End
	}

	symtbl, err := mf.NewSymbolTable(opts)
	if err != nil {
		glog.V(5).Infof("Failed to create Symbol Table (ELF: %s): %v", mf.FilePath(), err)
	}
	if symtbl == nil && gotbl == nil {
		glog.Errorf("No resolve available for ELF file %s", mf.FilePath())
		return nil
	}
	if gotbl != nil {
		gotbl.SetFallback(symtbl)
		return gotbl
	}
	return symtbl
}

func getElfType(name string, path *procPath) ProcModuleType {
	if proc.IsVDSO(name) {
		return VDSO
	}

	mf, _ := elf.NewMMapedElfFile(path.GetPath())
	if mf != nil {
		defer mf.Close()
		if mf.Type == delf.ET_EXEC {
			return EXEC
		} else if mf.Type == delf.ET_DYN {
			return SO
		}
	}

	return UNKNOWN
}

func cstring(b []byte) string {
	var i int
	for ; i < len(b); i++ {
		if b[i] == 0 {
			break
		}
	}
	return string(b[:i])
}
