package syms

import (
	delf "debug/elf"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang/glog"
	"github.com/vietanhduong/profiling/pkg/proc"
	"github.com/vietanhduong/profiling/pkg/syms/elf"
	"golang.org/x/sys/unix"
)

type ProcModule struct {
	name    string
	loaded  bool
	typ     ProcModuleType
	table   SymbolTable
	path    *modulePath
	opts    *SymbolOptions
	base    uint64
	procmap *proc.Map
}

func NewProcModule(name string, procmap *proc.Map, path *modulePath, opts *SymbolOptions) *ProcModule {
	if opts == nil {
		opts = defaultSymbolOpts
	}
	this := &ProcModule{
		name:    name,
		path:    path,
		opts:    opts,
		procmap: procmap,
		typ:     getElfType(path),
		table:   &emptyTable{},
	}
	return this
}

func (m *ProcModule) Cleanup() { m.table.Cleanup(); m.path.Close() }

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

	m.loaded = false
	m.typ = getElfType(m.path)
	m.load()
	return m.table.Resolve(addr)
}

func (m *ProcModule) findbase(mf *elf.MMapedFile) bool {
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
	}()

	if m.loaded || m.typ == UNKNOWN {
		return
	}
	m.loaded = true

	mf, err := elf.NewMMapedFile(m.path.GetPath())
	if err != nil {
		glog.Errorf("Failed to open mmaped file %s: %v", m.path.GetPath(), err)
		return
	}
	defer mf.Close()
	if !m.findbase(mf) {
		glog.Warningf("Unable to determine base of elf path %s", m.path.GetPath())
		return
	}

	if m.typ == PERF_MAP {
		glog.Info("PERF_MAP is unsupported yet")
	}

	if m.typ == SO || m.typ == EXEC {
		opts := &elf.SymbolOptions{
			DemangleOpts: m.opts.DemangleType.ToOptions(),
		}

		if m.opts.UseDebugFile {
			if debugfile := m.findDebugFile(mf); debugfile != "" {
				debugmf, err := elf.NewMMapedFile(debugfile)
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
		m.table, err = CreateVDSOResolver(unix.Getpid())
		if err != nil {
			glog.Warning("Failed to create vDSO resolver: %v", err)
		}
	}
}

func (m *ProcModule) findDebugFile(mf *elf.MMapedFile) string {
	id := mf.BuildId()
	if id == nil {
		id = &elf.BuildId{}
	}
	if debugfile := m.findDebugFileViaBuildId(*id); debugfile != "" {
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

func (m *ProcModule) findDebugFileViaLink(mf *elf.MMapedFile) string {
	data, err := mf.GetSectionData(".gnu_debuglink")
	if err != nil || len(data.Data) < 6 {
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

func createSymbolTable(mf *elf.MMapedFile, opts *elf.SymbolOptions) SymbolTable {
	var ret SymbolTable
	symtbl, err := mf.NewSymbolTable(opts)
	if err != nil {
		glog.Errorf("Failed to new symbol table: %v", err)
		return nil
	}
	if ret, err = mf.NewGoTable(symtbl); err != nil {
		ret = symtbl
	}
	return ret
}

func getElfType(path *modulePath) ProcModuleType {
	mf, err := elf.NewMMapedFile(path.GetPath())
	if mf != nil {
		defer mf.Close()
		if mf.Type == delf.ET_EXEC {
			return EXEC
		} else if mf.Type == delf.ET_DYN {
			return SO
		}
		return UNKNOWN
	}
	glog.V(3).Infof("Failed to open mmaped file %s: %v", path.GetPath(), err)

	if isValidPerfMap(path.GetPath()) {
		return PERF_MAP
	}

	if isVDSO(path.GetPath()) {
		return VDSO
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
