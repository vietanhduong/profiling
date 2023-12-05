package elf

import (
	"bytes"
	"encoding/hex"
)

func (mf *MMapedFile) BuildId() *BuildId {
	if id := mf.GnuBuildId(); id != nil {
		return id
	}
	return mf.GoBuildId()
}

func (mf *MMapedFile) GoBuildId() *BuildId {
	sd, err := mf.GetSectionData(".note.go.buildid")
	if err != nil || sd == nil || len(sd.Data) < 17 {
		return nil
	}
	data := sd.Data[16 : len(sd.Data)-1]
	if len(data) < 40 || bytes.Count(data, []byte(`/`)) < 2 || string(data) == "redacted" {
		return nil
	}
	id := GoBuildId(string(data))
	return &id
}

func (mf *MMapedFile) GnuBuildId() *BuildId {
	sd, err := mf.GetSectionData(".note.gnu.build-id")
	if err != nil || sd == nil || len(sd.Data) < 16 {
		return nil
	}
	if !bytes.Equal([]byte("GNU"), sd.Data[12:15]) {
		return nil
	}
	// 8 is xxhash, for example in Container-Optimized OS
	raw := sd.Data[16:]
	if len(raw) != 20 && len(raw) != 8 {
		return nil
	}
	id := GnuBuildId(hex.EncodeToString(raw))
	return &id
}
