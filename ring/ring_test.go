package ring

import (
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sampleMessage struct {
	size  int
	flags int32
}

func TestRingbufReader(t *testing.T) {
	readerTests := []struct {
		name     string
		messages []sampleMessage
		want     map[int][]byte
	}{
		{
			name:     "send one short sample",
			messages: []sampleMessage{{size: 5}},
			want: map[int][]byte{
				5: {1, 2, 3, 4, 4},
			},
		},
		{
			name:     "send three short samples, the second is discarded",
			messages: []sampleMessage{{size: 5}, {size: 10}, {size: 15}},
			want: map[int][]byte{
				5:  {1, 2, 3, 4, 4},
				15: {1, 2, 3, 4, 4, 3, 2, 1, 1, 2, 3, 4, 4, 3, 2},
			},
		},
	}
	for _, tt := range readerTests {
		t.Run(tt.name, func(t *testing.T) {
			prog, events := mustOutputSamplesProg(t, tt.messages...)

			raw := make(map[int][]byte)
			callback := func(b []byte) {
				raw[len(b)] = b
			}

			rd, err := NewReader(events, Spec{Callback: callback})
			if err != nil {
				t.Fatal(err)
			}
			defer rd.Close()

			if uint32(rd.reader.BufferSize()) != 2*events.MaxEntries() {
				t.Errorf("expected %d BufferSize, got %d", events.MaxEntries(), rd.reader.BufferSize())
			}

			count, err := rd.Poll(0)
			require.NoError(t, err, "Failed to poll records")
			assert.Equal(t, 0, count)

			ret, _, err := prog.Test(make([]byte, 15))
			require.NoError(t, err)

			if errno := syscall.Errno(-int32(ret)); errno != 0 {
				t.Fatal("Expected 0 as return value, got", errno)
			}

			count, err = rd.Poll(0)
			require.NoError(t, err, "Failed to poll records")
			assert.Equal(t, len(tt.want), count)

			if diff := cmp.Diff(tt.want, raw); diff != "" {
				t.Errorf("Read samples mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func outputSamplesProg(sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map, error) {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		return nil, nil, err
	}

	var maxSampleSize int
	for _, sampleMessage := range sampleMessages {
		if sampleMessage.size > maxSampleSize {
			maxSampleSize = sampleMessage.size
		}
	}

	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0x0102030404030201, asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := (maxSampleSize / 8) + 1
	for i := 0; i < bufDwords; i++ {
		insns = append(insns,
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	for sampleIdx, sampleMessage := range sampleMessages {
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Imm(asm.R2, int32(sampleMessage.size)),
			asm.Mov.Imm(asm.R3, int32(0)),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Reg(asm.R5, asm.R0),
		)
		for i := 0; i < sampleMessage.size; i++ {
			insns = append(insns,
				asm.LoadMem(asm.R4, asm.RFP, int16(i+1)*-1, asm.Byte),
				asm.StoreMem(asm.R5, int16(i), asm.R4, asm.Byte),
			)
		}

		// discard every even sample
		if sampleIdx&1 != 0 {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufDiscard.Call(),
			)
		} else {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufSubmit.Call(),
			)
		}
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)).WithSymbol("exit"),
		asm.Return(),
	)

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "MIT",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		events.Close()
		return nil, nil, err
	}

	return prog, events, nil
}

func mustOutputSamplesProg(tb testing.TB, sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	prog, events, err := outputSamplesProg(sampleMessages...)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		prog.Close()
		events.Close()
	})

	return prog, events
}
