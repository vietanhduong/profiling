package ring

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/golang/glog"
)

var emptycb Callback = func([]byte) {}

// This can be remove after this PR is merged https://github.com/cilium/ebpf/pull/1266
type RingBuffer struct {
	reader  *ringbuf.Reader
	cb      Callback
	bufsize int
}

func NewReader(m *ebpf.Map, spec Spec) (*RingBuffer, error) {
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("new ringbuf reader: %w", err)
	}
	if spec.Callback == nil {
		spec.Callback = emptycb
	}
	bufsize := spec.BufferSize
	if bufsize <= 0 {
		bufsize = DEFAULT_BUFFER_SIZE
	}

	this := &RingBuffer{
		reader:  reader,
		bufsize: bufsize,
	}

	if spec.Async {
		this.cb = func(raw []byte) { go spec.Callback(raw) }
	} else {
		this.cb = func(raw []byte) { spec.Callback(raw) }
	}

	return this, nil
}

func (rb *RingBuffer) Close() error {
	if rb == nil || rb.reader == nil {
		return nil
	}
	return rb.reader.Close()
}

func (rb *RingBuffer) Poll(timeout time.Duration) (int, error) {
	if rb.reader == nil {
		return -1, fmt.Errorf("not initialized")
	}
	var count int

	var t time.Time
	if timeout == 0 {
		t = time.Now().Add(-10 * time.Minute)
	} else if timeout > 0 {
		t = time.Now().Add(timeout)
	}
	rb.reader.SetDeadline(t)

	for {
		reader, err := rb.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrClosed) {
				return count, nil
			}
			return -1, fmt.Errorf("ringbuf read: %w", err)
		}
		rb.cb(reader.RawSample)
		count++
	}
}

func (rb *RingBuffer) Run(stop <-chan struct{}) {
	go func() {
		<-stop
		if rb.reader != nil {
			if err := rb.reader.Close(); err != nil {
				glog.Warningf("Failed to close ring buffer: %v", err)
			}
		}
	}()
}
