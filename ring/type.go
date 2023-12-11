package ring

const DEFAULT_BUFFER_SIZE = 1024 * 1024

type Callback func(raw []byte)

type Spec struct {
	Callback   Callback
	BufferSize int
	Async      bool
}

type Raw []byte
