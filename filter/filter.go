package bpf

// Filter interface is the implementation of packet filtering.
type Filter interface {
	// if equals zero, the packet is filtered
	Execute([]byte) int
}

// FilterFunc is a Filter interface implementation as a standalone
// function.
type FilterFunc func([]byte) int

func (f FilterFunc) Execute(b []byte) int {
	return f(b)
}
