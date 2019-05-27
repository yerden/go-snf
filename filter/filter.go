package filter

// Filter interface is the implementation of packet filtering.
type Filter interface {
	// if equals zero, the packet is filtered.
	//
	// fixed-size integer is used to guarantee some room for
	// possible result encoding.
	Filter([]byte) int32
}

// FilterFunc is a Filter interface implementation as a standalone
// function.
type FilterFunc func([]byte) int32

func (f FilterFunc) Filter(b []byte) int32 {
	return f(b)
}

var (
	// FilterAll is a all-denial filter.
	FilterAll = FilterFunc(func([]byte) int32 { return 0 })
	// AllowAll is a all-passing filter.
	AllowAll = FilterFunc(func([]byte) int32 { return 1 })
)
