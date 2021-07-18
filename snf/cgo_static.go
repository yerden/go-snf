// +build !snf_mockup,snf_static

package snf

/*
#cgo LDFLAGS: -Wl,-Bstatic -lsnf -Wl,-Bdynamic
*/
import "C"
