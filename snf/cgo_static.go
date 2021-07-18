// +build snf_static

package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -Wl,-Bstatic -lsnf -Wl,-Bdynamic
*/
import "C"
