// +build snf_static_pie

package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -Wl,-Bstatic -lsnf -Wl,-Bdynamic
*/
import "C"
