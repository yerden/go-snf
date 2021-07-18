// +build snf_static_nopie

package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -no-pie -L/opt/snf/lib -Wl,-Bstatic -lsnf -Wl,-Bdynamic
*/
import "C"
