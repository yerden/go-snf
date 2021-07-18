// +build !snf_mockup,!snf_static_pie,!snf_static_nopie

package snf

/*
#cgo CFLAGS: -I/opt/snf/include
#cgo LDFLAGS: -L/opt/snf/lib -lsnf
*/
import "C"
