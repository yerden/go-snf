# go-snf
[![Documentation](https://godoc.org/github.com/yerden/go-snf?status.svg)](http://godoc.org/github.com/yerden/go-snf/snf) [![Go Report Card](https://goreportcard.com/badge/github.com/yerden/go-snf)](https://goreportcard.com/report/github.com/yerden/go-snf) [![Build Status](https://travis-ci.com/yerden/go-snf.svg?branch=master)](https://travis-ci.com/yerden/go-snf)

Go wrappers for SNFv3 library supplied by CSPI for Myricom PCI-E network boards.

### Installation
Non-Go requirements:
* SNFv3, please refer to [CSPI](http://www.cspi.com) website for download and installation instructions.
* `libpcap` library and include headers. Consult your system documentation on how to install them.
* Tested on Linux environment only (Centos 7, Ubuntu Trusty).

### SNF library location
If you have SNF library installed in default location `/opt/snf` then you can simply build as it is.
If you want to test something in case you don't have installed SNF dependency you can specify `snf_mockup` build tag. In this case, all SNF calls will be implemented as stub functions.

Alternatively, you can specify SNF library custom location by supplying it in environment:
```
export CGO_CFLAGS="-I/path/to/snf/include"
export CGO_LDFLAGS="-L/path/to/snf/lib -lsnf"
```

### Caveats
The package is under development so API may experience some changes. Any contributions from Myricom NICs users are welcome.
