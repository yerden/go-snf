# go-snf
[![Documentation](https://godoc.org/github.com/yerden/go-snf?status.svg)](http://godoc.org/github.com/yerden/go-snf/snf) [![Go Report Card](https://goreportcard.com/badge/github.com/yerden/go-snf)](https://goreportcard.com/report/github.com/yerden/go-snf) [![Build Status](https://travis-ci.com/yerden/go-snf.svg?branch=master)](https://travis-ci.com/yerden/go-snf)

Go wrappers for SNFv3 library supplied by CSPI for Myricom PCI-E network boards.

### Installation
Non-Go requirements:
* SNFv3, please refer to [CSPI](http://www.cspi.com) website for download and installation instructions.
* `libpcap` library and include headers. Consult your system documentation on how to install them.
* Tested on Linux environment only (Centos 7, Ubuntu Trusty).

By default this package assumes that SNFv3 is installed to `/opt/snf`. If it's not your case, you can specify the location with these environment variables prior to building your project:
```
export CGO_CFLAGS="-I/path/to/snf/include"
export CGO_LDFLAGS="-L/path/to/snf/lib -lsnf"
```
After that you can use the package via your preferred module management solution (`go get`, `dep` etc.). Import path is `github.com/yerden/go-snf/snf`.

Please note that your project executable would be linked to `libsnf` dynamically. Therefore, in order to run it you should specify the location of the library with `LD_LIBRARY_PATH` environment variable or `ldconfig` subsystem. `libsnf` default path in SNFv3 installation is `/opt/snf/lib`.

### Caveats
The package is under development so API may experience some changes. Any contributions from Myricom NICs users are welcome.
