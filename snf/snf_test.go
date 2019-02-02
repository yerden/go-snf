package snf

import (
	"os/signal"
	"sync"
	"syscall"
)

func ExampleOpenHandle_first() {
	if err := Init(); err != nil {
		return
	}

	h, err := OpenHandle(
		0,                           // number of port
		3,                           // number of rings
		RssIP|RssSrcPort|RssDstPort, // rss flags
		PShared|RxDuplicate,         // flags
		256,                         // Megabytes for dataring size
	)

	if err != nil {
		return
	}
	defer h.Close()
}

func ExampleOpenHandle_second() {
	// this function will exit only on signals
	// SIGINT or SIGSEGV or when both goroutines
	// handling rings will exit
	if err := Init(); err != nil {
		return
	}

	// sample default handler
	h, err := OpenHandleDefaults(0)
	if err != nil {
		return
	}
	// Wait() is needed because we should wait
	// for successfull closing of rings and the handle;
	// this is especially important in main().
	defer h.Wait()
	// close handle, it's safe to close handle
	// even if it was closed before
	defer h.Close()

	// handling signals in case of abnormal exit once a
	// signal is raised all the rings and handle will be
	// closed. After that, in case the traffic handling goroutines
	// call Recv() on a ring, it will return io.EOF. This
	// would signal those goroutines to exit as well.
	signal.Notify(h.SigChannel(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGSEGV,
	)

	var wg sync.WaitGroup
	// wait for gouroutines to exit
	defer wg.Wait()
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()

	go func() {
		defer wg.Done()
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()
}

func ExampleOpenHandle_third() {
	// This function will exit only on signal
	// SIGINT or SIGSEGV
	if err := Init(); err != nil {
		return
	}

	h, err := OpenHandleDefaults(0)
	if err != nil {
		return
	}

	// handling signals in case of abnormal exit
	signal.Notify(h.SigChannel(),
		syscall.SIGINT,
		syscall.SIGSEGV,
	)

	go func() {
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()

	go func() {
		r, err := h.OpenRing()
		if err != nil {
			return
		}
		defer r.Close()
		// handle this ring and read packets
		// until io.EOF
	}()

	// once the Handle is closed we're outta here
	// Wait() is needed because we should wait
	// for successfull closing of rings and the handle
	h.Wait()
}
