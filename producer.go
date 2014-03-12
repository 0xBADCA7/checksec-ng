package main

// #cgo LDFLAGS: -larchive -lm
// #include <archive.h>
// #include <archive_entry.h>
// #include <math.h>
// #include <stdlib.h>
import "C"
import "unsafe"
import "fmt"

func mememe(filename string) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))

	a := C.archive_read_new()
	defer C.archive_read_free(a)

	C.archive_read_support_filter_all(a)
	C.archive_read_support_format_all(a)

	r := C.archive_read_open_filename(a, cfilename, 10240)

	if r != C.ARCHIVE_OK {
		fmt.Printf("FFF")
	}

	var entry *C.struct_archive_entry

	for C.archive_read_next_header(a, &entry) == C.ARCHIVE_OK {
		f := C.archive_entry_pathname(entry)
		fmt.Printf(C.GoString(f))
		// C.archive_read_data_skip(a)
	}
}
