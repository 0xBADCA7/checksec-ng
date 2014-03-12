package main

// #cgo LDFLAGS: -larchive -lm -lrpm -lrpmio -lpopt
// #include <archive.h>
// #include <archive_entry.h>
// #include <rpm/rpmlib.h>
// #include <rpm/rpmio.h>
// #include <rpm/rpmts.h>
// #include <rpm/rpmte.h>
// #include <rpm/rpmcli.h>
// #include <rpm/rpmdb.h>
// #include <rpm/header.h>
// #include <math.h>
// #include <stdlib.h>
import "C"

import "github.com/davecheney/profile"

import (
	"bytes"
	// "crypto/md5"
	"debug/dwarf"
	"debug/elf"
	// "encoding/hex"
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unsafe"
)

// https://code.google.com/p/go-wiki/wiki/cgo
// http://blog.golang.org/c-go-cgo

// set of all "debuginfo" packages
var debug_packages map[string]bool

// set of all normal (non-debuginfo) packages
var packages map[string]bool

// "-debuginfo-" RPMs -> (ELF, ELF + .debug)
type mapping struct {
	ELF, debug string
}

var ELFs map[string][]mapping

const (
	INVALID  = "Not an ELF binary"
	DISABLED = "Disabled"
	ENABLED  = "Enabled"
	PARTIAL  = "Partial"
	SEP      = ","
)

type checker func(file *elf.File) string

var checks = []struct {
	name string
	run  checker
}{
	{"NX", nx},
	{"CANARY", canary},
	{"RELRO", relro},
	{"PIE", pie},
	{"RPATH", rpath},
	{"RUNPATH", runpath},
}

func is_ELF(content []byte) bool {

	return bytes.HasPrefix(content, []byte{0x7f, 'E', 'L', 'F'})
}

func is_folder(name string) bool {
	finfo, err := os.Stat(name)
	if err != nil {
		fmt.Println(err, "\n")
		return false
	}

	return finfo.IsDir()
}

func dwzparser(dwzfile *elf.File, offset int64) string {
	if section := dwzfile.Section(".debug_str"); section != nil {
		reader := io.NewSectionReader(section, 0, int64(section.Size))
		reader.Seek(offset, 1)
		bufreader := bufio.NewReader(reader)
		str, _ := bufreader.ReadString('\x00') // XXX
		return str
	}

	panic("dwzparser ran into problems ;(")
	return ":-)"
}

func producer(debugfile *elf.File, dwzfile *elf.File) {

	// iterate over all CUs present in debugfile
	d, e := debugfile.DWARF()

	if e != nil {
		fmt.Println(e)
		panic("no DWARF info found?")
		return
	}

	reader := d.Reader()

	for {
		entry, err := reader.Next()
		if entry == nil {
			break
		}

		if err != nil {
			fmt.Println(err)
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			for _, f := range entry.Field {
				if f.Attr == dwarf.AttrName {
					// fmt.Println(f.Attr)
					// fmt.Println(f.Val)
					// fmt.Println(f.Fmt)
					// DW_FORM_GNU_strp_alt (0x1f21)
					if f.Fmt == 0x1f21 {
						fmt.Println(dwzparser(dwzfile, f.Val.(int64)))
					} else if f.Fmt == 0x1f20 {
						panic("DW_FORM_GNU_ref_alt handling missing for dwarf.AttrName ;(")
					} else if f.Fmt == 0x0e { // formStrp
						fmt.Println(f.Val)
					} else if f.Fmt == 0x08 { // formString
						fmt.Println(f.Val)
					} else {
						fmt.Println("form unhandled for dwarf.AttrName with form %s", f.Fmt)
						panic(";(")
					}

				} else if f.Attr == dwarf.AttrProducer {
					// fmt.Println(f.Attr)
					// mt.Println(f.Val)
					// fmt.Println(f.Fmt)
					// DW_FORM_GNU_strp_alt (0x1f21)
					if f.Fmt == 0x1f21 {
						fmt.Println(dwzparser(dwzfile, f.Val.(int64)))
					} else if f.Fmt == 0x1f20 {
						panic("DW_FORM_GNU_ref_alt handling missing for dwarf.AttrProducer ;(")
					} else if f.Fmt == 0x0e { // formStrp
						fmt.Println(f.Val)
					} else if f.Fmt == 0x08 { // formString
						fmt.Println(f.Val)
					} else {
						fmt.Println("form unhandled for dwarf.AttrProducer with form %s", f.Fmt)
						panic(";(")
					}

					// DW_FORM_GNU_ref_alt (0x1f20)
				}
			}
			// v, OK := entry.Val("DW_AT_producer")
			// fmt.Println(v)
		}
	}
}

func process_archive(filename string) {
	cfilename := C.CString(filename)
	cmode := C.CString("r")
	C.rpmInitCrypto()
	defer C.rpmFreeCrypto()

	// is filename an RPM file?
	if strings.HasSuffix(filename, ".rpm") {
		// extract metadata (RPM headers) from filename
		fd := C.Fopen(cfilename, cmode)
		var hdr C.Header
		ts := C.rpmtsCreate()
		C.rpmtsSetRootDir(ts, nil)
		C.rpmtsSetVSFlags(ts, C._RPMVSF_NOSIGNATURES)
		rc := C.rpmReadPackageFile(ts, fd, cfilename, &hdr)

		if rc != C.RPMRC_OK {
			fmt.Println("[-] %s, broken RPM?", filename)
			panic(";)")
		}

		// extract various "tags" from the RPM file
		csrpm := C.headerGetAsString(hdr, C.RPMTAG_SOURCERPM)
		srpm := C.GoString(csrpm)
		C.free((unsafe.Pointer)(csrpm))

		// cnvr := C.headerGetAsString(hdr, C.RPMTAG_NVRA)
		// nvr := C.GoString(cnvr)
		// fmt.Println(nvr)

		// determine the name of debuginfo package from srpm name
		re := regexp.MustCompile("(?P<name>.*)-.*-.*")
		res := re.FindAllStringSubmatch(srpm, -1)[0]
		if len(res) == 0 {
			fmt.Println("[-] %s, SRPM name missing?", filename)
			return
		}
		names := re.SubexpNames()
		md := map[string]string{}
		for i, n := range res {
			md[names[i]] = n
		}
		target_debug_package := md["name"] + "-debuginfo-"
		// fmt.Println(target_debug_package)

		// do we have this "target_debug_package" in "debug_packages"?
		debug_package := ""
		re = regexp.MustCompile(target_debug_package)
		for name, _ := range debug_packages {
			if re.MatchString(path.Base(name)+"\\d") == true {
				debug_package = name
			}
		}
		if debug_package == "" {
			fmt.Println("[-] %s, debuginfo missing?", filename)
			return
		}
		fmt.Println(debug_package)
		C.rpmtsClean(ts)
		C.rpmtsFree(ts)
		C.Fclose(fd)
		C.headerFree(hdr)
		C.rpmFreeRpmrc()

		// OK dhiru

		// create a lookup table for the files in debuginfo RPM
		// libarchive is too slow for doing this due to lzma decoding!
		debug_files := make(map[string]bool)
		dcfilename := C.CString(debug_package)
		dfd := C.Fopen(dcfilename, cmode)
		C.free(unsafe.Pointer(cmode))
		C.free(unsafe.Pointer(dcfilename))
		var dhdr C.Header
		dts := C.rpmtsCreate()
		C.rpmtsSetVSFlags(dts, C._RPMVSF_NOSIGNATURES)
		drc := C.rpmReadPackageFile(dts, dfd, dcfilename, &dhdr)
		if drc != C.RPMRC_OK {
			fmt.Println("[-] %s, broken RPM?", filename)
			return
		}
		fi := C.rpmfiNew(dts, dhdr, C.RPMTAG_BASENAMES, C.RPMFI_FLAGS_QUERY)
		fi = C.rpmfiInit(fi, 0)
		for C.rpmfiNext(fi) >= 0 {
			fn := C.rpmfiFN(fi)
			gfn := C.GoString(fn)
			if strings.HasSuffix(gfn, ".debug") {
				debug_files[gfn] = true
			}
		}
		// cleanup stuff
		C.rpmfiFree(fi)
		C.rpmtsClean(dts)
		C.rpmtsFree(dts)
		C.rpmFreeRpmrc()
		C.Fclose(dfd)
		C.headerFree(dhdr)

		// OK dhiru

		// process all ELF files in "filename"
		a := C.archive_read_new()
		defer C.archive_read_free(a)
		C.archive_read_support_filter_all(a)
		C.archive_read_support_format_all(a)
		r := C.archive_read_open_filename(a, cfilename, 10240)
		C.free(unsafe.Pointer(cfilename))
		if r != C.ARCHIVE_OK {
			fmt.Println("[-] %s, broken archive?", filename)
			return
		}
		entry := C.archive_entry_new()
		for C.archive_read_next_header(a, &entry) == C.ARCHIVE_OK {
			f := C.archive_entry_pathname(entry)
			name := C.GoString(f)
			size := C.archive_entry_size(entry)

			// allocate buffer for reading data
			cbuf := unsafe.Pointer((*C.char)(C.malloc((C.size_t)(size))))
			_ = C.archive_read_data(a, cbuf, C.size_t(size))
			data := (*[1 << 30]byte)(unsafe.Pointer(cbuf))[:size]

			// is this entry an ELF? partial reading of 4 bytes isn't much faster
			if !is_ELF(data) {
				continue
			}

			// locate the correct corresponding ".debug" file
			debugfile := ""
			t := path.Base(name) + ".debug"
			for dname, _ := range debug_files {
				if strings.HasSuffix(dname, t) == true {
					debugfile = dname
				}
			}
			if debugfile == "" {
				fmt.Println("[-]", path.Base(filename), "is missing .debug file for", name)
				continue
			}

			if len(data) > 0 {
				file, e := elf.NewFile(bytes.NewReader(data))
				if e != nil {
					fmt.Println(INVALID)
					C.free(cbuf)
					continue
				}
				fmt.Printf("%s,", name)
				checksec(file)
				C.free(cbuf) // deferring this doesn't work very well
			} else {
				C.free(cbuf)
			}
			mapping_entry := mapping{name, debugfile}
			ELFs[debug_package] = append(ELFs[debug_package], mapping_entry)
		}

		if len(ELFs) == 0 {
			// nothing to do further!
			return
		}
	} else {
		// panic("Unexpected control flow ;(")
	}
}

func worker(debug_package string, mappings []mapping) {
	//// producer handling stuff, almost all time is (should be) spent here! ////
	fmt.Println(mappings)
	cfilename := C.CString(debug_package)
	a := C.archive_read_new()
	C.archive_read_support_filter_all(a)
	C.archive_read_support_format_all(a)
	r := C.archive_read_open_filename(a, cfilename, 30240)
	if r != C.ARCHIVE_OK {
		fmt.Println("[-] %s, broken archive?", debug_package)
	}

	// get the "dwz" content for this debug_package
	pentry := C.archive_entry_new()
	var dwzfile *elf.File

	for C.archive_read_next_header(a, &pentry) == C.ARCHIVE_OK {
		f := C.archive_entry_pathname(pentry)
		entryname := C.GoString(f)
		size := C.archive_entry_size(pentry)

		// skip folders
		mode := C.archive_entry_mode(pentry)
		gmode := int(mode)
		if gmode&0040000 != 0 {
			continue
		}

		// get the "dwz" content for this debug_package
		if strings.Contains(entryname, "lib/debug/.dwz/") {
			dwzbuf := unsafe.Pointer((*C.char)(C.malloc((C.size_t)(size))))
			_ = C.archive_read_data(a, dwzbuf, C.size_t(size))

			// C array to Go array without explicit copying
			// https://code.google.com/p/go-wiki/wiki/cgo
			dwzdata := (*[1 << 30]byte)(unsafe.Pointer(dwzbuf))[:size]
			if len(dwzdata) > 0 {
				dwzfile, _ = elf.NewFile(bytes.NewReader(dwzdata))
			}
			break
		}
	}
	// cleanups
	// C.archive_read_free(a)

	// process ".debug" files
	var debugfile *elf.File
	var e error
	a = C.archive_read_new()
	defer C.archive_read_free(a)
	C.archive_read_support_filter_all(a)
	C.archive_read_support_format_all(a)
	pentry = C.archive_entry_new()
	C.archive_read_open_filename(a, cfilename, 30240)
	for C.archive_read_next_header(a, &pentry) == C.ARCHIVE_OK {
		f := C.archive_entry_pathname(pentry)
		entryname := C.GoString(f)
		size := C.archive_entry_size(pentry)

		// skip folders
		mode := C.archive_entry_mode(pentry)
		gmode := int(mode)
		if gmode&0040000 != 0 {
			continue
		}
		// skip zero sized entries
		if size == 0 {
			continue
		}
		// skip non-debug files
		if !strings.HasSuffix(entryname, ".debug") {
			continue
		}

		found := false

		for _, v := range mappings {
			if strings.HasSuffix(entryname, v.debug) {
				found = true
			}

		}
		if !found {
			continue
		}
		// allocate buffer for reading data
		cbuf := unsafe.Pointer((*C.char)(C.malloc((C.size_t)(size))))
		_ = C.archive_read_data(a, cbuf, C.size_t(size))
		data := (*[1 << 30]byte)(unsafe.Pointer(cbuf))[:size]
		// hasher := md5.New()
		// hasher.Write([]byte(data))
		// fmt.Println(hex.EncodeToString(hasher.Sum(nil)))
		if len(data) > 0 {
			debugfile, e = elf.NewFile(bytes.NewReader(data))
			if e != nil {
				fmt.Println(e, "FFF", data[1:3], len(data))
				continue
			}
		} else {
			fmt.Println(len(data), "YYY!")
		}
		// real action
		producer(debugfile, dwzfile)
	}
}

func checksec(file *elf.File) {

	for _, check := range checks {
		fmt.Print(check.name, "=", check.run(file))
		fmt.Print(SEP)
	}
	// producer(file)
	fmt.Println()
}

func usage() {
	fmt.Printf("Usage %s <path to RPM files>\n", os.Args[0])
}

func visit_debuginfo(path string, f os.FileInfo, err error) error {
	// is path a "debuginfo" RPM?
	if strings.Contains(path, "-debuginfo-") && !is_folder(path) {
		fmt.Printf("[D] Visited: %s\n", path)
		debug_packages[path] = true
	}
	return nil
}

func visit_package(path string, f os.FileInfo, err error) error {
	// is path a "debuginfo" RPM?
	if !strings.Contains(path, "-debuginfo-") && !is_folder(path) {
		fmt.Printf("[P] Visited: %s\n", path)
		packages[path] = true
		process_archive(path)
	}
	return nil
}

func main() {
	// flag.Parse()
	// root := flag.Arg(0)
	defer profile.Start(profile.MemProfile).Stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(-1)
	}

	// we expect os.Args[1] to be a folder
	name := os.Args[1]
	if !is_folder(name) {
		usage()
		os.Exit(-1)
	}

	// initialization stuff
	debug_packages = make(map[string]bool)
	packages = make(map[string]bool)
	ELFs = make(map[string][]mapping)
	runtime.GOMAXPROCS(2)

	// make a map of all "debuginfo" packages
	filepath.Walk(name, visit_debuginfo)

	// scan all normal (non-debuginfo) packages
	filepath.Walk(name, visit_package)

	fmt.Println(ELFs)

	for k, v := range ELFs {
		worker(k, v)
	}
}
