package selfupdate

import (
	"syscall"
	"unsafe"
)

func hideFile(path string) error {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setFileAttributes := kernel32.NewProc("SetFileAttributesW")

	utf16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	r1, _, err := setFileAttributes.Call(uintptr(unsafe.Pointer(utf16)), 2)

	if r1 == 0 {
		return err
	} else {
		return nil
	}
}
