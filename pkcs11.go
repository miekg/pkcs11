package pkcs11

/*
#cgo LDFLAGS: -lltdl
#include "pkcs11c"
*/
import "C"

import (
	"unsafe"
)
// TODO: error type

// Pkcs11 ....
type Pkcs11 struct {
	ctx *C.struct_ctx
}

// Slot is slot within an HSM.
type Slot struct {
	Manufacturer string
	Description  string
	Removable    bool
	*Token
}

type Token struct {
	Label              string
	Manufacturer       string
	Model              string
	Serial             string
	Initialized        bool
	LoginRequired      bool
	SecureLogin        bool
	UserPinSet         bool
	ReadOnly           bool
	HasRandGenerator   bool
	UserPinCountLow    bool
	UserPinFinalTry    bool
	UserPinLocked      bool
	UserPinToBeChanged bool
	SoPinCountLow      bool
	SoPinFinalTry      bool
	SoPinLocked        bool
	SoPinToBeChanged   bool
}

// New returns a new instance of an pkcs11 struct. The dynamic Pkcs11 library is
// loaded and initialized. New returns nil on error.
func New(module string) *Pkcs11 {
	p := new(Pkcs11)
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	p.ctx = C.CNew(mod)
	return p
}

// Destroy unload the module and frees any remaining memory.
func (p *Pkcs11) Destroy() {
	if p == nil {
		return
	}
	C.CDestroy(p.ctx)
}

// Slots returns all available slots in the system.
func (p *Pkcs11) Slots() ([]*Slot, error) {
	
}
