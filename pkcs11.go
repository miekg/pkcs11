package pkcs11

/*
#cgo LDFLAGS: -lp11
#include <libp11.h>
PKCS11_SLOT ** slotNew() {
	PKCS11_SLOT **sl;
	return sl;
}
unsigned int uintNew() {
	unsigned int p = 0;
	return p;
}
*/
import "C"

import (
	"unsafe"
)

type Pkcs11 struct {
	ctx *C.PKCS11_CTX
}

type Slot struct {
	Manufacturer string
	Description string
	Removable bool
	Tokens []Token
}

type Token struct {
	// ...
}

// New creates a new pkcs11 context.
func New() *Pkcs11 {
	p := new(Pkcs11)
	p.ctx = C.PKCS11_CTX_new()
	return p
}

func (p *Pkcs11) Destroy() {
	C.PKCS11_CTX_free(p.ctx)
}

// Load loads an engine into p.
func (p *Pkcs11) Load(engine string) error {
	cengine := C.CString(engine)
	defer C.free(unsafe.Pointer(cengine))
	rc := C.PKCS11_CTX_load(p.ctx, cengine)
	if rc == 0 {
		return nil
	}
	return nil // TODO(mg): make real error
}

func (p *Pkcs11) Unload() {
	C.PKCS11_CTX_unload(p.ctx)
}

// Slots enumerates all slots.
func (p *Pkcs11) Slots() ([]Slot, error) {
	slot := C.slotNew()
	nslot := C.uintNew()
	C.PKCS11_enumerate_slots(p.ctx, slot, nslot)
	return nil, nil
}
