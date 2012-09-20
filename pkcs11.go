package pkcs11

/*
#cgo LDFLAGS: -lp11
#include <libp11.h>
PKCS11_SLOT * slotNew() {
	PKCS11_SLOT *sl = NULL;
	return sl;
}
PKCS11_SLOT * slotIndex(PKCS11_SLOT **l, int i) {
	return l[i];
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

type Pkcs11Error struct {
	err string
}

func (e *Pkcs11Error) Error() string {
	return "pkcs11: " + e.err
}

func newError(s string) error {
	e := new(Pkcs11Error)
	e.err = s
	return e
}

// New creates a new pkcs11 context.
func New() *Pkcs11 {
	p := new(Pkcs11)
	p.ctx = C.PKCS11_CTX_new()
	return p
}

// Destroy destroy a pkcs11 context.
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
func (p *Pkcs11) Slots() (s []Slot, e error) {
	slot := C.slotNew()
	nslot := C.uintNew()
	rc := C.PKCS11_enumerate_slots(p.ctx, &slot, &nslot)
	if rc < 0 {
		return nil, newError("no slots available")
	}
	// Loop through the slots and copy them into Go Slots
	for i := 0; i < int(nslot); i++ {
		s1 := Slot{}
		s1.Manufacturer = C.GoString(C.slotIndex(&slot, C.int(i)).manufacturer)
		s1.Description = C.GoString(C.slotIndex(&slot, C.int(i)).description)
		s1.Removable = int(C.slotIndex(&slot, C.int(i)).removable) == 1
		if C.slotIndex(&slot, C.int(i)).token != nil {
			t := new(Token)
			t.Label = C.GoString(C.slotIndex(&slot, C.int(i)).token.label)
			t.Manufacturer = C.GoString(C.slotIndex(&slot, C.int(i)).token.manufacturer)
			t.Model = C.GoString(C.slotIndex(&slot, C.int(i)).token.model)
			t.Serial = C.GoString(C.slotIndex(&slot, C.int(i)).token.serialnr)

			t.Initialized = int(C.slotIndex(&slot, C.int(i)).token.initialized) == 1
			t.LoginRequired = int(C.slotIndex(&slot, C.int(i)).token.loginRequired) == 1
			t.SecureLogin = int(C.slotIndex(&slot, C.int(i)).token.secureLogin) == 1
			t.UserPinSet = int(C.slotIndex(&slot, C.int(i)).token.userPinSet) == 1
			t.ReadOnly = int(C.slotIndex(&slot, C.int(i)).token.readOnly) == 1
			t.HasRandGenerator = int(C.slotIndex(&slot, C.int(i)).token.hasRng) == 1
			t.UserPinCountLow = int(C.slotIndex(&slot, C.int(i)).token.userPinCountLow) == 1
			t.UserPinFinalTry = int(C.slotIndex(&slot, C.int(i)).token.userPinFinalTry) == 1
			t.UserPinLocked = int(C.slotIndex(&slot, C.int(i)).token.userPinLocked) == 1
			t.UserPinToBeChanged = int(C.slotIndex(&slot, C.int(i)).token.userPinToBeChanged) == 1
			t.SoPinCountLow = int(C.slotIndex(&slot, C.int(i)).token.soPinCountLow) == 1
			t.SoPinFinalTry = int(C.slotIndex(&slot, C.int(i)).token.soPinFinalTry) == 1
			t.SoPinLocked = int(C.slotIndex(&slot, C.int(i)).token.soPinLocked) == 1
			t.SoPinToBeChanged = int(C.slotIndex(&slot, C.int(i)).token.soPinToBeChanged) == 1
			s1.Token = t
		}
		s = append(s, s1)
	}
	return
}
