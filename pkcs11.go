package pkcs11

/*
#cgo LDFLAGS: -lltdl
#include <string.h>
#include "pkcs11c"

CK_SLOT_INFO_PTR SlotIndex(CK_SLOT_INFO_PTR *l, int i) { return l[i]; } 
CK_TOKEN_INFO_PTR TokenIndex(CK_TOKEN_INFO_PTR *l, int i) { return l[i]; } 
CK_SLOT_INFO_PTR SlotNew() { CK_SLOT_INFO_PTR s = NULL; return s; }
CK_TOKEN_INFO_PTR TokenNew() { CK_TOKEN_INFO_PTR t = NULL; return t; }
CK_ULONG UlongNew() { CK_ULONG u = 0; return u; }
*/
import "C"

import (
	"unsafe"
)

// TODO: error type
// TODO: documentation

// Pkcs11 ....
type Pkcs11 struct {
	ctx *C.struct_ctx
}

// Slot is ...
type Slot struct {
	slotId       int
	Manufacturer string
	Description  string
	Removable    bool
	// Hardwareversion ??
	*Token
}

// Token is ..
type Token struct {
	parent             *Pkcs11 // parent ctx
	slotId             int     // parent Slot id
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
	p.ctx = C.New(mod)
	if p.ctx == nil {
		return nil
	}
	return p
}

// Destroy unload the module and frees any remaining memory.
func (p *Pkcs11) Destroy() {
	if p == nil {
		return
	}
	C.Destroy(p.ctx)
}

// Slots returns all available slots in the system.
func (p *Pkcs11) Slots() (s []*Slot, e error) {
	slots := C.SlotNew()
	tokens := C.TokenNew()
	nslots := C.UlongNew()
	if rv := C.Slots(p.ctx, &slots, &tokens, &nslots); rv != 0 {
		return nil, nil // TODO(mg): error
	}
	for i := 0; i < int(nslots); i++ {
		o := new(Slot)
		o.slotId = i
		o.Description = string(C.GoBytes(unsafe.Pointer(&C.SlotIndex(&slots, C.int(i)).slotDescription), 64))
		o.Manufacturer = string(C.GoBytes(unsafe.Pointer(&C.SlotIndex(&slots, C.int(i)).manufacturerID), 32))
		o.Removable = int(C.SlotIndex(&slots, C.int(i)).flags)&C.CKF_REMOVABLE_DEVICE == C.CKF_REMOVABLE_DEVICE
		if C.TokenIndex(&tokens, C.int(i)) != nil {
			t := new(Token)
			t.parent = p
			t.slotId = o.slotId
			t.Label = string(C.GoBytes(unsafe.Pointer(&C.TokenIndex(&tokens, C.int(i)).label), 32))
			t.Manufacturer = string(C.GoBytes(unsafe.Pointer(&C.TokenIndex(&tokens, C.int(i)).manufacturerID), 32))
			t.Model = string(C.GoBytes(unsafe.Pointer(&C.TokenIndex(&tokens, C.int(i)).manufacturerID), 16))
			t.Serial = string(C.GoBytes(unsafe.Pointer(&C.TokenIndex(&tokens, C.int(i)).serialNumber), 16))

			t.HasRandGenerator = int(C.TokenIndex(&tokens, C.int(i)).flags)&C.CKF_RNG == C.CKF_RNG
			t.ReadOnly = int(C.TokenIndex(&tokens, C.int(i)).flags)&C.CKF_WRITE_PROTECTED == C.CKF_WRITE_PROTECTED
			t.LoginRequired = int(C.TokenIndex(&tokens, C.int(i)).flags)&C.CKF_LOGIN_REQUIRED == C.CKF_LOGIN_REQUIRED
			t.UserPinSet = int(C.TokenIndex(&tokens, C.int(i)).flags)&C.CKF_USER_PIN_INITIALIZED == C.CKF_USER_PIN_INITIALIZED
			t.Initialized = int(C.TokenIndex(&tokens, C.int(i)).flags)&C.CKF_TOKEN_INITIALIZED == C.CKF_TOKEN_INITIALIZED

			o.Token = t
		}
		s = append(s, o)
	}
	return
}

// Init initializes a token.
func (t *Token) Init(sopin, label string) error {
	cpin := C.CString(sopin)
	clab := C.CString(label) // 32 bytes, padded with spaces
	t1 := C.TokenNew()
	defer C.free(unsafe.Pointer(cpin))
	defer C.free(unsafe.Pointer(clab))
	defer C.free(unsafe.Pointer(t1))

	rv := C.InitToken(t.parent.ctx, &t1, C.uint(t.slotId), cpin, C.uint(len(sopin)), clab)
	if rv != 0 {
		return nil // TODO(mg): error
	}
	// TODO: more
	t.Label = string(C.GoBytes(unsafe.Pointer(&t1.label), 32))
	t.Initialized = int(t1.flags)&C.CKF_TOKEN_INITIALIZED == C.CKF_TOKEN_INITIALIZED
	return nil
}
