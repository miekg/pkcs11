// All names loose the CK_ prefix
// All names loose the hungarian notation
// All the defines are kept from the C package so: C.CKM_RSA_X_509
// All struct's get a Go variant
//
package pkcs11

/*
#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <stdlib.h>
#include "pkcs11.h"

CK_ULONG Index(CK_ULONG_PTR array, CK_ULONG i) { return array[i]; }
CK_ULONG Sizeof() { return sizeof(CK_ULONG); }

*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ToList converts from a C style array to a []uint.
func toList(clist C.CK_ULONG_PTR, size C.CK_ULONG) []uint {
	l := make([]uint, int(size))
	for i := 0; i < len(l); i++ {
		l[i] = uint(C.Index(clist, C.CK_ULONG(i)))
	}
	defer C.free(unsafe.Pointer(clist))
	return l
}

// CBBool converts a bool to a CK_BBOOL.
func cBBool(x bool) C.CK_BBOOL {
	if x {
		return C.CK_BBOOL(C.CK_TRUE)
	}
	return C.CK_BBOOL(C.CK_FALSE)
}

type Error uint

func (e Error) Error() string {
	return "pkcs11: " + fmt.Sprintf("pkcs11: 0x%X: %s", uint(e), strerror[uint(e)])
}

func toError(e C.CK_RV) error {
	if e == C.CKR_OK {
		return nil
	}
	return Error(e)
}

type SessionHandle uint

type ObjectHandle uint

type Version struct {
	Major byte
	Minor byte
}

type Info struct {
	// TODO
}

type SlotInfo struct {
	SlotDescription [64]byte
	ManufacturerID  [32]byte
	Flags           uint
	HardwareVersion Version
	FirmwareVersion Version
}

type TokenInfo struct {
	Label              [32]byte
	ManufacturerID     [32]byte
	Model              [16]byte
	SerialNumber       [16]byte
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	hardwareVersion    Version
	firmwareVersion    Version
	UTCTime            [16]byte
}

type SessionInfo struct {
	SlotID      uint
	Sate        uint
	Flags       uint
	DeviceError uint
}

type Attribute struct {
	Type  uint
	Value []byte
}

func NewAttribute(typ uint, x interface{}) *Attribute {
	a := new(Attribute)
	a.Type = typ
	if x == nil {
		a.Value = nil
		return a
	}
	switch x.(type) {
	case bool: // create bbool
		if x.(bool) {
			a.Value = []byte{1}
			break
		}
		a.Value = []byte{0}
	case uint, int:
		var y uint
		if _, ok := x.(int); ok {
			y = uint(x.(int))
		}
		if _, ok := x.(uint); ok {
			y = x.(uint)
		}
		switch int(C.Sizeof()) {
		case 4:
			a.Value = make([]byte, 4, 4)
			a.Value[0] = byte(y)
			a.Value[1] = byte(y >> 8)
			a.Value[2] = byte(y >> 16)
			a.Value[3] = byte(y >> 24)
		case 8:
			a.Value = make([]byte, 8, 8)
			a.Value[0] = byte(y)
			a.Value[1] = byte(y >> 8)
			a.Value[2] = byte(y >> 16)
			a.Value[3] = byte(y >> 24)
			a.Value[4] = byte(y >> 32)
			a.Value[5] = byte(y >> 40)
			a.Value[6] = byte(y >> 48)
			a.Value[7] = byte(y >> 56)
		}
	case string:
		a.Value = []byte(x.(string))
	case []byte: // just copy
		a.Value = x.([]byte)
	default:
		panic("pkcs11: unhandled attribute type")
	}
	return a
}

// cAttribute returns the start address and the length of an attribute list.
func cAttributeList(a []*Attribute) (C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	if len(a) == 0 {
		return nil, 0
	}
	pa := make([]C.CK_ATTRIBUTE, len(a))
	for i := 0; i < len(a); i++ {
		pa[i]._type = C.CK_ATTRIBUTE_TYPE(a[i].Type)
		if a[i].Value == nil {
			continue
		}
		pa[i].pValue = C.CK_VOID_PTR((&a[i].Value[0]))
		pa[i].ulValueLen = C.CK_ULONG(len(a[i].Value))
	}
	return C.CK_ATTRIBUTE_PTR(&pa[0]), C.CK_ULONG(len(a))
}

type Date struct {
	// TODO
}

type Mechanism struct {
	Mechanism uint
	Parameter []byte
}

func NewMechanism(mech uint, x interface{}) *Mechanism {
	m := new(Mechanism)
	m.Mechanism = mech
	if x == nil {
		m.Parameter = nil
		return m
	}
	// TODO(mg): Not seen anything as elaborate as Attributes, so for know do nothing.
	return m
}

func cMechanismList(m []*Mechanism) (C.CK_MECHANISM_PTR, C.CK_ULONG) {
	if len(m) == 0 {
		return nil, 0
	}
	pm := make([]C.CK_MECHANISM, len(m))
	for i := 0; i < len(m); i++ {
		pm[i].mechanism = C.CK_MECHANISM_TYPE(m[i].Mechanism)
		if m[i].Parameter == nil {
			continue
		}
		pm[i].pParameter = C.CK_VOID_PTR(&(m[i].Parameter[0]))
		pm[i].ulParameterLen = C.CK_ULONG(len(m[i].Parameter))
	}
	return C.CK_MECHANISM_PTR(&pm[0]), C.CK_ULONG(len(m))
}

type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}
