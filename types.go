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

CK_ULONG Index(CK_ULONG_PTR array, CK_ULONG i) {
	return array[i];
}

*/
import "C"

import (
	"strconv"
	"unsafe"
)

// List is used as a "generic" list as all object from PKCS#11 hold a uint (CK_ULONG).
type List []uint

// ToList converts from a C style array to a List.
func toList(clist C.CK_ULONG_PTR, size C.CK_ULONG) List {
	l := make(List, int(size))
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

func (e Error) Error() string { return "pkcs11: " + strconv.Itoa(int(e)) }

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

func NewAttribute(typ uint, x interface{}) Attribute {
	var a Attribute
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
	case uint:
		if x.(uint) <= 1<<16-1 {
			a.Value = make([]byte, 2)
			a.Value[0] = byte(x.(int) >> 8)
			a.Value[1] = byte(x.(int))
			break
		}
		if x.(uint) <= 1<<32-1 {
			a.Value = make([]byte, 4)
			a.Value[0] = byte(x.(int) >> 24)
			a.Value[1] = byte(x.(int) >> 16)
			a.Value[2] = byte(x.(int) >> 8)
			a.Value[3] = byte(x.(int))
		}
	case []byte: // just copy
		a.Value = x.([]byte)
	}
	return a
}

// cAttribute returns the start address and the length of an attribute list.
func cAttributeList(a []Attribute) (C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	if len(a) == 0 {
		return nil, 0
	}
	cp := make([]C.CK_ATTRIBUTE, len(a))
	for i := 0; i < len(a); i++ {
		var l C.CK_ATTRIBUTE
		l._type = C.CK_ATTRIBUTE_TYPE(a[i].Type)
		l.pValue = C.CK_VOID_PTR(&(a[i].Value[0]))
		l.ulValueLen = C.CK_ULONG(len(a[i].Value))
	}
	return C.CK_ATTRIBUTE_PTR(&(cp[0])), C.CK_ULONG(len(a))
}

type Date struct {
	// TODO
}

type Mechanism struct {
	Type      uint
	Parameter []byte
}

func NewMechanism(typ uint, x interface{}) Mechanism {
	var m Mechanism
	m.Type = typ
	if x == nil {
		m.Parameter = nil
		return m
	}
	// Add specific types? Ala Attributes?
	return m
}

// cMechanism returns a C pointer to the mechanism m.
func cMechanism(m Mechanism) C.CK_MECHANISM_PTR {
	var m1 C.CK_MECHANISM
	m1.mechanism = C.CK_MECHANISM_TYPE(m.Type)
	m1.pParameter = C.CK_VOID_PTR(&(m.Parameter[0]))
	m1.ulParameterLen = C.CK_ULONG(len(m.Parameter))
	return C.CK_MECHANISM_PTR(&m1)
}

type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

// stopped after this one
