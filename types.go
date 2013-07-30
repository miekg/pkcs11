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

import "unsafe"

// A Void is used a lot in the PKCS#11 library, it always consists of a *void and a length.
// We use []byte as a subsitite in Go.
type Void []byte

type List []uint

// Convert from a C style array to a List
func ToList(clist C.CK_ULONG_PTR, size C.CK_ULONG) List {
	l := make(List, int(size))
	for i := 0; i < len(l); i++ {
		l[i] = uint(C.Index(clist, C.CK_ULONG(i)))
	}
	defer C.free(unsafe.Pointer(clist))
	return l
}

func CBBool(x bool) C.CK_BBOOL {
	if x {
		return C.CK_BBOOL(C.CK_TRUE)
	}
	return C.CK_BBOOL(C.CK_FALSE)
}

// SlotID is a identifier for a particular slot
type SlotID uint

type Error uint

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
	Flags           C.CK_FLAGS
	HardwareVersion Version
	FirmwareVersion Version
}

type TokenInfo struct {
	Label              [32]byte
	ManufacturerID     [32]byte
	Model              [16]byte
	SerialNumber       [16]byte
	Flags              C.CK_FLAGS
	MaxSessionCount    C.CK_ULONG
	SessionCount       C.CK_ULONG
	MaxRwSessionCount  C.CK_ULONG
	RwSessionCount     C.CK_ULONG
	MaxPinLen          C.CK_ULONG
	MinPinLen          C.CK_ULONG
	TotalPublicMemory  C.CK_ULONG
	FreePublicMemory   C.CK_ULONG
	TotalPrivateMemory C.CK_ULONG
	FreePrivateMemory  C.CK_ULONG
	hardwareVersion    Version
	firmwareVersion    Version
	UTCTime            [16]byte
}

type SessionInfo struct {
	SlotID      C.CK_SLOT_ID
	Sate        C.CK_STATE
	Flags       C.CK_FLAGS
	DeviceError C.CK_ULONG
}

type Attribute struct {
	Type  C.CK_ATTRIBUTE_TYPE
	Value Void
}

type Date struct {
	// TODO
}

type Mechanism struct {
	Type      C.CK_MECHANISM_TYPE
	Parameter Void
}

type MechanismInfo struct {
	MinKeySize C.CK_ULONG
	MaxKeySize C.CK_ULONG
	Flags      C.CK_FLAGS
}

// stopped after this one
