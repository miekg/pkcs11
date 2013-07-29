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
*/
import "C"

// A Void is used a lot in the PKCS#11 library, it always consists of a *void and a length.
// We use []byte as a subsitite in Go.
type Void []byte

type SlotID C.CK_SLOT_ID

type Error C.CK_RV

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
