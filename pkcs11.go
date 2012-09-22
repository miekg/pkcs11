// Package pkcs11 provides an interface to the PKCS#11 API.
//
//
package pkcs11

/*
#cgo LDFLAGS: -lltdl
#include <string.h>
#include "pkcs11c"

CK_SLOT_ID_PTR SlotIDIndex(CK_SLOT_ID_PTR *p, int i) { return p[i]; } 

CK_TOKEN_INFO_PTR TokenIndex(CK_TOKEN_INFO_PTR *l, int i) { return l[i]; } 
*/
import "C"

import (
	"strconv"
	"unsafe"
)

func versionFromC(v C.CK_VERSION) *Version {
	v1 := new(Version)
	v1.Major = byte(v.major)
	v1.Minor = byte(v.minor)
	return v1
}

func stringFromC(p unsafe.Pointer, i int) string {
	return string(C.GoBytes(p, C.int(i)))
}

func infoFromC(pInfo C.CK_INFO_PTR) *Info {
	i := new(Info)
	i.ManufacturerID = stringFromC(unsafe.Pointer(&(pInfo.manufacturerID)), 32)
	i.CryptokiVersion = versionFromC(pInfo.cryptokiVersion)
	i.Flags = uint(pInfo.flags)
	i.LibraryDescription = stringFromC(unsafe.Pointer(&(pInfo.libraryDescription)), 32)
	i.LibraryVersion = versionFromC(pInfo.libraryVersion)
	return i
}

func slotInfoFromC(pSlotInfo C.CK_SLOT_INFO_PTR) *SlotInfo {
	i := new(SlotInfo)
	i.SlotDescription = stringFromC(unsafe.Pointer(&(pSlotInfo.slotDescription)), 64)
	i.ManufacturerID = stringFromC(unsafe.Pointer(&(pSlotInfo.manufacturerID)), 32)
	i.Flags = uint(pSlotInfo.flags)
	i.HardwareVersion = versionFromC(pSlotInfo.hardwareVersion)
	i.FirmwareVersion = versionFromC(pSlotInfo.firmwareVersion)
	return i
}

func tokenInfoFromC(pTokenInfo C.CK_TOKEN_INFO_PTR) *TokenInfo {
	t := new(TokenInfo)
	t.Label = stringFromC(unsafe.Pointer(&(pTokenInfo.label)), 32)
	t.ManufacturerID = stringFromC(unsafe.Pointer(&(pTokenInfo.manufacturerID)), 32)
	t.Model = stringFromC(unsafe.Pointer(&(pTokenInfo.model)), 16)
	t.SerialNumber = stringFromC(unsafe.Pointer(&(pTokenInfo.serialNumber)), 16)
	t.Flags = uint(pTokenInfo.flags)
	t.MaxSessionCount = uint(pTokenInfo.ulMaxSessionCount)
	t.SessionCount = uint(pTokenInfo.ulSessionCount)
	t.MaxRwSessionCount = uint(pTokenInfo.ulMaxRwSessionCount)
	t.RwSessionCount = uint(pTokenInfo.ulRwSessionCount)
	t.MaxPinLen = uint(pTokenInfo.ulMaxPinLen)
	t.MinPinLen = uint(pTokenInfo.ulMinPinLen)
	t.TotalPublicMemory = uint(pTokenInfo.ulTotalPublicMemory)
	t.FreePublicMemory = uint(pTokenInfo.ulFreePublicMemory)
	t.TotalPrivateMemory = uint(pTokenInfo.ulTotalPrivateMemory)
	t.FreePrivateMemory = uint(pTokenInfo.ulFreePrivateMemory)
	t.HardwareVersion = versionFromC(pTokenInfo.hardwareVersion)
	t.FirmwareVersion = versionFromC(pTokenInfo.firmwareVersion)
	t.UTCTime = stringFromC(unsafe.Pointer(&(pTokenInfo.utcTime)), 16)
	return t
}

// Pkcs11Error represents an error from the PKCS#11 library.
type Pkcs11Error struct {
	err string // error text
	rv  int    // return value from pkcs11 api
}

func newPkcs11Error(s string, rv C.CK_RV) *Pkcs11Error {
	return &Pkcs11Error{err: s, rv: int(rv)}
}

func (e *Pkcs11Error) Error() string {
	s := "pkcs11: " + e.err + "(rv: " + strconv.Itoa(e.rv) + ")"
	return s
}

type Pkcs11 struct {
	ctx *C.struct_ctx
}

// New returns a new instance of a pkcs11. The dynamic PKCS#11 library is
// loaded. New returns nil on error.
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

// Wraps PKCS#11's C_Initialize.
func (p *Pkcs11) C_Initialize() error {
	e := C.Go_C_Initialize(p.ctx)
	if e != C.CKR_OK {
		return newPkcs11Error("", e)
	}
	return nil
}

// Wraps PKCS#11's C_Finalize.
func (p *Pkcs11) C_Finalize() error {
	e := C.Go_C_Finalize(p.ctx)
	if e != C.CKR_OK {
		return newPkcs11Error("", e)
	}
	return nil
}

// Destroy unload the module and frees any remaining memory.
func (p *Pkcs11) Destroy() {
	if p == nil {
		return
	}
	C.Destroy(p.ctx)
}

func (p *Pkcs11) C_GetInfo() (*Info, error) {
	var pInfo C.CK_INFO_PTR
	defer C.free(unsafe.Pointer(pInfo))
	e := C.Go_C_GetInfo(p.ctx, &pInfo)
	if e != C.CKR_OK {
		return nil, newPkcs11Error("", e)
	}
	return infoFromC(pInfo), nil
}

func (p *Pkcs11) C_GetSlotList(tokenPresent bool) ([]uint, error) {
	var (
		slotlist C.CK_SLOT_ID_PTR
		pcount   C.CK_ULONG
		e        C.CK_RV
	)
	defer C.free(unsafe.Pointer(slotlist))
	if tokenPresent {
		e = C.Go_C_GetSlotList(p.ctx, C.CK_TRUE, &slotlist, &pcount)
	} else {
		e = C.Go_C_GetSlotList(p.ctx, C.CK_FALSE, &slotlist, &pcount)
	}
	if e != C.CKR_OK {
		return nil, newPkcs11Error("", e)
	}
	u := make([]uint, 0)
	for i := uint(0); i < uint(pcount); i++ {
		u = append(u, uint(*(C.SlotIDIndex(&slotlist, C.int(i)))))
	}
	return u, nil
}

func (p *Pkcs11) C_GetSlotInfo(SlotID uint) (*SlotInfo, error) {
	var (
		slot C.CK_SLOT_INFO_PTR
	)
	defer C.free(unsafe.Pointer(slot))
	e := C.Go_C_GetSlotInfo(p.ctx, C.CK_SLOT_ID(SlotID), &slot)
	if e != C.CKR_OK {
		return nil, newPkcs11Error("", e)
	}
	return slotInfoFromC(slot), nil
}

func (p *Pkcs11) C_GetTokenInfo(slotID uint) (*TokenInfo, error) {
	var (
		token C.CK_TOKEN_INFO_PTR
	)
	defer C.free(unsafe.Pointer(token))
	e := C.Go_C_GetTokenInfo(p.ctx, C.CK_SLOT_ID(slotID), &token)
	if e != C.CKR_OK {
		return nil, newPkcs11Error("", e)
	}
	return tokenInfoFromC(token), nil
}

func (p *Pkcs11) C_InitToken(slotID uint, soPin, label string) error {
	if len(label) > 32 {
		return newPkcs11Error("label must be 32 bytes or less", 1)
	}
	for len(label) < 32 { // stupid loop to make it 32 bytes
		label += " "
	}
	csoPin := C.CString(soPin)
	clabel := C.CString(label)
	defer C.free(unsafe.Pointer(csoPin))
	defer C.free(unsafe.Pointer(clabel))
	e := C.Go_C_InitToken(p.ctx, C.CK_SLOT_ID(slotID), csoPin, C.CK_ULONG(len(soPin)), clabel)
	if e != C.CKR_OK {
		return newPkcs11Error("", e)
	}
	return nil
}

// Callback function not supported...?
// pApplication/Notify
func (p *Pkcs11) C_OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	var sh SessionHandle
	e := C.Go_C_OpenSession(p.ctx, C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags), C.CK_SESSION_HANDLE_PTR(unsafe.Pointer(&sh)))
	if e != C.CKR_OK {
		return 0, newPkcs11Error("", e)
	}
	return sh, nil
}

func (p *Pkcs11) C_CloseSession(sh SessionHandle) error {
	e := C.Go_C_CloseSession(p.ctx, C.CK_SESSION_HANDLE(sh))
	if e != C.CKR_OK {
		return newPkcs11Error("", e)
	}
	return nil
}

func (p *Pkcs11) C_SetPIN(sh SessionHandle, oldPin, newPin string) error {
	coldPin := C.CString(oldPin)
	cnewPin := C.CString(newPin)
	defer C.free(unsafe.Pointer(coldPin))
	defer C.free(unsafe.Pointer(cnewPin))
	e := C.Go_C_SetPIN(p.ctx, C.CK_SESSION_HANDLE(sh), coldPin, C.CK_ULONG(len(oldPin)), cnewPin, C.CK_ULONG(len(newPin)))
	if e != C.CKR_OK {
		return newPkcs11Error("", e)
	}
	return nil
}
