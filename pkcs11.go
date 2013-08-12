// Package pkcs11 is a wrapper around the PKCS#11 cryptoigraphic library.
package pkcs11

/*
#cgo LDFLAGS: -lltdl
#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <stdlib.h>
#include <stdio.h>
#include <ltdl.h>
#include <unistd.h>
#include "pkcs11.h"

struct ctx {
	lt_dlhandle handle;
	CK_FUNCTION_LIST_PTR sym;
};

// New initializes a ctx and fills the symbol table.
struct ctx *New(const char *module)
{
	if (lt_dlinit() != 0) {
		return NULL;
	}
	CK_C_GetFunctionList list;
	struct ctx *c = calloc(1, sizeof(struct ctx));
	c->handle = lt_dlopen(module);
	if (c->handle == NULL) {
		free(c);
		return NULL;
	}
	list = (CK_C_GetFunctionList) lt_dlsym(c->handle, "C_GetFunctionList");
	if (list == NULL) {
		free(c);
		return NULL;
	}
	list(&c->sym);
	return c;
}

// Destroy cleans up a ctx.
void Destroy(struct ctx *c)
{
	if (!c) {
		return;
	}
	if (c->handle == NULL) {
		return;
	}
	if (lt_dlclose(c->handle) < 0) {
		return;
	}
	lt_dlexit();
	free(c);
}

CK_RV Initialize(struct ctx * c, CK_VOID_PTR initArgs)
{
	return c->sym->C_Initialize(initArgs);
}

CK_RV Finalize(struct ctx * c)
{
	return c->sym->C_Finalize(NULL);
}

CK_RV GetSlotList(struct ctx * c, CK_BBOOL tokenPresent,
		  CK_ULONG_PTR * slotList, CK_ULONG_PTR ulCount)
{
	CK_RV e = c->sym->C_GetSlotList(tokenPresent, NULL, ulCount);
	if (e != CKR_OK) {
		return e;
	}
	*slotList = calloc(*ulCount, sizeof(CK_SLOT_ID));
	e = c->sym->C_GetSlotList(tokenPresent, *slotList, ulCount);
	return e;
}

CK_RV GetMechanismList(struct ctx *c, CK_ULONG slotID,
		       CK_ULONG_PTR * mech, CK_ULONG_PTR mechlen)
{
	CK_RV e =
	    c->sym->C_GetMechanismList((CK_SLOT_ID) slotID, NULL, mechlen);
	if (e != CKR_OK) {
		return e;
	}
	*mech = calloc(*mechlen, sizeof(CK_MECHANISM_TYPE));
	e = c->sym->C_GetMechanismList((CK_SLOT_ID) slotID,
				       (CK_MECHANISM_TYPE_PTR) * mech, mechlen);
	return e;
}

CK_RV OpenSession(struct ctx * c, CK_ULONG slotID, CK_ULONG flags,
		  CK_SESSION_HANDLE_PTR session)
{
	CK_RV e =
	    c->sym->C_OpenSession((CK_SLOT_ID) slotID, (CK_FLAGS) flags, NULL,
				  NULL, session);
	return e;
}

CK_RV CloseSession(struct ctx * c, CK_SESSION_HANDLE session)
{
	CK_RV e = c->sym->C_CloseSession(session);
	return e;
}

CK_RV CloseAllSessions(struct ctx * c, CK_ULONG slotID)
{
	CK_RV e = c->sym->C_CloseAllSessions(slotID);
	return e;
}

CK_RV Login(struct ctx * c, CK_SESSION_HANDLE session, CK_USER_TYPE userType,
	    char *pin, CK_ULONG pinLen)
{
	CK_RV e =
	    c->sym->C_Login(session, userType, (CK_UTF8CHAR_PTR) pin, pinLen);
	return e;
}

CK_RV Logout(struct ctx * c, CK_SESSION_HANDLE session)
{
	CK_RV e = c->sym->C_Logout(session);
	return e;
}

CK_RV CreateObject(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_ATTRIBUTE_PTR temp, CK_ULONG tempCount,
		   CK_OBJECT_HANDLE_PTR obj)
{
	CK_RV e = c->sym->C_CreateObject(session, temp, tempCount, obj);
	return e;
}

// TODO(miek): CopyObject

CK_RV DestroyObject(struct ctx * c, CK_SESSION_HANDLE session,
		    CK_OBJECT_HANDLE object)
{
	CK_RV e = c->sym->C_DestroyObject(session, object);
	return e;
}

CK_RV GetObjectSize(struct ctx * c, CK_SESSION_HANDLE session,
		    CK_OBJECT_HANDLE object, CK_ULONG_PTR size)
{
	CK_RV e = c->sym->C_GetObjectSize(session, object, size);
	return e;
}

CK_RV GetAttributeValue(struct ctx *c, CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR temp,
			CK_ULONG templen)
{
	// Call for the first time, check the returned ulValue in the attributes, then
	// allocate enough space and try again.
	CK_RV e = c->sym->C_GetAttributeValue(session, object, temp, templen);
	if (e != CKR_OK) {
		return e;
	}
	CK_ULONG i;
	for (i = 0; i < templen; i++ ) {
		if ((CK_LONG)temp[i].ulValueLen == -1) {
			// either access denied or no such object
			continue;
		}
		temp[i].pValue = calloc(temp[i].ulValueLen, sizeof(CK_BYTE));
	}
	e = c->sym->C_GetAttributeValue(session, object, temp, templen);
	return e;
}

// TODO(miek): SetAttributeValue

CK_RV FindObjectsInit(struct ctx * c, CK_SESSION_HANDLE session,
		      CK_ATTRIBUTE_PTR temp, CK_ULONG tempCount)
{
	CK_RV e = c->sym->C_FindObjectsInit(session, temp, tempCount);
	return e;
}

CK_RV FindObjects(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_OBJECT_HANDLE_PTR * obj, CK_ULONG max,
		  CK_ULONG_PTR objCount)
{
	*obj = calloc(max, sizeof(CK_OBJECT_HANDLE));
	CK_RV e = c->sym->C_FindObjects(session, *obj, max, objCount);
	return e;
}

CK_RV FindObjectsFinal(struct ctx * c, CK_SESSION_HANDLE session)
{
	CK_RV e = c->sym->C_FindObjectsFinal(session);
	return e;
}

CK_RV EncryptInit(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	CK_RV e = c->sym->C_EncryptInit(session, mechanism, key);
	return e;
}

CK_RV Encrypt(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR message,
	      CK_ULONG mlen, CK_BYTE_PTR * enc, CK_ULONG_PTR enclen)
{
	CK_RV rv = c->sym->C_Encrypt(session, message, mlen, NULL, enclen);
	if (rv != CKR_OK) {
		return rv;
	}
	*enc = calloc(*enclen, sizeof(CK_BYTE));
	if (*enc == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_Encrypt(session, message, mlen, *enc, enclen);
	return rv;
}

CK_RV DecryptInit(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	CK_RV e = c->sym->C_DecryptInit(session, mechanism, key);
	return e;
}

CK_RV Decrypt(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR cypher,
	      CK_ULONG clen, CK_BYTE_PTR * plain, CK_ULONG_PTR plainlen)
{
	CK_RV e = c->sym->C_Decrypt(session, cypher, clen, NULL, plainlen);
	if (e != CKR_OK) {
		return e;
	}
	*plain = calloc(*plainlen, sizeof(CK_BYTE));
	if (*plain == NULL) {
		return CKR_HOST_MEMORY;
	}
	e = c->sym->C_Decrypt(session, cypher, clen, *plain, plainlen);
	return e;
}

CK_RV DigestInit(struct ctx * c, CK_SESSION_HANDLE session,
		 CK_MECHANISM_PTR mechanism)
{
	CK_RV e = c->sym->C_DigestInit(session, mechanism);
	return e;
}

CK_RV Digest(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR message,
	     CK_ULONG mlen, CK_BYTE_PTR * hash, CK_ULONG_PTR hashlen)
{
	CK_RV rv = c->sym->C_Digest(session, message, mlen, NULL, hashlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*hash = calloc(*hashlen, sizeof(CK_BYTE));
	if (*hash == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_Digest(session, message, mlen, *hash, hashlen);
	return rv;
}

CK_RV DigestUpdate(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_BYTE_PTR message, CK_ULONG mlen)
{
	CK_RV rv = c->sym->C_DigestUpdate(session, message, mlen);
	return rv;
}

CK_RV DigestKey(struct ctx * c, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_RV rv = c->sym->C_DigestKey(session, key);
	return rv;
}

CK_RV DigestFinal(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR * hash,
		  CK_ULONG_PTR hashlen)
{
	CK_RV rv = c->sym->C_DigestFinal(session, NULL, hashlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*hash = calloc(*hashlen, sizeof(CK_BYTE));
	if (*hash == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DigestFinal(session, *hash, hashlen);
	return rv;
}

CK_RV SignInit(struct ctx * c, CK_SESSION_HANDLE session,
	       CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	CK_RV e = c->sym->C_SignInit(session, mechanism, key);
	return e;
}

CK_RV Sign(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR message,
	   CK_ULONG mlen, CK_BYTE_PTR * sig, CK_ULONG_PTR siglen)
{
	CK_RV rv = c->sym->C_Sign(session, message, mlen, NULL, siglen);
	if (rv != CKR_OK) {
		return rv;
	}
	*sig = calloc(*siglen, sizeof(CK_BYTE));
	if (*sig == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_Sign(session, message, mlen, *sig, siglen);
	return rv;
}

CK_RV SignUpdate(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_BYTE_PTR message, CK_ULONG mlen)
{
	CK_RV rv = c->sym->C_SignUpdate(session, message, mlen);
	return rv;
}

CK_RV SignFinal(struct ctx *c, CK_SESSION_HANDLE session, CK_BYTE_PTR * sig,
		CK_ULONG_PTR siglen)
{
	CK_RV rv = c->sym->C_SignFinal(session, NULL, siglen);
	if (rv != CKR_OK) {
		return rv;
	}
	*sig = calloc(*siglen, sizeof(CK_BYTE));
	if (*sig == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_SignFinal(session, *sig, siglen);
	return rv;
}


CK_RV GenerateKey(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR temp,
		  CK_ULONG tempCount, CK_OBJECT_HANDLE_PTR key)
{
	CK_RV e =
	    c->sym->C_GenerateKey(session, mechanism, temp, tempCount, key);
	return e;
}

CK_RV GenerateKeyPair(struct ctx * c, CK_SESSION_HANDLE session,
		      CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR pub,
		      CK_ULONG pubCount, CK_ATTRIBUTE_PTR priv,
		      CK_ULONG privCount, CK_OBJECT_HANDLE_PTR pubkey,
		      CK_OBJECT_HANDLE_PTR privkey)
{
	CK_RV e =
	    c->sym->C_GenerateKeyPair(session, mechanism, pub, pubCount, priv,
				      privCount,
				      pubkey, privkey);
	return e;
}

CK_RV WrapKey(struct ctx * c, CK_SESSION_HANDLE session,
	      CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrappingkey,
	      CK_OBJECT_HANDLE key, CK_BYTE_PTR * wrapped,
	      CK_ULONG_PTR wrappedlen)
{
	CK_RV rv =
	    c->sym->C_WrapKey(session, mechanism, wrappingkey, key, NULL,
			      wrappedlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*wrapped = calloc(*wrappedlen, sizeof(CK_BYTE));
	if (*wrapped == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_WrapKey(session, mechanism, wrappingkey, key, *wrapped,
			       wrappedlen);
	return rv;
}

// TODO(miek): UnwrapKey and DeriveKey

CK_RV SeedRandom(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR seed,
		 CK_ULONG seedlen)
{
	CK_RV rv = c->sym->C_SeedRandom(session, seed, seedlen);
	return rv;
}

CK_RV GenerateRandom(struct ctx * c, CK_SESSION_HANDLE session,
		     CK_BYTE_PTR * rand, CK_ULONG length)
{
	*rand = calloc(length, sizeof(CK_BYTE));
	if (*rand == NULL) {
		return CKR_HOST_MEMORY;
	}
	CK_RV e = c->sym->C_GenerateRandom(session, *rand, length);
	return e;
}

CK_RV WaitForSlotEvent(struct ctx * c, CK_FLAGS flags, CK_ULONG_PTR slot)
{
	CK_RV e = c->sym->C_WaitForSlotEvent(flags, (CK_SLOT_ID_PTR)slot, NULL);
	return e;
}

*/
import "C"

import "unsafe"

// Ctx contains the current pkcs11 context.
type Ctx struct {
	ctx         *C.struct_ctx
}

// New creates a new context and initializes the module/library for use.
func New(module string) *Ctx {
	c := new(Ctx)
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	c.ctx = C.New(mod)
	if c.ctx == nil {
		return nil
	}
	return c
}

// Destroy unloads the module/library and frees any remaining memory.
func (c *Ctx) Destroy() {
	if c == nil {
		return
	}
	C.Destroy(c.ctx)
	c.ctx = nil
}

/* Initialize initializes the Cryptoki library. */
func (c *Ctx) Initialize() error {
	args := &C.CK_C_INITIALIZE_ARGS{nil, nil, nil, nil, C.CKF_OS_LOCKING_OK, nil}
	e := C.Initialize(c.ctx, C.CK_VOID_PTR(args))
	return toError(e)
}

/* Finalize indicates that an application is done with the Cryptoki library. */
func (c *Ctx) Finalize() error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.Finalize(c.ctx)
	return toError(e)
}

// GetInfo

/* GetSlotList obtains a list of slots in the system. */
func (c *Ctx) GetSlotList(tokenPresent bool) ([]uint, error) {
	var (
		slotList C.CK_ULONG_PTR
		ulCount  C.CK_ULONG
	)
	e := C.GetSlotList(c.ctx, cBBool(tokenPresent), &slotList, &ulCount)
	if toError(e) != nil {
		return nil, toError(e)
	}
	l := toList(slotList, ulCount)
	return l, nil
}

// GetSlotInfo

// GetTokenInfo

/* GetMechanismList obtains a list of mechanism types supported by a token. */
func (c *Ctx) GetMechanismList(slotID uint) ([]*Mechanism, error) {
	var (
		mech    C.CK_ULONG_PTR // in pkcs#11 we're all CK_ULONGs \o/
		mechlen C.CK_ULONG
	)
	e := C.GetMechanismList(c.ctx, C.CK_ULONG(slotID), &mech, &mechlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	// Although the function returns only type, cast them back into real
	// attributes as this is used in other functions.
	m := make([]*Mechanism, int(mechlen))
	for i, typ := range toList(mech, mechlen) {
		m[i] = NewMechanism(typ, nil)
	}
	return m, nil
}

// GetMechanismInfo

// InitToken

// InitPIN

// SetPIN

/* OpenSession opens a session between an application and a token. */
func (c *Ctx) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	var s C.CK_SESSION_HANDLE
	e := C.OpenSession(c.ctx, C.CK_ULONG(slotID), C.CK_ULONG(flags), C.CK_SESSION_HANDLE_PTR(&s))
	return SessionHandle(s), toError(e)
}

/* CloseSession closes a session between an application and a token. */
func (c *Ctx) CloseSession(sh SessionHandle) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.CloseSession(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

/* CloseAllSessions closes all sessions with a token. */
func (c *Ctx) CloseAllSessions(slotID uint) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.CloseAllSessions(c.ctx, C.CK_ULONG(slotID))
	return toError(e)
}

// GetSessionInfo

// GetOperationState

// SetOperationState

/* Login logs a user into a token. */
func (c *Ctx) Login(sh SessionHandle, userType uint, pin string) error {
	p := C.CString(pin)
	defer C.free(unsafe.Pointer(p))
	e := C.Login(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_USER_TYPE(userType), p, C.CK_ULONG(len(pin)))
	return toError(e)
}

/* Logout logs a user out from a token. */
func (c *Ctx) Logout(sh SessionHandle) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.Logout(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

/* CreateObject creates a new object. */
func (c *Ctx) CreateObject(sh SessionHandle, temp []*Attribute) (ObjectHandle, error) {
	var obj C.CK_OBJECT_HANDLE
	t, tcount := cAttributeList(temp)
	e := C.CreateObject(c.ctx, C.CK_SESSION_HANDLE(sh), t, tcount, C.CK_OBJECT_HANDLE_PTR(&obj))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(obj), nil
	}
	return 0, e1
}

// TODO(miek): CopyObject here

/* DestroyObject destroys an object. */
func (c *Ctx) DestroyObject(sh SessionHandle, oh ObjectHandle) error {
	e := C.DestroyObject(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(oh))
	return toError(e)
}

/* GetObjectSize gets the size of an object in bytes. */
func (c *Ctx) GetObjectSize(sh SessionHandle, oh ObjectHandle) (uint, error) {
	var size C.CK_ULONG
	e := C.GetObjectSize(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(oh), &size)
	return uint(size), toError(e)
}

/* GetAttributeValue obtains the value of one or more object attributes. */
func (c *Ctx) GetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) ([]*Attribute, error) {
	// copy the attribute list and make all the values nil, so that
	// the C function can (allocate) fill them in
	pa := make([]C.CK_ATTRIBUTE, len(a))
	for i := 0; i < len(a); i++ {
		pa[i]._type = C.CK_ATTRIBUTE_TYPE(a[i].Type)
	}
	e := C.GetAttributeValue(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(o), C.CK_ATTRIBUTE_PTR(&pa[0]), C.CK_ULONG(len(a)))
	if toError(e) != nil {
		return nil, toError(e)
	}
	a1 := make([]*Attribute, len(a))
	for i, c := range pa {
		x := new(Attribute)
		x.Type = uint(c._type)
		if int(c.ulValueLen) != -1 {
			x.Value = C.GoBytes(unsafe.Pointer(c.pValue), C.int(c.ulValueLen))
			C.free(unsafe.Pointer(c.pValue))
		}
		a1[i] = x
	}
	return a1, nil
}

func (c *Ctx) SetAttributeValue() {}

func (c *Ctx) FindObjectsInit(sh SessionHandle, temp []*Attribute) error {
	t, tcount := cAttributeList(temp)
	e := C.FindObjectsInit(c.ctx, C.CK_SESSION_HANDLE(sh), t, tcount)
	return toError(e)
}

// FindObjects continues a search for token and session
// objects that match a template, obtaining additional object
// handles. The returned boolean indicates if the list would
// have been larger than max.
func (c *Ctx) FindObjects(sh SessionHandle, max int) ([]ObjectHandle, bool, error) {
	var (
		objectList C.CK_OBJECT_HANDLE_PTR
		ulCount    C.CK_ULONG
	)
	e := C.FindObjects(c.ctx, C.CK_SESSION_HANDLE(sh), &objectList, C.CK_ULONG(max), &ulCount)
	if toError(e) != nil {
		return nil, false, toError(e)
	}
	l := toList(C.CK_ULONG_PTR(unsafe.Pointer(objectList)), ulCount)
	// Make again a new list of the correct type.
	// This is copying data, but this is not an often used function.
	o := make([]ObjectHandle, len(l))
	for i, v := range l {
		o[i] = ObjectHandle(v)
	}
	return o, ulCount > C.CK_ULONG(max), nil
}

/* FindObjectsFinal finishes a search for token and session objects. */
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	e := C.FindObjectsFinal(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

/* EncryptInit initializes an encryption operation. */
func (c *Ctx) EncryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	mech, _ := cMechanismList(m)
	e := C.EncryptInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(o))
	return toError(e)
}

/* Encrypt encrypts single-part data. */
func (c *Ctx) Encrypt(sh SessionHandle, message []byte) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	e := C.Encrypt(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&message[0])), C.CK_ULONG(len(message)), &enc, &enclen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	s := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return s, nil
}

/* DecryptInit initializes a decryption operation. */
func (c *Ctx) DecryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	mech, _ := cMechanismList(m)
	e := C.DecryptInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(o))
	return toError(e)
}

/* Decrypt decrypts encrypted data in a single part. */
func (c *Ctx) Decrypt(sh SessionHandle, cypher []byte) ([]byte, error) {
	var (
		plain    C.CK_BYTE_PTR
		plainlen C.CK_ULONG
	)
	e := C.Decrypt(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&cypher[0])), C.CK_ULONG(len(cypher)), &plain, &plainlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	s := C.GoBytes(unsafe.Pointer(plain), C.int(plainlen))
	C.free(unsafe.Pointer(plain))
	return s, nil
}

/* DigestInit initializes a message-digesting operation. */
func (c *Ctx) DigestInit(sh SessionHandle, m []*Mechanism) error {
	mech, _ := cMechanismList(m)
	e := C.DigestInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech)
	return toError(e)
}

/* Digest digests message in a single part. */
func (c *Ctx) Digest(sh SessionHandle, message []byte) ([]byte, error) {
	var (
		hash    C.CK_BYTE_PTR
		hashlen C.CK_ULONG
	)
	e := C.Digest(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&message[0])), C.CK_ULONG(len(message)), &hash, &hashlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(hash), C.int(hashlen))
	C.free(unsafe.Pointer(hash))
	return h, nil
}

/* DigestUpdate continues a multiple-part message-digesting operation. */
func (c *Ctx) DigestUpdate(sh SessionHandle, message []byte) error {
	e := C.DigestUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&message[0])), C.CK_ULONG(len(message)))
	if toError(e) != nil {
		return toError(e)
	}
	return nil
}

// DigestKey continues a multi-part message-digesting
// operation, by digesting the value of a secret key as part of
// the data already digested.
func (c *Ctx) DigestKey(sh SessionHandle, key ObjectHandle) error {
	e := C.DigestKey(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(key))
	if toError(e) != nil {
		return toError(e)
	}
	return nil
}

/* DigestFinal finishes a multiple-part message-digesting operation. */
func (c *Ctx) DigestFinal(sh SessionHandle) ([]byte, error) {
	var (
		hash    C.CK_BYTE_PTR
		hashlen C.CK_ULONG
	)
	e := C.DigestFinal(c.ctx, C.CK_SESSION_HANDLE(sh), &hash, &hashlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(hash), C.int(hashlen))
	C.free(unsafe.Pointer(hash))
	return h, nil
}

// SignInit initializes a signature (private key encryption)
// operation, where the signature is (will be) an appendix to
// the data, and plaintext cannot be recovered from the
//signature.
func (c *Ctx) SignInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	mech, _ := cMechanismList(m) // Only the first is used, but still use a list.
	e := C.SignInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(o))
	return toError(e)
}

// Sign signs (encrypts with private key) data in a single part, where the signature
// is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
func (c *Ctx) Sign(sh SessionHandle, message []byte) ([]byte, error) {
	var (
		sig    C.CK_BYTE_PTR
		siglen C.CK_ULONG
	)
	e := C.Sign(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&message[0])), C.CK_ULONG(len(message)), &sig, &siglen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	s := C.GoBytes(unsafe.Pointer(sig), C.int(siglen))
	C.free(unsafe.Pointer(sig))
	return s, nil
}

// SignUpdate continues a multiple-part signature operation,
// where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (c *Ctx) SignUpdate(sh SessionHandle, message []byte) error {
	e := C.SignUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&message[0])), C.CK_ULONG(len(message)))
	return toError(e)
}

/* SignFinal finishes a multiple-part signature operation returning the signature. */
func (c *Ctx) SignFinal(sh SessionHandle) ([]byte, error) {
	var (
		sig    C.CK_BYTE_PTR
		siglen C.CK_ULONG
	)
	e := C.SignFinal(c.ctx, C.CK_SESSION_HANDLE(sh), &sig, &siglen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(sig), C.int(siglen))
	C.free(unsafe.Pointer(sig))
	return h, nil
}

/* GenerateKey generates a secret key, creating a new key object. */
func (c *Ctx) GenerateKey(sh SessionHandle, m []*Mechanism, temp []*Attribute) (ObjectHandle, error) {
	var key C.CK_OBJECT_HANDLE
	t, tcount := cAttributeList(temp)
	mech, _ := cMechanismList(m)
	e := C.GenerateKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, t, tcount, C.CK_OBJECT_HANDLE_PTR(&key))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(key), nil
	}
	return 0, e1
}

/* GenerateKeyPair generates a public-key/private-key pair creating new key objects. */
func (c *Ctx) GenerateKeyPair(sh SessionHandle, m []*Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	var (
		pubkey  C.CK_OBJECT_HANDLE
		privkey C.CK_OBJECT_HANDLE
	)
	pub, pubcount := cAttributeList(public)
	priv, privcount := cAttributeList(private)
	mech, _ := cMechanismList(m)
	e := C.GenerateKeyPair(c.ctx, C.CK_SESSION_HANDLE(sh), mech, pub, pubcount, priv, privcount, C.CK_OBJECT_HANDLE_PTR(&pubkey), C.CK_OBJECT_HANDLE_PTR(&privkey))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(pubkey), ObjectHandle(privkey), nil
	}
	return 0, 0, e1
}

/* WrapKey wraps (i.e., encrypts) a key. */
func (c *Ctx) WrapKey(sh SessionHandle, m []*Mechanism, wrappingkey, key ObjectHandle) ([]byte, error) {
	var (
		wrappedkey    C.CK_BYTE_PTR
		wrappedkeylen C.CK_ULONG
	)
	mech, _ := cMechanismList(m)
	e := C.WrapKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(wrappingkey), C.CK_OBJECT_HANDLE(key), &wrappedkey, &wrappedkeylen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(wrappedkey), C.int(wrappedkeylen))
	C.free(unsafe.Pointer(wrappedkey))
	return h, nil
}

// TODO(miek): UnwrapKey
// TODO(miek): DeriveKey

// SeedRandom mixes additional seed material into the token's
// random number generator.
func (c *Ctx) SeedRandom(sh SessionHandle, seed []byte) error {
	e := C.SeedRandom(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&seed[0])), C.CK_ULONG(len(seed)))
	return toError(e)
}

/* GenerateRandom generates random data. */
func (c *Ctx) GenerateRandom(sh SessionHandle, length int) ([]byte, error) {
	var rand C.CK_BYTE_PTR
	e := C.GenerateRandom(c.ctx, C.CK_SESSION_HANDLE(sh), &rand, C.CK_ULONG(length))
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(rand), C.int(length))
	C.free(unsafe.Pointer(rand))
	return h, nil
}

// WaitForSlotEvent returns a channel which returns a slot event
// (token insertion, // removal, etc.) when it occurs.
func (c *Ctx) WaitForSlotEvent(flags uint) chan SlotEvent {
	sl := make(chan SlotEvent, 1) // hold one element
	go c.waitForSlotEventHelper(flags, sl)
	return sl
}

func (c *Ctx) waitForSlotEventHelper(f uint, sl chan SlotEvent) {
	var slotID C.CK_ULONG
	C.WaitForSlotEvent(c.ctx, C.CK_FLAGS(f), &slotID)
	sl <- SlotEvent{uint(slotID)}
	close(sl) // TODO(miek) sending and then closing ...?
}
