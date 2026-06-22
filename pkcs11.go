// Copyright 2026 Miek Gieben and the Golang pkcs11 Contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX-License-Identifier: BSD-3-Clause

//go:generate go run const_generate.go

// Package pkcs11 is a wrapper around the PKCS#11 cryptographic library.
// Latest version of the specification:
// https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
package pkcs11

// It is *assumed*, that:
//
// * Go's uint size == PKCS11's CK_ULONG size
// * CK_ULONG never overflows an Go int

/*
#cgo windows CFLAGS: -DPACKED_STRUCTURES
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl
#cgo openbsd LDFLAGS:
#cgo freebsd LDFLAGS: -ldl

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pkcs11go.h"

#ifdef _WIN32
#include <windows.h>

struct ctx {
	HMODULE handle;
	CK_FUNCTION_LIST_PTR sym;       // v2.40 function table for backward compatibility
	CK_FUNCTION_LIST_3_2_PTR fl32;  // v3.2 function table, NULL if not supported
};

// New initializes a ctx and fills the symbol table.
struct ctx *New(const char *module)
{
	CK_C_GetFunctionList list;
	struct ctx *c = calloc(1, sizeof(struct ctx));
	c->handle = LoadLibrary(module);
	if (c->handle == NULL) {
		free(c);
		return NULL;
	}
	list = (CK_C_GetFunctionList) GetProcAddress(c->handle, "C_GetFunctionList");
	if (list == NULL) {
		free(c);
		return NULL;
	}
	list(&c->sym);

	// C_GetInterface is a v3.0 function — it does not exist in CK_FUNCTION_LIST
	// (v2.40).  Look it up directly from the library handle instead.
	CK_RV (*getInterface)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) =
		(CK_RV (*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS))
		GetProcAddress(c->handle, "C_GetInterface");
	if (getInterface != NULL) {
		CK_VERSION v32 = {3, 2};
		CK_INTERFACE_PTR iface = NULL;
		if (getInterface((CK_UTF8CHAR_PTR)"PKCS 11", &v32, &iface, 0) == CKR_OK
		    && iface != NULL) {
			c->fl32 = (CK_FUNCTION_LIST_3_2_PTR)iface->pFunctionList;
		}
	}

	return c;
}

// Destroy cleans up a ctx.
void Destroy(struct ctx *c)
{
	if (!c) {
		return;
	}
	free(c);
}
#else
#include <dlfcn.h>

struct ctx {
	void *handle;
	CK_FUNCTION_LIST_PTR sym;      // v2.40 function table for backward compatibility
	CK_FUNCTION_LIST_3_2_PTR fl32; // v3.2 function table, NULL if not supported
};

// New initializes a ctx and fills the symbol table.
struct ctx *New(const char *module)
{
	CK_C_GetFunctionList list;
	struct ctx *c = calloc(1, sizeof(struct ctx));
	c->handle = dlopen(module, RTLD_LAZY);
	if (c->handle == NULL) {
		free(c);
		return NULL;
	}
	list = (CK_C_GetFunctionList) dlsym(c->handle, "C_GetFunctionList");
	if (list == NULL) {
		free(c);
		return NULL;
	}
	list(&c->sym);

	// C_GetInterface is a v3.0 function — it does not exist in CK_FUNCTION_LIST
	// (v2.40).  Look it up directly from the library handle instead.
	CK_RV (*getInterface)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) =
		(CK_RV (*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS))
		dlsym(c->handle, "C_GetInterface");
	if (getInterface != NULL) {
		CK_VERSION v32 = {3, 2};
		CK_INTERFACE_PTR iface = NULL;
		if (getInterface((CK_UTF8CHAR_PTR)"PKCS 11", &v32, &iface, 0) == CKR_OK
		    && iface != NULL) {
			c->fl32 = (CK_FUNCTION_LIST_3_2_PTR)iface->pFunctionList;
		}
	}

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
	if (dlclose(c->handle) < 0) {
		return;
	}
	free(c);
}
#endif

CK_RV Initialize(struct ctx * c, CK_FLAGS flags, CK_VOID_PTR reserved)
{
	CK_C_INITIALIZE_ARGS args;
	memset(&args, 0, sizeof(args));
	args.flags = flags;
	args.pReserved = reserved;
	return c->sym->C_Initialize(&args);
}

CK_RV Finalize(struct ctx * c)
{
	return c->sym->C_Finalize(NULL);
}

CK_RV GetInfo(struct ctx * c, ckInfoPtr info)
{
	CK_INFO p;
	CK_RV e = c->sym->C_GetInfo(&p);
	if (e != CKR_OK) {
		return e;
	}
	info->cryptokiVersion = p.cryptokiVersion;
	memcpy(info->manufacturerID, p.manufacturerID, sizeof(p.manufacturerID));
	info->flags = p.flags;
	memcpy(info->libraryDescription, p.libraryDescription, sizeof(p.libraryDescription));
	info->libraryVersion = p.libraryVersion;
	return e;
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

CK_RV GetSlotInfo(struct ctx * c, CK_ULONG slotID, CK_SLOT_INFO_PTR info)
{
	CK_RV e = c->sym->C_GetSlotInfo((CK_SLOT_ID) slotID, info);
	return e;
}

CK_RV GetTokenInfo(struct ctx * c, CK_ULONG slotID, CK_TOKEN_INFO_PTR info)
{
	CK_RV e = c->sym->C_GetTokenInfo((CK_SLOT_ID) slotID, info);
	return e;
}

CK_RV GetMechanismList(struct ctx * c, CK_ULONG slotID,
		       CK_ULONG_PTR * mech, CK_ULONG_PTR mechlen)
{
	CK_RV e =
	    c->sym->C_GetMechanismList((CK_SLOT_ID) slotID, NULL, mechlen);
	// Gemaltos PKCS11 implementation returns CKR_BUFFER_TOO_SMALL on a NULL ptr instad of CKR_OK as the spec states.
	if (e != CKR_OK && e != CKR_BUFFER_TOO_SMALL) {
		return e;
	}
	*mech = calloc(*mechlen, sizeof(CK_MECHANISM_TYPE));
	e = c->sym->C_GetMechanismList((CK_SLOT_ID) slotID,
				       (CK_MECHANISM_TYPE_PTR) * mech, mechlen);
	return e;
}

CK_RV GetMechanismInfo(struct ctx * c, CK_ULONG slotID, CK_MECHANISM_TYPE mech,
		       CK_MECHANISM_INFO_PTR info)
{
	CK_RV e = c->sym->C_GetMechanismInfo((CK_SLOT_ID) slotID, mech, info);
	return e;
}

CK_RV InitToken(struct ctx * c, CK_ULONG slotID, char *pin, CK_ULONG pinlen,
		char *label)
{
	CK_RV e =
	    c->sym->C_InitToken((CK_SLOT_ID) slotID, (CK_UTF8CHAR_PTR) pin,
				pinlen, (CK_UTF8CHAR_PTR) label);
	return e;
}

CK_RV InitPIN(struct ctx * c, CK_SESSION_HANDLE sh, char *pin, CK_ULONG pinlen)
{
	CK_RV e = c->sym->C_InitPIN(sh, (CK_UTF8CHAR_PTR) pin, pinlen);
	return e;
}

CK_RV SetPIN(struct ctx * c, CK_SESSION_HANDLE sh, char *oldpin,
	     CK_ULONG oldpinlen, char *newpin, CK_ULONG newpinlen)
{
	CK_RV e = c->sym->C_SetPIN(sh, (CK_UTF8CHAR_PTR) oldpin, oldpinlen,
				   (CK_UTF8CHAR_PTR) newpin, newpinlen);
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

CK_RV GetSessionInfo(struct ctx * c, CK_SESSION_HANDLE session,
		     CK_SESSION_INFO_PTR info)
{
	CK_RV e = c->sym->C_GetSessionInfo(session, info);
	return e;
}

CK_RV GetOperationState(struct ctx * c, CK_SESSION_HANDLE session,
			CK_BYTE_PTR * state, CK_ULONG_PTR statelen)
{
	CK_RV rv = c->sym->C_GetOperationState(session, NULL, statelen);
	if (rv != CKR_OK) {
		return rv;
	}
	*state = calloc(*statelen, sizeof(CK_BYTE));
	if (*state == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_GetOperationState(session, *state, statelen);
	return rv;
}

CK_RV SetOperationState(struct ctx * c, CK_SESSION_HANDLE session,
			CK_BYTE_PTR state, CK_ULONG statelen,
			CK_OBJECT_HANDLE encryptkey, CK_OBJECT_HANDLE authkey)
{
	return c->sym->C_SetOperationState(session, state, statelen, encryptkey,
					   authkey);
}

CK_RV Login(struct ctx *c, CK_SESSION_HANDLE session, CK_USER_TYPE userType,
	    char *pin, CK_ULONG pinLen)
{
	if (pinLen == 0) {
		pin = NULL;
	}
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
	return c->sym->C_CreateObject(session, temp, tempCount, obj);
}

CK_RV CopyObject(struct ctx * c, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
		 CK_ATTRIBUTE_PTR temp, CK_ULONG tempCount,
		 CK_OBJECT_HANDLE_PTR obj)
{
	return c->sym->C_CopyObject(session, o, temp, tempCount, obj);
}

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

CK_RV GetAttributeValue(struct ctx * c, CK_SESSION_HANDLE session,
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
	for (i = 0; i < templen; i++) {
		if ((CK_LONG) temp[i].ulValueLen == -1) {
			// either access denied or no such object
			continue;
		}
		temp[i].pValue = calloc(temp[i].ulValueLen, sizeof(CK_BYTE));
	}
	return c->sym->C_GetAttributeValue(session, object, temp, templen);
}

CK_RV SetAttributeValue(struct ctx * c, CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR temp,
			CK_ULONG templen)
{
	return c->sym->C_SetAttributeValue(session, object, temp, templen);
}

CK_RV FindObjectsInit(struct ctx * c, CK_SESSION_HANDLE session,
		      CK_ATTRIBUTE_PTR temp, CK_ULONG tempCount)
{
	return c->sym->C_FindObjectsInit(session, temp, tempCount);
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
	return c->sym->C_EncryptInit(session, mechanism, key);
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

CK_RV EncryptUpdate(struct ctx * c, CK_SESSION_HANDLE session,
		    CK_BYTE_PTR plain, CK_ULONG plainlen, CK_BYTE_PTR * cipher,
		    CK_ULONG_PTR cipherlen)
{
	CK_RV rv =
	    c->sym->C_EncryptUpdate(session, plain, plainlen, NULL, cipherlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*cipher = calloc(*cipherlen, sizeof(CK_BYTE));
	if (*cipher == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_EncryptUpdate(session, plain, plainlen, *cipher,
				     cipherlen);
	return rv;
}

CK_RV EncryptFinal(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_BYTE_PTR * cipher, CK_ULONG_PTR cipherlen)
{
	CK_RV rv = c->sym->C_EncryptFinal(session, NULL, cipherlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*cipher = calloc(*cipherlen, sizeof(CK_BYTE));
	if (*cipher == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_EncryptFinal(session, *cipher, cipherlen);
	return rv;
}

CK_RV DecryptInit(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	return c->sym->C_DecryptInit(session, mechanism, key);
}

CK_RV Decrypt(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR cipher,
	      CK_ULONG clen, CK_BYTE_PTR * plain, CK_ULONG_PTR plainlen)
{
	CK_RV e = c->sym->C_Decrypt(session, cipher, clen, NULL, plainlen);
	if (e != CKR_OK) {
		return e;
	}
	*plain = calloc(*plainlen, sizeof(CK_BYTE));
	if (*plain == NULL) {
		return CKR_HOST_MEMORY;
	}
	e = c->sym->C_Decrypt(session, cipher, clen, *plain, plainlen);
	return e;
}

CK_RV DecryptUpdate(struct ctx * c, CK_SESSION_HANDLE session,
		    CK_BYTE_PTR cipher, CK_ULONG cipherlen, CK_BYTE_PTR * part,
		    CK_ULONG_PTR partlen)
{
	CK_RV rv =
	    c->sym->C_DecryptUpdate(session, cipher, cipherlen, NULL, partlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*part = calloc(*partlen, sizeof(CK_BYTE));
	if (*part == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DecryptUpdate(session, cipher, cipherlen, *part,
				     partlen);
	return rv;
}

CK_RV DecryptFinal(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_BYTE_PTR * plain, CK_ULONG_PTR plainlen)
{
	CK_RV rv = c->sym->C_DecryptFinal(session, NULL, plainlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*plain = calloc(*plainlen, sizeof(CK_BYTE));
	if (*plain == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DecryptFinal(session, *plain, plainlen);
	return rv;
}

CK_RV DigestInit(struct ctx * c, CK_SESSION_HANDLE session,
		 CK_MECHANISM_PTR mechanism)
{
	return c->sym->C_DigestInit(session, mechanism);
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
	return c->sym->C_SignInit(session, mechanism, key);
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

CK_RV SignFinal(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR * sig,
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

CK_RV SignRecoverInit(struct ctx * c, CK_SESSION_HANDLE session,
		      CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	return c->sym->C_SignRecoverInit(session, mechanism, key);
}

CK_RV SignRecover(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR data,
		  CK_ULONG datalen, CK_BYTE_PTR * sig, CK_ULONG_PTR siglen)
{
	CK_RV rv = c->sym->C_SignRecover(session, data, datalen, NULL, siglen);
	if (rv != CKR_OK) {
		return rv;
	}
	*sig = calloc(*siglen, sizeof(CK_BYTE));
	if (*sig == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_SignRecover(session, data, datalen, *sig, siglen);
	return rv;
}

CK_RV VerifyInit(struct ctx * c, CK_SESSION_HANDLE session,
		 CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	return c->sym->C_VerifyInit(session, mechanism, key);
}

CK_RV Verify(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR message,
	     CK_ULONG mesglen, CK_BYTE_PTR sig, CK_ULONG siglen)
{
	CK_RV rv = c->sym->C_Verify(session, message, mesglen, sig, siglen);
	return rv;
}

CK_RV VerifyUpdate(struct ctx * c, CK_SESSION_HANDLE session,
		   CK_BYTE_PTR part, CK_ULONG partlen)
{
	CK_RV rv = c->sym->C_VerifyUpdate(session, part, partlen);
	return rv;
}

CK_RV VerifyFinal(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR sig,
		  CK_ULONG siglen)
{
	CK_RV rv = c->sym->C_VerifyFinal(session, sig, siglen);
	return rv;
}

CK_RV VerifyRecoverInit(struct ctx * c, CK_SESSION_HANDLE session,
			CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	return c->sym->C_VerifyRecoverInit(session, mechanism, key);
}

CK_RV VerifyRecover(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR sig,
		    CK_ULONG siglen, CK_BYTE_PTR * data, CK_ULONG_PTR datalen)
{
	CK_RV rv = c->sym->C_VerifyRecover(session, sig, siglen, NULL, datalen);
	if (rv != CKR_OK) {
		return rv;
	}
	*data = calloc(*datalen, sizeof(CK_BYTE));
	if (*data == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_VerifyRecover(session, sig, siglen, *data, datalen);
	return rv;
}

CK_RV DigestEncryptUpdate(struct ctx * c, CK_SESSION_HANDLE session,
			  CK_BYTE_PTR part, CK_ULONG partlen, CK_BYTE_PTR * enc,
			  CK_ULONG_PTR enclen)
{
	CK_RV rv =
	    c->sym->C_DigestEncryptUpdate(session, part, partlen, NULL, enclen);
	if (rv != CKR_OK) {
		return rv;
	}
	*enc = calloc(*enclen, sizeof(CK_BYTE));
	if (*enc == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DigestEncryptUpdate(session, part, partlen, *enc,
					   enclen);
	return rv;
}

CK_RV DecryptDigestUpdate(struct ctx * c, CK_SESSION_HANDLE session,
			  CK_BYTE_PTR cipher, CK_ULONG cipherlen,
			  CK_BYTE_PTR * part, CK_ULONG_PTR partlen)
{
	CK_RV rv =
	    c->sym->C_DecryptDigestUpdate(session, cipher, cipherlen, NULL,
					  partlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*part = calloc(*partlen, sizeof(CK_BYTE));
	if (*part == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DecryptDigestUpdate(session, cipher, cipherlen, *part,
					   partlen);
	return rv;
}

CK_RV SignEncryptUpdate(struct ctx * c, CK_SESSION_HANDLE session,
			CK_BYTE_PTR part, CK_ULONG partlen, CK_BYTE_PTR * enc,
			CK_ULONG_PTR enclen)
{
	CK_RV rv =
	    c->sym->C_SignEncryptUpdate(session, part, partlen, NULL, enclen);
	if (rv != CKR_OK) {
		return rv;
	}
	*enc = calloc(*enclen, sizeof(CK_BYTE));
	if (*enc == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_SignEncryptUpdate(session, part, partlen, *enc, enclen);
	return rv;
}

CK_RV DecryptVerifyUpdate(struct ctx * c, CK_SESSION_HANDLE session,
			  CK_BYTE_PTR cipher, CK_ULONG cipherlen,
			  CK_BYTE_PTR * part, CK_ULONG_PTR partlen)
{
	CK_RV rv =
	    c->sym->C_DecryptVerifyUpdate(session, cipher, cipherlen, NULL,
					  partlen);
	if (rv != CKR_OK) {
		return rv;
	}
	*part = calloc(*partlen, sizeof(CK_BYTE));
	if (*part == NULL) {
		return CKR_HOST_MEMORY;
	}
	rv = c->sym->C_DecryptVerifyUpdate(session, cipher, cipherlen, *part,
					   partlen);
	return rv;
}

CK_RV GenerateKey(struct ctx * c, CK_SESSION_HANDLE session,
		  CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR temp,
		  CK_ULONG tempCount, CK_OBJECT_HANDLE_PTR key)
{
	return c->sym->C_GenerateKey(session, mechanism, temp, tempCount, key);
}

CK_RV GenerateKeyPair(struct ctx * c, CK_SESSION_HANDLE session,
		      CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR pub,
		      CK_ULONG pubCount, CK_ATTRIBUTE_PTR priv,
		      CK_ULONG privCount, CK_OBJECT_HANDLE_PTR pubkey,
		      CK_OBJECT_HANDLE_PTR privkey)
{
	return c->sym->C_GenerateKeyPair(session, mechanism, pub, pubCount,
		priv, privCount, pubkey, privkey);
}

CK_RV WrapKey(struct ctx * c, CK_SESSION_HANDLE session,
	      CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrappingkey,
	      CK_OBJECT_HANDLE key, CK_BYTE_PTR * wrapped,
	      CK_ULONG_PTR wrappedlen)
{
	CK_RV rv = c->sym->C_WrapKey(session, mechanism, wrappingkey, key, NULL,
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

CK_RV DeriveKey(struct ctx * c, CK_SESSION_HANDLE session,
		CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE basekey,
		CK_ATTRIBUTE_PTR a, CK_ULONG alen, CK_OBJECT_HANDLE_PTR key)
{
	return c->sym->C_DeriveKey(session, mechanism, basekey, a, alen, key);
}

CK_RV UnwrapKey(struct ctx * c, CK_SESSION_HANDLE session,
		CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE unwrappingkey,
		CK_BYTE_PTR wrappedkey, CK_ULONG wrappedkeylen,
		CK_ATTRIBUTE_PTR a, CK_ULONG alen, CK_OBJECT_HANDLE_PTR key)
{
	return c->sym->C_UnwrapKey(session, mechanism, unwrappingkey, wrappedkey,
				      wrappedkeylen, a, alen, key);
}

CK_RV SeedRandom(struct ctx * c, CK_SESSION_HANDLE session, CK_BYTE_PTR seed,
		 CK_ULONG seedlen)
{
	CK_RV e = c->sym->C_SeedRandom(session, seed, seedlen);
	return e;
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
	CK_RV e =
	    c->sym->C_WaitForSlotEvent(flags, (CK_SLOT_ID_PTR) slot, NULL);
	return e;
}

static inline CK_VOID_PTR getAttributePval(CK_ATTRIBUTE_PTR a)
{
	return a->pValue;
}

// ── PKCS #11 v3.2 trampolines ─────────────────────────────────────────────
// All functions call through c->fl32, which is NULL when the token does not
// support v3.2.  The guard macro returns CKR_FUNCTION_NOT_SUPPORTED in that
// case so callers receive a well-defined error rather than a crash.
// Argument order matches the official OASIS pkcs11f.h exactly.
// ──────────────────────────────────────────────────────────────────────────

#define P11_V32_GUARD(c, fn) \
	if ((c)->fl32 == NULL || (c)->fl32->fn == NULL) \
		return CKR_FUNCTION_NOT_SUPPORTED

CK_RV EncapsulateKey(struct ctx *c, CK_SESSION_HANDLE session,
		     CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE pubKey,
		     CK_ATTRIBUTE_PTR tmpl, CK_ULONG tmplCount,
		     CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen,
		     CK_OBJECT_HANDLE_PTR phKey)
{
	P11_V32_GUARD(c, C_EncapsulateKey);
	return c->fl32->C_EncapsulateKey(session, mechanism, pubKey,
		tmpl, tmplCount, pCiphertext, pulCiphertextLen, phKey);
}

CK_RV DecapsulateKey(struct ctx *c, CK_SESSION_HANDLE session,
		     CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE privKey,
		     CK_ATTRIBUTE_PTR tmpl, CK_ULONG tmplCount,
		     CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen,
		     CK_OBJECT_HANDLE_PTR phKey)
{
	P11_V32_GUARD(c, C_DecapsulateKey);
	return c->fl32->C_DecapsulateKey(session, mechanism, privKey,
		tmpl, tmplCount, pCiphertext, ulCiphertextLen, phKey);
}

CK_RV VerifySignatureInit(struct ctx *c, CK_SESSION_HANDLE session,
			  CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key,
			  CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	P11_V32_GUARD(c, C_VerifySignatureInit);
	return c->fl32->C_VerifySignatureInit(session, mechanism, key,
		pSignature, ulSignatureLen);
}

CK_RV VerifySignature(struct ctx *c, CK_SESSION_HANDLE session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	P11_V32_GUARD(c, C_VerifySignature);
	return c->fl32->C_VerifySignature(session, pData, ulDataLen);
}

CK_RV VerifySignatureUpdate(struct ctx *c, CK_SESSION_HANDLE session,
			    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	P11_V32_GUARD(c, C_VerifySignatureUpdate);
	return c->fl32->C_VerifySignatureUpdate(session, pPart, ulPartLen);
}

CK_RV VerifySignatureFinal(struct ctx *c, CK_SESSION_HANDLE session)
{
	P11_V32_GUARD(c, C_VerifySignatureFinal);
	return c->fl32->C_VerifySignatureFinal(session);
}

CK_RV GetSessionValidationFlags(struct ctx *c, CK_SESSION_HANDLE session,
				CK_SESSION_VALIDATION_FLAGS_TYPE type,
				CK_FLAGS_PTR pFlags)
{
	P11_V32_GUARD(c, C_GetSessionValidationFlags);
	return c->fl32->C_GetSessionValidationFlags(session, type, pFlags);
}

CK_RV WrapKeyAuthenticated(struct ctx *c, CK_SESSION_HANDLE session,
			   CK_MECHANISM_PTR mechanism,
			   CK_OBJECT_HANDLE wrappingKey, CK_OBJECT_HANDLE key,
			   CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
			   CK_BYTE_PTR *pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	P11_V32_GUARD(c, C_WrapKeyAuthenticated);
	return c->fl32->C_WrapKeyAuthenticated(session, mechanism,
		wrappingKey, key,
		pAssociatedData, ulAssociatedDataLen,
		*pWrappedKey, pulWrappedKeyLen);
}

// Official pkcs11f.h order: pTemplate/ulAttributeCount BEFORE pAssociatedData
CK_RV UnwrapKeyAuthenticated(struct ctx *c, CK_SESSION_HANDLE session,
			     CK_MECHANISM_PTR mechanism,
			     CK_OBJECT_HANDLE unwrappingKey,
			     CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
			     CK_ATTRIBUTE_PTR tmpl, CK_ULONG tmplCount,
			     CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
			     CK_OBJECT_HANDLE_PTR phKey)
{
	P11_V32_GUARD(c, C_UnwrapKeyAuthenticated);
	return c->fl32->C_UnwrapKeyAuthenticated(session, mechanism,
		unwrappingKey,
		pWrappedKey, ulWrappedKeyLen,
		tmpl, tmplCount,
		pAssociatedData, ulAssociatedDataLen,
		phKey);
}

CK_RV AsyncComplete(struct ctx *c, CK_SESSION_HANDLE session,
		    CK_UTF8CHAR_PTR pFunctionName, CK_ASYNC_DATA_PTR pResult)
{
	P11_V32_GUARD(c, C_AsyncComplete);
	return c->fl32->C_AsyncComplete(session, pFunctionName, pResult);
}

CK_RV AsyncGetID(struct ctx *c, CK_SESSION_HANDLE session,
		 CK_UTF8CHAR_PTR pFunctionName, CK_ULONG_PTR pulID)
{
	P11_V32_GUARD(c, C_AsyncGetID);
	return c->fl32->C_AsyncGetID(session, pFunctionName, pulID);
}

CK_RV AsyncJoin(struct ctx *c, CK_SESSION_HANDLE session,
		CK_UTF8CHAR_PTR pFunctionName, CK_ULONG ulID,
		CK_BYTE_PTR pData, CK_ULONG ulData)
{
	P11_V32_GUARD(c, C_AsyncJoin);
	return c->fl32->C_AsyncJoin(session, pFunctionName, ulID,
		pData, ulData);
}

#undef P11_V32_GUARD
*/
import "C"
import (
	"strings"
	"unsafe"
)

// Ctx contains the current pkcs11 context.
type Ctx struct {
	ctx *C.struct_ctx
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
	if c == nil || c.ctx == nil {
		return
	}
	C.Destroy(c.ctx)
	c.ctx = nil
}

type initializeArgs struct {
	flags    uint
	reserved unsafe.Pointer
}

// An InitializeOption modifies the default behavior of Initialize.
type InitializeOption func(*initializeArgs)

// InitializeWithFlags sets the flags field in CK_C_INITIALIZE_ARGS.
// Note that flags defaults to CKF_OS_LOCKING_OK if this option is not provided.
func InitializeWithFlags(flags uint) InitializeOption {
	return func(args *initializeArgs) {
		args.flags = flags
	}
}

// InitializeWithReserved sets the pReserved field in CK_C_INITIALIZE_ARGS.
func InitializeWithReserved(reserved unsafe.Pointer) InitializeOption {
	return func(args *initializeArgs) {
		args.reserved = reserved
	}
}

// Initialize initializes the Cryptoki library.
func (c *Ctx) Initialize(opts ...InitializeOption) error {
	args := initializeArgs{flags: CKF_OS_LOCKING_OK}
	for _, o := range opts {
		o(&args)
	}
	e := C.Initialize(c.ctx, C.CK_FLAGS(args.flags), C.CK_VOID_PTR(args.reserved))
	return toError(e)
}

// Finalize indicates that an application is done with the Cryptoki library.
func (c *Ctx) Finalize() error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.Finalize(c.ctx)
	return toError(e)
}

// GetInfo returns general information about Cryptoki.
func (c *Ctx) GetInfo() (Info, error) {
	var p C.ckInfo
	e := C.GetInfo(c.ctx, &p)
	i := Info{
		CryptokiVersion:    toVersion(p.cryptokiVersion),
		ManufacturerID:     strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&p.manufacturerID[0]), 32)), " "),
		Flags:              uint(p.flags),
		LibraryDescription: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&p.libraryDescription[0]), 32)), " "),
		LibraryVersion:     toVersion(p.libraryVersion),
	}
	return i, toError(e)
}

// GetSlotList obtains a list of slots in the system.
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

// GetSlotInfo obtains information about a particular slot in the system.
func (c *Ctx) GetSlotInfo(slotID uint) (SlotInfo, error) {
	var csi C.CK_SLOT_INFO
	e := C.GetSlotInfo(c.ctx, C.CK_ULONG(slotID), &csi)
	s := SlotInfo{
		SlotDescription: strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&csi.slotDescription[0]), 64)), " "),
		ManufacturerID:  strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&csi.manufacturerID[0]), 32)), " "),
		Flags:           uint(csi.flags),
		HardwareVersion: toVersion(csi.hardwareVersion),
		FirmwareVersion: toVersion(csi.firmwareVersion),
	}
	return s, toError(e)
}

// GetTokenInfo obtains information about a particular token
// in the system.
func (c *Ctx) GetTokenInfo(slotID uint) (TokenInfo, error) {
	var cti C.CK_TOKEN_INFO
	e := C.GetTokenInfo(c.ctx, C.CK_ULONG(slotID), &cti)
	s := TokenInfo{
		Label:              strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&cti.label[0]), 32)), " "),
		ManufacturerID:     strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&cti.manufacturerID[0]), 32)), " "),
		Model:              strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&cti.model[0]), 16)), " "),
		SerialNumber:       strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&cti.serialNumber[0]), 16)), " "),
		Flags:              uint(cti.flags),
		MaxSessionCount:    uint(cti.ulMaxSessionCount),
		SessionCount:       uint(cti.ulSessionCount),
		MaxRwSessionCount:  uint(cti.ulMaxRwSessionCount),
		RwSessionCount:     uint(cti.ulRwSessionCount),
		MaxPinLen:          uint(cti.ulMaxPinLen),
		MinPinLen:          uint(cti.ulMinPinLen),
		TotalPublicMemory:  uint(cti.ulTotalPublicMemory),
		FreePublicMemory:   uint(cti.ulFreePublicMemory),
		TotalPrivateMemory: uint(cti.ulTotalPrivateMemory),
		FreePrivateMemory:  uint(cti.ulFreePrivateMemory),
		HardwareVersion:    toVersion(cti.hardwareVersion),
		FirmwareVersion:    toVersion(cti.firmwareVersion),
		UTCTime:            strings.TrimRight(string(C.GoBytes(unsafe.Pointer(&cti.utcTime[0]), 16)), " "),
	}
	return s, toError(e)
}

// GetMechanismList obtains a list of mechanism types supported by a token.
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

// GetMechanismInfo obtains information about a particular
// mechanism possibly supported by a token.
func (c *Ctx) GetMechanismInfo(slotID uint, m []*Mechanism) (MechanismInfo, error) {
	var cm C.CK_MECHANISM_INFO
	e := C.GetMechanismInfo(c.ctx, C.CK_ULONG(slotID), C.CK_MECHANISM_TYPE(m[0].Mechanism),
		C.CK_MECHANISM_INFO_PTR(&cm))
	mi := MechanismInfo{
		MinKeySize: uint(cm.ulMinKeySize),
		MaxKeySize: uint(cm.ulMaxKeySize),
		Flags:      uint(cm.flags),
	}
	return mi, toError(e)
}

// InitToken initializes a token. The label must be 32 characters
// long, it is blank padded if it is not. If it is longer it is capped
// to 32 characters.
func (c *Ctx) InitToken(slotID uint, pin string, label string) error {
	p := C.CString(pin)
	defer C.free(unsafe.Pointer(p))
	ll := len(label)
	for ll < 32 {
		label += " "
		ll++
	}
	l := C.CString(label[:32])
	defer C.free(unsafe.Pointer(l))
	e := C.InitToken(c.ctx, C.CK_ULONG(slotID), p, C.CK_ULONG(len(pin)), l)
	return toError(e)
}

// InitPIN initializes the normal user's PIN.
func (c *Ctx) InitPIN(sh SessionHandle, pin string) error {
	p := C.CString(pin)
	defer C.free(unsafe.Pointer(p))
	e := C.InitPIN(c.ctx, C.CK_SESSION_HANDLE(sh), p, C.CK_ULONG(len(pin)))
	return toError(e)
}

// SetPIN modifies the PIN of the user who is logged in.
func (c *Ctx) SetPIN(sh SessionHandle, oldpin string, newpin string) error {
	old := C.CString(oldpin)
	defer C.free(unsafe.Pointer(old))
	new := C.CString(newpin)
	defer C.free(unsafe.Pointer(new))
	e := C.SetPIN(c.ctx, C.CK_SESSION_HANDLE(sh), old, C.CK_ULONG(len(oldpin)), new, C.CK_ULONG(len(newpin)))
	return toError(e)
}

// OpenSession opens a session between an application and a token.
func (c *Ctx) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	var s C.CK_SESSION_HANDLE
	e := C.OpenSession(c.ctx, C.CK_ULONG(slotID), C.CK_ULONG(flags), C.CK_SESSION_HANDLE_PTR(&s))
	return SessionHandle(s), toError(e)
}

// CloseSession closes a session between an application and a token.
func (c *Ctx) CloseSession(sh SessionHandle) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.CloseSession(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

// CloseAllSessions closes all sessions with a token.
func (c *Ctx) CloseAllSessions(slotID uint) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.CloseAllSessions(c.ctx, C.CK_ULONG(slotID))
	return toError(e)
}

// GetSessionInfo obtains information about the session.
func (c *Ctx) GetSessionInfo(sh SessionHandle) (SessionInfo, error) {
	var csi C.CK_SESSION_INFO
	e := C.GetSessionInfo(c.ctx, C.CK_SESSION_HANDLE(sh), &csi)
	s := SessionInfo{SlotID: uint(csi.slotID),
		State:       uint(csi.state),
		Flags:       uint(csi.flags),
		DeviceError: uint(csi.ulDeviceError),
	}
	return s, toError(e)
}

// GetOperationState obtains the state of the cryptographic operation in a session.
func (c *Ctx) GetOperationState(sh SessionHandle) ([]byte, error) {
	var (
		state    C.CK_BYTE_PTR
		statelen C.CK_ULONG
	)
	e := C.GetOperationState(c.ctx, C.CK_SESSION_HANDLE(sh), &state, &statelen)
	defer C.free(unsafe.Pointer(state))
	if toError(e) != nil {
		return nil, toError(e)
	}
	b := C.GoBytes(unsafe.Pointer(state), C.int(statelen))
	return b, nil
}

// SetOperationState restores the state of the cryptographic operation in a session.
func (c *Ctx) SetOperationState(sh SessionHandle, state []byte, encryptKey, authKey ObjectHandle) error {
	e := C.SetOperationState(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&state[0])),
		C.CK_ULONG(len(state)), C.CK_OBJECT_HANDLE(encryptKey), C.CK_OBJECT_HANDLE(authKey))
	return toError(e)
}

// Login logs a user into a token.
func (c *Ctx) Login(sh SessionHandle, userType uint, pin string) error {
	p := C.CString(pin)
	defer C.free(unsafe.Pointer(p))
	e := C.Login(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_USER_TYPE(userType), p, C.CK_ULONG(len(pin)))
	return toError(e)
}

// Logout logs a user out from a token.
func (c *Ctx) Logout(sh SessionHandle) error {
	if c.ctx == nil {
		return toError(CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	e := C.Logout(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

// CreateObject creates a new object.
func (c *Ctx) CreateObject(sh SessionHandle, temp []*Attribute) (ObjectHandle, error) {
	var obj C.CK_OBJECT_HANDLE
	arena, t, tcount := cAttributeList(temp)
	defer arena.Free()
	e := C.CreateObject(c.ctx, C.CK_SESSION_HANDLE(sh), t, tcount, C.CK_OBJECT_HANDLE_PTR(&obj))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(obj), nil
	}
	return 0, e1
}

// CopyObject copies an object, creating a new object for the copy.
func (c *Ctx) CopyObject(sh SessionHandle, o ObjectHandle, temp []*Attribute) (ObjectHandle, error) {
	var obj C.CK_OBJECT_HANDLE
	arena, t, tcount := cAttributeList(temp)
	defer arena.Free()

	e := C.CopyObject(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(o), t, tcount, C.CK_OBJECT_HANDLE_PTR(&obj))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(obj), nil
	}
	return 0, e1
}

// DestroyObject destroys an object.
func (c *Ctx) DestroyObject(sh SessionHandle, oh ObjectHandle) error {
	e := C.DestroyObject(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(oh))
	return toError(e)
}

// GetObjectSize gets the size of an object in bytes.
func (c *Ctx) GetObjectSize(sh SessionHandle, oh ObjectHandle) (uint, error) {
	var size C.CK_ULONG
	e := C.GetObjectSize(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(oh), &size)
	return uint(size), toError(e)
}

// GetAttributeValue obtains the value of one or more object attributes.
func (c *Ctx) GetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) ([]*Attribute, error) {
	// copy the attribute list and make all the values nil, so that
	// the C function can (allocate) fill them in
	pa := make([]C.CK_ATTRIBUTE, len(a))
	for i := 0; i < len(a); i++ {
		pa[i]._type = C.CK_ATTRIBUTE_TYPE(a[i].Type)
	}
	e := C.GetAttributeValue(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(o), &pa[0], C.CK_ULONG(len(a)))
	if err := toError(e); err != nil {
		return nil, err
	}
	a1 := make([]*Attribute, len(a))
	for i, c := range pa {
		x := new(Attribute)
		x.Type = uint(c._type)
		if int(c.ulValueLen) != -1 {
			buf := unsafe.Pointer(C.getAttributePval(&c))
			x.Value = C.GoBytes(buf, C.int(c.ulValueLen))
			C.free(buf)
		}
		a1[i] = x
	}
	return a1, nil
}

// SetAttributeValue modifies the value of one or more object attributes
func (c *Ctx) SetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) error {
	arena, pa, palen := cAttributeList(a)
	defer arena.Free()
	e := C.SetAttributeValue(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(o), pa, palen)
	return toError(e)
}

// FindObjectsInit initializes a search for token and session
// objects that match a template.
func (c *Ctx) FindObjectsInit(sh SessionHandle, temp []*Attribute) error {
	arena, t, tcount := cAttributeList(temp)
	defer arena.Free()
	e := C.FindObjectsInit(c.ctx, C.CK_SESSION_HANDLE(sh), t, tcount)
	return toError(e)
}

// FindObjects continues a search for token and session
// objects that match a template, obtaining additional object
// handles. Calling the function repeatedly may yield additional results until
// an empty slice is returned.
//
// The returned boolean value is deprecated and should be ignored.
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

// FindObjectsFinal finishes a search for token and session objects.
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	e := C.FindObjectsFinal(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(e)
}

// EncryptInit initializes an encryption operation.
func (c *Ctx) EncryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.EncryptInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(o))
	return toError(e)
}

// Encrypt encrypts single-part data.
func (c *Ctx) Encrypt(sh SessionHandle, message []byte) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	e := C.Encrypt(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(message), C.CK_ULONG(len(message)), &enc, &enclen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	s := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return s, nil
}

// EncryptUpdate continues a multiple-part encryption operation.
func (c *Ctx) EncryptUpdate(sh SessionHandle, plain []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	e := C.EncryptUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(plain), C.CK_ULONG(len(plain)), &part, &partlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// EncryptFinal finishes a multiple-part encryption operation.
func (c *Ctx) EncryptFinal(sh SessionHandle) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	e := C.EncryptFinal(c.ctx, C.CK_SESSION_HANDLE(sh), &enc, &enclen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return h, nil
}

// DecryptInit initializes a decryption operation.
func (c *Ctx) DecryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.DecryptInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(o))
	return toError(e)
}

// Decrypt decrypts encrypted data in a single part.
func (c *Ctx) Decrypt(sh SessionHandle, cipher []byte) ([]byte, error) {
	var (
		plain    C.CK_BYTE_PTR
		plainlen C.CK_ULONG
	)
	e := C.Decrypt(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(cipher), C.CK_ULONG(len(cipher)), &plain, &plainlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	s := C.GoBytes(unsafe.Pointer(plain), C.int(plainlen))
	C.free(unsafe.Pointer(plain))
	return s, nil
}

// DecryptUpdate continues a multiple-part decryption operation.
func (c *Ctx) DecryptUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	e := C.DecryptUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(cipher), C.CK_ULONG(len(cipher)), &part, &partlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// DecryptFinal finishes a multiple-part decryption operation.
func (c *Ctx) DecryptFinal(sh SessionHandle) ([]byte, error) {
	var (
		plain    C.CK_BYTE_PTR
		plainlen C.CK_ULONG
	)
	e := C.DecryptFinal(c.ctx, C.CK_SESSION_HANDLE(sh), &plain, &plainlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(plain), C.int(plainlen))
	C.free(unsafe.Pointer(plain))
	return h, nil
}

// DigestInit initializes a message-digesting operation.
func (c *Ctx) DigestInit(sh SessionHandle, m []*Mechanism) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.DigestInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech)
	return toError(e)
}

// Digest digests message in a single part.
func (c *Ctx) Digest(sh SessionHandle, message []byte) ([]byte, error) {
	var (
		hash    C.CK_BYTE_PTR
		hashlen C.CK_ULONG
	)
	e := C.Digest(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(message), C.CK_ULONG(len(message)), &hash, &hashlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(hash), C.int(hashlen))
	C.free(unsafe.Pointer(hash))
	return h, nil
}

// DigestUpdate continues a multiple-part message-digesting operation.
func (c *Ctx) DigestUpdate(sh SessionHandle, message []byte) error {
	e := C.DigestUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(message), C.CK_ULONG(len(message)))
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

// DigestFinal finishes a multiple-part message-digesting operation.
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
// the data, and plaintext cannot be recovered from the signature.
func (c *Ctx) SignInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
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
	e := C.Sign(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(message), C.CK_ULONG(len(message)), &sig, &siglen)
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
	e := C.SignUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(message), C.CK_ULONG(len(message)))
	return toError(e)
}

// SignFinal finishes a multiple-part signature operation returning the signature.
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

// SignRecoverInit initializes a signature operation, where the data can be recovered from the signature.
func (c *Ctx) SignRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.SignRecoverInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))
	return toError(e)
}

// SignRecover signs data in a single operation, where the data can be recovered from the signature.
func (c *Ctx) SignRecover(sh SessionHandle, data []byte) ([]byte, error) {
	var (
		sig    C.CK_BYTE_PTR
		siglen C.CK_ULONG
	)
	e := C.SignRecover(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(data), C.CK_ULONG(len(data)), &sig, &siglen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(sig), C.int(siglen))
	C.free(unsafe.Pointer(sig))
	return h, nil
}

// VerifyInit initializes a verification operation, where the
// signature is an appendix to the data, and plaintext cannot
// be recovered from the signature (e.g. DSA).
func (c *Ctx) VerifyInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.VerifyInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))
	return toError(e)
}

// Verify verifies a signature in a single-part operation,
// where the signature is an appendix to the data, and plaintext
// cannot be recovered from the signature.
func (c *Ctx) Verify(sh SessionHandle, data []byte, signature []byte) error {
	e := C.Verify(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(data), C.CK_ULONG(len(data)), cMessage(signature), C.CK_ULONG(len(signature)))
	return toError(e)
}

// VerifyUpdate continues a multiple-part verification
// operation, where the signature is an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (c *Ctx) VerifyUpdate(sh SessionHandle, part []byte) error {
	e := C.VerifyUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(part), C.CK_ULONG(len(part)))
	return toError(e)
}

// VerifyFinal finishes a multiple-part verification
// operation, checking the signature.
func (c *Ctx) VerifyFinal(sh SessionHandle, signature []byte) error {
	e := C.VerifyFinal(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(signature), C.CK_ULONG(len(signature)))
	return toError(e)
}

// VerifyRecoverInit initializes a signature verification
// operation, where the data is recovered from the signature.
func (c *Ctx) VerifyRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.VerifyRecoverInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))
	return toError(e)
}

// VerifyRecover verifies a signature in a single-part
// operation, where the data is recovered from the signature.
func (c *Ctx) VerifyRecover(sh SessionHandle, signature []byte) ([]byte, error) {
	var (
		data    C.CK_BYTE_PTR
		datalen C.CK_ULONG
	)
	e := C.DecryptVerifyUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(signature), C.CK_ULONG(len(signature)), &data, &datalen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(data), C.int(datalen))
	C.free(unsafe.Pointer(data))
	return h, nil
}

// DigestEncryptUpdate continues a multiple-part digesting and encryption operation.
func (c *Ctx) DigestEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	e := C.DigestEncryptUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(part), C.CK_ULONG(len(part)), &enc, &enclen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return h, nil
}

// DecryptDigestUpdate continues a multiple-part decryption and digesting operation.
func (c *Ctx) DecryptDigestUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	e := C.DecryptDigestUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(cipher), C.CK_ULONG(len(cipher)), &part, &partlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// SignEncryptUpdate continues a multiple-part signing and encryption operation.
func (c *Ctx) SignEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	var (
		enc    C.CK_BYTE_PTR
		enclen C.CK_ULONG
	)
	e := C.SignEncryptUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(part), C.CK_ULONG(len(part)), &enc, &enclen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(enc), C.int(enclen))
	C.free(unsafe.Pointer(enc))
	return h, nil
}

// DecryptVerifyUpdate continues a multiple-part decryption and verify operation.
func (c *Ctx) DecryptVerifyUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	var (
		part    C.CK_BYTE_PTR
		partlen C.CK_ULONG
	)
	e := C.DecryptVerifyUpdate(c.ctx, C.CK_SESSION_HANDLE(sh), cMessage(cipher), C.CK_ULONG(len(cipher)), &part, &partlen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(part), C.int(partlen))
	C.free(unsafe.Pointer(part))
	return h, nil
}

// GenerateKey generates a secret key, creating a new key object.
func (c *Ctx) GenerateKey(sh SessionHandle, m []*Mechanism, temp []*Attribute) (ObjectHandle, error) {
	var key C.CK_OBJECT_HANDLE
	attrarena, t, tcount := cAttributeList(temp)
	defer attrarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	e := C.GenerateKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, t, tcount, C.CK_OBJECT_HANDLE_PTR(&key))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(key), nil
	}
	return 0, e1
}

// GenerateKeyPair generates a public-key/private-key pair creating new key objects.
func (c *Ctx) GenerateKeyPair(sh SessionHandle, m []*Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	var (
		pubkey  C.CK_OBJECT_HANDLE
		privkey C.CK_OBJECT_HANDLE
	)
	pubarena, pub, pubcount := cAttributeList(public)
	defer pubarena.Free()
	privarena, priv, privcount := cAttributeList(private)
	defer privarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	e := C.GenerateKeyPair(c.ctx, C.CK_SESSION_HANDLE(sh), mech, pub, pubcount, priv, privcount, C.CK_OBJECT_HANDLE_PTR(&pubkey), C.CK_OBJECT_HANDLE_PTR(&privkey))
	e1 := toError(e)
	if e1 == nil {
		return ObjectHandle(pubkey), ObjectHandle(privkey), nil
	}
	return 0, 0, e1
}

// WrapKey wraps (i.e., encrypts) a key.
func (c *Ctx) WrapKey(sh SessionHandle, m []*Mechanism, wrappingkey, key ObjectHandle) ([]byte, error) {
	var (
		wrappedkey    C.CK_BYTE_PTR
		wrappedkeylen C.CK_ULONG
	)
	arena, mech := cMechanism(m)
	defer arena.Free()
	e := C.WrapKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(wrappingkey), C.CK_OBJECT_HANDLE(key), &wrappedkey, &wrappedkeylen)
	if toError(e) != nil {
		return nil, toError(e)
	}
	h := C.GoBytes(unsafe.Pointer(wrappedkey), C.int(wrappedkeylen))
	C.free(unsafe.Pointer(wrappedkey))
	return h, nil
}

// UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object.
func (c *Ctx) UnwrapKey(sh SessionHandle, m []*Mechanism, unwrappingkey ObjectHandle, wrappedkey []byte, a []*Attribute) (ObjectHandle, error) {
	var key C.CK_OBJECT_HANDLE
	attrarena, ac, aclen := cAttributeList(a)
	defer attrarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	e := C.UnwrapKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(unwrappingkey), C.CK_BYTE_PTR(unsafe.Pointer(&wrappedkey[0])), C.CK_ULONG(len(wrappedkey)), ac, aclen, &key)
	return ObjectHandle(key), toError(e)
}

// DeriveKey derives a key from a base key, creating a new key object.
func (c *Ctx) DeriveKey(sh SessionHandle, m []*Mechanism, basekey ObjectHandle, a []*Attribute) (ObjectHandle, error) {
	var key C.CK_OBJECT_HANDLE
	attrarena, ac, aclen := cAttributeList(a)
	defer attrarena.Free()
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	e := C.DeriveKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(basekey), ac, aclen, &key)
	return ObjectHandle(key), toError(e)
}

// SeedRandom mixes additional seed material into the token's
// random number generator.
func (c *Ctx) SeedRandom(sh SessionHandle, seed []byte) error {
	e := C.SeedRandom(c.ctx, C.CK_SESSION_HANDLE(sh), C.CK_BYTE_PTR(unsafe.Pointer(&seed[0])), C.CK_ULONG(len(seed)))
	return toError(e)
}

// GenerateRandom generates random data.
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
// (token insertion, removal, etc.) when it occurs.
func (c *Ctx) WaitForSlotEvent(flags uint) chan SlotEvent {
	sl := make(chan SlotEvent, 1) // hold one element
	go c.waitForSlotEventHelper(flags, sl)
	return sl
}

func (c *Ctx) waitForSlotEventHelper(f uint, sl chan SlotEvent) {
	var slotID C.CK_ULONG
	C.WaitForSlotEvent(c.ctx, C.CK_FLAGS(f), &slotID)
	sl <- SlotEvent{uint(slotID)}
	close(sl) // TODO(miek): Sending and then closing ...?
}

// ── PKCS #11 v3.2 Go methods ─────────────────────────────────────────────────
// ── ML-KEM: Encapsulation / Decapsulation ────────────────────────────────────

// All methods return ErrFunctionNotSupported when called against a token that
// does not advertise a v3.2 interface via C_GetInterface.

// EncapsulateKey performs KEM encapsulation (PKCS #11 v3.2 §5.18.8).
// Returns the ciphertext and a handle to the newly derived shared-secret key.
//   - ciphertext: the KEM ciphertext to be sent to the recipient
//   - key:        handle to the newly derived shared-secret key object
//
// The attrs template controls the type of the derived key object, for example:
//
//	symTmpl := []*pkcs11.Attribute{
//	    pkcs11.NewAttribute(pkcs11.CKA_CLASS,     pkcs11.CKO_SECRET_KEY),
//	    pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,  pkcs11.CKK_AES),
//	    pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
//	    pkcs11.NewAttribute(pkcs11.CKA_TOKEN,     false),
//	}
//	ct, symKey, err := ctx.EncapsulateKey(sh,
//	    []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ML_KEM, nil)},
//	    pubKey, symTmpl)
func (c *Ctx) EncapsulateKey(sh SessionHandle, m []*Mechanism, pubKey ObjectHandle, attrs []*Attribute) ([]byte, ObjectHandle, error) {
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	attrarena, tmpl, tmplCount := cAttributeList(attrs)
	defer attrarena.Free()

	var phKey C.CK_OBJECT_HANDLE
	var ctLen C.CK_ULONG
	rv := C.EncapsulateKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(pubKey), tmpl, tmplCount,
		nil, &ctLen, &phKey)
	if rv != C.CKR_OK && rv != C.CKR_BUFFER_TOO_SMALL {
		return nil, 0, toError(rv)
	}
	ct := make([]byte, ctLen)
	rv = C.EncapsulateKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(pubKey), tmpl, tmplCount,
		(*C.CK_BYTE)(unsafe.Pointer(&ct[0])), &ctLen, &phKey)
	if rv != C.CKR_OK {
		return nil, 0, toError(rv)
	}
	return ct[:ctLen], ObjectHandle(phKey), nil
}

// DecapsulateKey performs KEM decapsulation (PKCS #11 v3.2 §5.18.9).
// Returns a handle to the recovered shared-secret key.
func (c *Ctx) DecapsulateKey(sh SessionHandle, m []*Mechanism, privKey ObjectHandle, attrs []*Attribute, ciphertext []byte) (ObjectHandle, error) {
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	attrarena, tmpl, tmplCount := cAttributeList(attrs)
	defer attrarena.Free()

	var phKey C.CK_OBJECT_HANDLE
	rv := C.DecapsulateKey(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(privKey), tmpl, tmplCount,
		cMessage(ciphertext), C.CK_ULONG(len(ciphertext)), &phKey)
	return ObjectHandle(phKey), toError(rv)
}

// VerifySignatureInit initialises a stateless verify operation (v3.2 §5.15).
// The signature is bound at init, not at the final step.
func (c *Ctx) VerifySignatureInit(sh SessionHandle, m []*Mechanism, key ObjectHandle, signature []byte) error {
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	rv := C.VerifySignatureInit(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(key),
		cMessage(signature), C.CK_ULONG(len(signature)))
	return toError(rv)
}

// VerifySignature completes a single-part stateless verify (v3.2 §5.15).
// Must be preceded by VerifySignatureInit.
func (c *Ctx) VerifySignature(sh SessionHandle, data []byte) error {
	rv := C.VerifySignature(c.ctx, C.CK_SESSION_HANDLE(sh),
		cMessage(data), C.CK_ULONG(len(data)))
	return toError(rv)
}

// VerifySignatureUpdate feeds data to an ongoing stateless verify (v3.2 §5.15).
func (c *Ctx) VerifySignatureUpdate(sh SessionHandle, part []byte) error {
	rv := C.VerifySignatureUpdate(c.ctx, C.CK_SESSION_HANDLE(sh),
		cMessage(part), C.CK_ULONG(len(part)))
	return toError(rv)
}

// VerifySignatureFinal completes a multi-part stateless verify (v3.2 §5.15).
func (c *Ctx) VerifySignatureFinal(sh SessionHandle) error {
	rv := C.VerifySignatureFinal(c.ctx, C.CK_SESSION_HANDLE(sh))
	return toError(rv)
}

// GetSessionValidationFlags queries the FIPS validation status of the last
// operation on this session (v3.2 §5.6.11).
// Pass CKS_LAST_VALIDATION_OK to check whether the last operation was validated.
func (c *Ctx) GetSessionValidationFlags(sh SessionHandle, flagType uint) (uint, error) {
	var flags C.CK_FLAGS
	rv := C.GetSessionValidationFlags(c.ctx, C.CK_SESSION_HANDLE(sh),
		C.CK_SESSION_VALIDATION_FLAGS_TYPE(flagType), &flags)
	if rv != C.CKR_OK {
		return 0, toError(rv)
	}
	return uint(flags), nil
}

// WrapKeyAuthenticated wraps a key with AEAD authentication (v3.2 §5.18.6).
// Returns the wrapped key blob (ciphertext + authentication tag).
func (c *Ctx) WrapKeyAuthenticated(sh SessionHandle, m []*Mechanism, wrappingKey, key ObjectHandle, aad []byte) ([]byte, error) {
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()

	var aadPtr C.CK_BYTE_PTR
	if len(aad) > 0 {
		aadPtr = cMessage(aad)
	}

	// Length query: pass nil buffer to discover the required output size.
	var wrappedKey C.CK_BYTE_PTR
	var wrappedLen C.CK_ULONG
	rv := C.WrapKeyAuthenticated(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		aadPtr, C.CK_ULONG(len(aad)),
		&wrappedKey, &wrappedLen)
	if rv != C.CKR_OK && rv != C.CKR_BUFFER_TOO_SMALL {
		return nil, toError(rv)
	}

	// Allocate the output buffer with C.malloc so that &wrappedKey (a Go
	// pointer to a C.CK_BYTE_PTR) never points into Go-managed heap memory.
	// Passing a Go pointer to a Go pointer is forbidden by the CGo rules
	// and causes a runtime panic in Go 1.21+.
	buf := C.malloc(C.size_t(wrappedLen))
	if buf == nil {
		return nil, toError(C.CKR_HOST_MEMORY)
	}
	defer C.free(buf)
	wrappedKey = (*C.CK_BYTE)(buf)

	rv = C.WrapKeyAuthenticated(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
		aadPtr, C.CK_ULONG(len(aad)),
		&wrappedKey, &wrappedLen)
	if rv != C.CKR_OK {
		return nil, toError(rv)
	}
	return C.GoBytes(buf, C.int(wrappedLen)), nil
}

// UnwrapKeyAuthenticated unwraps a key with AEAD authentication (v3.2 §5.18.7).
// aad must match exactly what was supplied to WrapKeyAuthenticated.
// Official pkcs11f.h order: pTemplate before pAssociatedData.
func (c *Ctx) UnwrapKeyAuthenticated(sh SessionHandle, m []*Mechanism, unwrappingKey ObjectHandle, wrappedKey, aad []byte, attrs []*Attribute) (ObjectHandle, error) {
	mecharena, mech := cMechanism(m)
	defer mecharena.Free()
	attrarena, tmpl, tmplCount := cAttributeList(attrs)
	defer attrarena.Free()

	var aadPtr C.CK_BYTE_PTR
	if len(aad) > 0 {
		aadPtr = cMessage(aad)
	}

	var phKey C.CK_OBJECT_HANDLE
	rv := C.UnwrapKeyAuthenticated(c.ctx, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(unwrappingKey),
		cMessage(wrappedKey), C.CK_ULONG(len(wrappedKey)),
		tmpl, tmplCount,
		aadPtr, C.CK_ULONG(len(aad)),
		&phKey)
	return ObjectHandle(phKey), toError(rv)
}

// AsyncComplete retrieves the result of a completed async operation (v3.2 §5.21).
// functionName is the PKCS #11 function name that was called asynchronously,
// e.g. "C_Sign". Returns CKR_PENDING if the operation has not finished yet.
func (c *Ctx) AsyncComplete(sh SessionHandle, functionName string) ([]byte, error) {
	fname := C.CString(functionName)
	defer C.free(unsafe.Pointer(fname))

	var result C.CK_ASYNC_DATA
	rv := C.AsyncComplete(c.ctx, C.CK_SESSION_HANDLE(sh),
		(*C.CK_UTF8CHAR)(unsafe.Pointer(fname)), &result)
	if rv != C.CKR_OK {
		return nil, toError(rv)
	}
	if result.pValue != nil && result.ulValue > 0 {
		// C_AsyncComplete allocates pValue; copy into Go memory then free.
		defer C.free(unsafe.Pointer(result.pValue))
		return C.GoBytes(unsafe.Pointer(result.pValue), C.int(result.ulValue)), nil
	}
	return nil, nil
}

// AsyncGetID retrieves the persistent ID of an in-flight async operation
// (v3.2 §5.21). functionName is the PKCS #11 function name, e.g. "C_Sign".
func (c *Ctx) AsyncGetID(sh SessionHandle, functionName string) (uint, error) {
	fname := C.CString(functionName)
	defer C.free(unsafe.Pointer(fname))

	var id C.CK_ULONG
	rv := C.AsyncGetID(c.ctx, C.CK_SESSION_HANDLE(sh),
		(*C.CK_UTF8CHAR)(unsafe.Pointer(fname)), &id)
	if rv != C.CKR_OK {
		return 0, toError(rv)
	}
	return uint(id), nil
}

// AsyncJoin re-attaches a session to a persistent async operation (v3.2 §5.21).
// functionName and id identify the operation; pass nil for data if not needed.
func (c *Ctx) AsyncJoin(sh SessionHandle, functionName string, id uint, data []byte) error {
	fname := C.CString(functionName)
	defer C.free(unsafe.Pointer(fname))

	var dataPtr C.CK_BYTE_PTR
	if len(data) > 0 {
		dataPtr = cMessage(data)
	}
	rv := C.AsyncJoin(c.ctx, C.CK_SESSION_HANDLE(sh),
		(*C.CK_UTF8CHAR)(unsafe.Pointer(fname)),
		C.CK_ULONG(id), dataPtr, C.CK_ULONG(len(data)))
	return toError(rv)
}
