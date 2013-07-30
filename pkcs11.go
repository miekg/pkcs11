package pkcs11

// Assumption uint is 32 bits on 32 bits platforms and 64 bits on 64 bit platforms

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
#include "pkcs11.h"

struct ctx {
        lt_dlhandle handle;
        CK_FUNCTION_LIST_PTR sym;
};

// New initializes a ctx and fills the symbol table.
struct ctx * New(const char *module) {
        if (lt_dlinit() != 0) {
                return NULL;
        }
        CK_C_GetFunctionList list;
        struct ctx *c=  calloc(1, sizeof(struct ctx));
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
void Destroy(struct ctx *c) {
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

CK_RV Initialize(struct ctx* c, CK_VOID_PTR initArgs) {
	return c->sym->C_Initialize(initArgs);
}

CK_RV Finalize(struct ctx* c) {
	return c->sym->C_Finalize(NULL_PTR);
}

CK_RV GetSlotList(struct ctx* c, CK_BBOOL tokenPresent, CK_ULONG_PTR *slotList, CK_ULONG_PTR ulCount) {
	CK_RV e = c->sym->C_GetSlotList(tokenPresent, NULL_PTR, ulCount);
	if (e != CKR_OK) {
		return e;
	}
	*slotList = calloc(1, sizeof(CK_SLOT_ID) * *ulCount);
	e = c->sym->C_GetSlotList(tokenPresent, *slotList, ulCount);
	return e;
}

CK_RV OpenSession(struct ctx* c, CK_ULONG slotID, CK_ULONG flags, 

*/
import "C"

import "unsafe"

// Ctx contains the current pkcs11 context.
type Ctx struct {
	ctx         *C.struct_ctx
	initialized bool
	// mutex?
}

// New creates a new context.
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

// Destroy unload the module and frees any remaining memory.
func (c *Ctx) Destroy() {
	if c == nil {
		return
	}
	C.Destroy(c.ctx)
}

func (c *Ctx) Initialize() error {
	args := &C.CK_C_INITIALIZE_ARGS{nil, nil, nil, nil, C.CKF_OS_LOCKING_OK, nil}
	e := C.Initialize(c.ctx, C.CK_VOID_PTR(args))
	if e == C.CKR_OK {
		c.initialized = true // TODO(miek): keep?
	}
	return toError(e)
}

func (c *Ctx) Finalize() error {
	e := C.Finalize(c.ctx)
	return toError(e)
}

func (c *Ctx) GetSlotList(tokenPresent bool) (List, error) {
	var (
		slotList C.CK_ULONG_PTR
		ulCount  C.CK_ULONG
	)
	e := C.GetSlotList(c.ctx, cBBool(tokenPresent), &slotList, &ulCount)
	if toError(e) == nil {
		l := toList(slotList, ulCount)
		return l, nil
	}
	return nil, toError(e)
}

func (c *Ctx) OpenSession

func (c *Ctx) GenerateKeyPair(sh SessionHandle, m Mechanism, public, private []Attribute) (ObjectHandle, ObjectHandle, error) {
	return 0, 0, nil
}
