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
#include <ltdl.h>
#include "pkcs11.h"

void* VoidPointer(CK_ULONG size) {
	void *p = NULL;
	p = calloc(1, sizeof(CK_ULONG) * size);
	return p;
}

CK_ULONG Index(CK_ULONG* array, CK_ULONG i) {
	return array[i];
}

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

CK_RV Initialize(struct ctx* c, CK_VOID_PTR pInitArgs) {
	return c->sym->C_Initialize(pInitArgs);
}

*/
import "C"

import "unsafe"

// Ctx contains the current pkcs11 context.
type Ctx struct {
	ctx *C.struct_ctx
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

func (c *Ctx) Initialize() {
	pInitArgs := &C.CK_C_INITIALIZE_ARGS{nil, nil, nil, nil, C.CKF_OS_LOCKING_OK, nil}
	C.Initialize(c.ctx, C.CK_VOID_PTR(pInitArgs))
}

func (c *Ctx) GetSlotList(tokenPresent bool) []SlotID {

}
