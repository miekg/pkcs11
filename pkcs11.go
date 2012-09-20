package pkcs11

/*
#cgo LDFLAGS: -lltdl
// This is for Unix
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
#include <stdlib.h>
#include <ltdl.h>

struct ctx {
	lt_dlhandle handle;
	CK_FUNCTION_LIST_PTR_PTR funcs;
};

struct ctx * new(const char *module) {
	if (lt_dlinit() != 0) {
		return NULL;
	}
	struct ctx *c;
	c = calloc(1, sizeof(struct ctx));
	c->handle = lt_dlopen(module);
	if (c->handle == NULL) {
		return NULL;
	}
	c->funcs = lt_dlsym(c->handle, "C_GetFunctionList");
	if (c->funcs == NULL) {
		return NULL;
	}
	return c;
}

void destroy(struct ctx *c) {
	if (c->handle == NULL) {
		return;
	}
	if (lt_dlclose(c->handle) < 0) {
		return;
	}
	lt_dlexit();
	free(c);
}
*/
import "C"

import (
	"unsafe"
)

type Pkcs11 struct {
	ctx *C.struct_ctx
// moet ** zijn?	funcs C.CK_FUNCTION_LIST_PTR
	session C.CK_SESSION_HANDLE
}

// New returns a new instance of...
// It returns nil if the module can not be loaded.
func New(module string) *Pkcs11 {
	p := new(Pkcs11)
        mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	p.ctx = C.new(mod)
	// Call initialize
	return p
}

// Destroy unload the module and frees any remaining memory.
func (p *Pkcs11) Destroy() {
	if p == nil {
		return
	}
	C.destroy(p.ctx)
}
