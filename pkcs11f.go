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
void* VoidPointer(CK_ULONG size) {
	void *p = NULL;
	p = calloc(1, sizeof(CK_ULONG) * size);
	return p;
}

CK_ULONG Index(CK_ULONG* array, CK_ULONG i) {
	return array[i];
}

*/
import "C"

func (c *Ctx) Initialize() {
	Args := &C.CK_C_INITIALIZE_ARGS{nil, nil, nil, nil, C.CKF_OS_LOCKING_OK, nil}
	c.ctx.sym[C_Initialize](&Args)
}

// Slot and token management
func (c *Ctx) GetSlotList(tokenPresent bool) []SlotID {
	pcount := C.CK_ULONG(1)
	

	return nil
}
