// All names loose the CK_ prefix
// All names loose the hungarian notation
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

type Attribute struct {
	Type  C.CK_ATTRIBUTE_TYPE
	Value C.CK_VOID_PTR
	Len   C.CK_ULONG
}
