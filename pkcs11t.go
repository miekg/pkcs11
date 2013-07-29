package pkcs11

/*
#include "pkcs11.h"
*/
import "C"

type CK_ATTRIBUTE struct {
	typ C.CK_ATTRIBUTE_TYPE
//	pValue C.CK_VOID_PTR
	ulValueLen C.CK_ULONG
}
