package pkcs11

/*
#include <stdlib.h>
void* VoidPointer() {
	void *p = NULL;
	return p;
}


*/
import "C"

// Slot and token management
func GetSlotList(tokenPresent bool) []SlotID {
	slotlist := C.VoidPointer()
	return nil
}
