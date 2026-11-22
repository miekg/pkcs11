package pkcs11

import (
	"testing"
	"unsafe"
)

func TestSecretWipe(t *testing.T) {
	const pin = "1234-secret"
	s := newSecret(pin)
	defer s.free()

	b := unsafe.Slice((*byte)(unsafe.Pointer(s.p)), int(s.n))
	if string(b[:len(pin)]) != pin || b[len(pin)] != 0 {
		t.Fatalf("copy is %q, want %q and a NUL", b, pin)
	}
	s.wipe()
	for i, c := range b {
		if c != 0 {
			t.Fatalf("byte %d is %#x after wipe, want 0", i, c)
		}
	}
}
