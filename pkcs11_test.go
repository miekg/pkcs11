package pkcs11

// These t depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"fmt"
	"os"
	"testing"
)

func setenv() {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
}

func TestDigest(t *testing.T) {
	setenv()
	p := New("/usr/lib/softhsm/libsofthsm.so")
	if p == nil {
		t.Fatalf("new error\n")
	}
	defer p.Destroy()
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e.Error())
	}
	defer p.Finalize()
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e.Error())
	}
	session, e := p.OpenSession(slots[0], CKF_SERIAL_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e.Error())
	}
	defer p.CloseSession(session)
	e = p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)})
	if e != nil {
		t.Fatalf("DigestInit: %s\n", e.Error())
	}

	hash, err := p.Digest(session, []byte("this is a string"))
	if err != nil {
		t.Fatalf("sig: %s\n", err.Error())
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%x", d)
	}
	// Teststring create with: echo -n "this is a string" | sha1sum
	if hex != "517592df8fec3ad146a79a9af153db2a4d784ec5" {
		t.Fatalf("wrong digest: %s", hex)
	}
}
