package pkcs11

// These t depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"fmt"
	"os"
	"testing"
)

func setenv() *Ctx {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
	p := New("/usr/lib/softhsm/libsofthsm.so")
	return p
}

func getSession(p *Ctx, t *testing.T) SessionHandle {
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e.Error())
	}
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e.Error())
	}
	session, e := p.OpenSession(slots[0], CKF_SERIAL_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e.Error())
	}
	return session
}

func TestGetAttributeValue(t *testing.T) {
	p := setenv()
	session := getSession(p, t)
	defer p.Destroy()
	defer p.CloseSession(session)
	defer p.Finalize()
	// There are at least two RSA keys in the hsm.db, objecthandle 1 and 2.
	template := []*Attribute{
		NewAttribute(CKA_PUBLIC_EXPONENT, nil),
		NewAttribute(CKA_MODULUS_BITS, 1024),
		NewAttribute(CKA_LABEL, "MyFirstKey"),
	}
	attr, err := p.GetAttributeValue(session, ObjectHandle(1), template)
	if err != nil {
		t.Fatalf("err %s\n", err.Error())
	}
	for i, a := range attr {
		t.Logf("Attr %d, type %d, value %s", i, a.Type, string(a.Value))
	}
}

func TestDigest(t *testing.T) {
	p := setenv()
	session := getSession(p, t)
	defer p.Destroy()
	defer p.CloseSession(session)
	defer p.Finalize()
	e := p.DigestInit(session, []*Mechanism{NewMechanism(CKM_SHA_1, nil)})
	if e != nil {
		t.Fatalf("DigestInit: %s\n", e.Error())
	}

	hash, e := p.Digest(session, []byte("this is a string"))
	if e != nil {
		t.Fatalf("sig: %s\n", e.Error())
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
