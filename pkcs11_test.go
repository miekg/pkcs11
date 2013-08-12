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
	// Debug lib
	// p := New("/home/miek/libsofthsm.so")
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
	if e := p.Login(session, CKU_USER, "1234"); e != nil {
		t.Fatal("user pin %s\n", e.Error())
	}
	return session
}

func TestObjectFinding(t *testing.T) {
	p := setenv()
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
	// There are 2 keys in the db with this tag
	template := []*Attribute{NewAttribute(CKA_LABEL, "MyFirstKey")}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("Failed to init: %s\n", e.Error())
	}
	obj, b, e := p.FindObjects(session, 2)
	if e != nil {
		t.Fatalf("Failed to find: %s %v\n", e.Error(), b)
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("Failed to finalize: %s\n", e.Error())
	}
	if len(obj) != 2 {
		t.Fatal("should have found two objects")
	}
}

func TestGetAttributeValue(t *testing.T) {
	p := setenv()
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.Destroy()
	defer p.Finalize()
	defer p.CloseSession(session)
	// There are at least two RSA keys in the hsm.db, objecthandle 1 and 2.
	template := []*Attribute{
		NewAttribute(CKA_PUBLIC_EXPONENT, nil),
		NewAttribute(CKA_MODULUS_BITS, nil),
		NewAttribute(CKA_LABEL, nil),
	}
	// ObjectHandle two is the public key
	attr, err := p.GetAttributeValue(session, ObjectHandle(2), template)
	if err != nil {
		t.Fatalf("err %s\n", err.Error())
	}
	for i, a := range attr {
		t.Logf("Attr %d, type %d, valuelen %d", i, a.Type, len(a.Value))
	}
}

func TestDigest(t *testing.T) {
	p := setenv()
	session := getSession(p, t)
	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()
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
