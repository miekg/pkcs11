// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11

import (
	"bytes"
	"testing"
)

const notFound = 0xffffffff

// test whether mech is available; skip the test if it isn't
func needMech(t *testing.T, p *Ctx, sh SessionHandle, mech uint) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatal("GetSlotList:", err)
	}
	_, err = p.GetMechanismInfo(slots[0], []*Mechanism{NewMechanism(mech, nil)})
	if err == nil {
		return
	}
	e, ok := err.(Error)
	if !ok || e != CKR_MECHANISM_INVALID {
		t.Fatal("GetMechanismInfo:", err)
	}
	t.Skipf("skipping test; mech 0x%X not supported by softhsm", mech)
}

func findObject(t *testing.T, p *Ctx, sh SessionHandle, class uint, label string) ObjectHandle {
	template := []*Attribute{
		NewAttribute(CKA_CLASS, class),
		NewAttribute(CKA_LABEL, label),
	}
	if err := p.FindObjectsInit(sh, template); err != nil {
		t.Fatal("FindObjectsInit:", err)
	}
	obj, _, err := p.FindObjects(sh, 1)
	if err != nil {
		t.Fatal("FindObjects:", err)
	}
	if err := p.FindObjectsFinal(sh); err != nil {
		t.Fatal("FindObjectsFinal:", err)
	}
	if len(obj) > 0 {
		return obj[0]
	}
	return notFound
}

// generate a rsa key if it doesn't exist
func getRSA(t *testing.T, p *Ctx, sh SessionHandle) (pub, priv ObjectHandle) {
	pub = findObject(t, p, sh, CKO_PUBLIC_KEY, "paramstest")
	priv = findObject(t, p, sh, CKO_PUBLIC_KEY, "paramstest")
	if pub == notFound || priv == notFound {
		pub, priv = generateRSAKeyPair(t, p, sh, "paramstest", false)
	}
	return
}

func TestPSSParams(t *testing.T) {
	p := setenv(t)
	sh := getSession(p, t)
	defer finishSession(p, sh)
	needMech(t, p, sh, CKM_RSA_PKCS_PSS)
	pub, priv := getRSA(t, p, sh)

	sum := []byte("1234567890abcdef1234567890abcdef")
	params := NewPSSParams(CKM_SHA256, CKG_MGF1_SHA256, 32)
	mech := []*Mechanism{NewMechanism(CKM_RSA_PKCS_PSS, params)}
	if err := p.SignInit(sh, mech, priv); err != nil {
		t.Fatal("SignInit:", err)
	}
	sig, err := p.Sign(sh, sum)
	if err != nil {
		t.Fatal("Sign:", err)
	}
	if err := p.VerifyInit(sh, mech, pub); err != nil {
		t.Fatal("VerifyInit:")
	}
	if err := p.Verify(sh, sum, sig); err != nil {
		t.Fatal("Verify:")
	}
}

func TestOAEPParams(t *testing.T) {
	p := setenv(t)
	sh := getSession(p, t)
	defer finishSession(p, sh)
	needMech(t, p, sh, CKM_RSA_PKCS_OAEP)
	pub, priv := getRSA(t, p, sh)

	msg := []byte("1234567890abcdef1234567890abcdef")
	params := NewOAEPParams(CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nil)
	mech := []*Mechanism{NewMechanism(CKM_RSA_PKCS_OAEP, params)}
	if err := p.EncryptInit(sh, mech, pub); err != nil {
		t.Fatal("EncryptInit:", err)
	}
	ciphertext, err := p.Encrypt(sh, msg)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}
	if err := p.DecryptInit(sh, mech, priv); err != nil {
		t.Fatal("DecryptInit:")
	}
	msg2, err := p.Decrypt(sh, ciphertext)
	if err != nil {
		t.Fatal("Decrypt:")
	}
	if !bytes.Equal(msg, msg2) {
		t.Errorf("plaintext does not match: expected %x != actual %x", msg, msg2)
	}
}

func TestGCMParams(t *testing.T) {
	p := setenv(t)
	sh := getSession(p, t)
	defer finishSession(p, sh)
	needMech(t, p, sh, CKM_AES_GCM)

	key, err := p.GenerateKey(sh, []*Mechanism{NewMechanism(CKM_AES_KEY_GEN, nil)}, []*Attribute{
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_VALUE_LEN, 32),
	})
	if err != nil {
		t.Fatal("GenerateKey:", err)
	}

	iv := []byte("0123456789ab")
	msg := []byte("1234567890abcdef1234567890abcdef")
	params := NewGCMParams(iv, nil, 128)
	defer params.Free()
	if err := p.EncryptInit(sh, []*Mechanism{NewMechanism(CKM_AES_GCM, params)}, key); err != nil {
		t.Fatal("EncryptInit:", err)
	}
	ciphertext, err := p.Encrypt(sh, msg)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}
	iv = params.IV()
	params.Free()

	params = NewGCMParams(iv, nil, 128)
	defer params.Free()
	if err := p.DecryptInit(sh, []*Mechanism{NewMechanism(CKM_AES_GCM, params)}, key); err != nil {
		t.Fatal("DecryptInit:", err)
	}
	msg2, err := p.Decrypt(sh, ciphertext)
	if err != nil {
		t.Fatal("Decrypt:", err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Errorf("plaintext does not match: expected %x != actual %x", msg, msg2)
	}
	params.Free()
}
