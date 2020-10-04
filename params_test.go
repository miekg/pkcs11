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

// derveECBKey derives DES3_ECB
func deriveECBKey(p *Ctx, session SessionHandle, bdk ObjectHandle, ksn []byte) ObjectHandle {
	template := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKK_DES2),
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_EXTRACTABLE, true),
	}
	params := NewKeyDerivationStringData(ksn)
	mech := []*Mechanism{NewMechanism(CKM_DES3_ECB_ENCRYPT_DATA, params)}
	sessionKey, err := p.DeriveKey(session, mech, bdk, template)

	if err != nil {
		panic(err)
	}

	return sessionKey
}

// derveKey derives DES3_CBC
func deriveKey(p *Ctx, session SessionHandle, bdk ObjectHandle, ksn []byte) ObjectHandle {
	template := []*Attribute{
		NewAttribute(CKA_KEY_TYPE, CKK_DES2),
		NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
		NewAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_SENSITIVE, false),
		NewAttribute(CKA_EXTRACTABLE, true),
	}
	params := NewDesCBCEncryptDataParams([]byte{0, 0, 0, 0, 0, 0, 0, 0}, ksn)
	mech := []*Mechanism{NewMechanism(CKM_DES3_CBC_ENCRYPT_DATA, params)}
	sessionKey, err := p.DeriveKey(session, mech, bdk, template)

	if err != nil {
		panic(err)
	}

	return sessionKey
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

func TestDesCBCEncryptDataParams(t *testing.T) {
	p := setenv(t)
	sh := getSession(p, t)
	defer finishSession(p, sh)
	needMech(t, p, sh, CKM_DES3_CBC_ENCRYPT_DATA)

	key, err := p.GenerateKey(sh, []*Mechanism{NewMechanism(CKM_DES2_KEY_GEN, nil)}, []*Attribute{
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DERIVE, true),
	})
	if err != nil {
		t.Fatal("GenerateKey:", err)
	}

	ksn := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32}

	dKey := deriveKey(p, sh, key, ksn)
	encryptMech := []*Mechanism{NewMechanism(CKM_DES3_ECB, nil)}
	if err := p.EncryptInit(sh, encryptMech, dKey); err != nil {
		t.Fatal("EncryptInit:", err)
	}
	cipherText, err := p.Encrypt(sh, data)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}

	err = p.DecryptInit(sh, encryptMech, dKey)
	if err != nil {
		t.Fatalf("Could not initiate Decrypt operation: %v", err)
	}
	decryptedText, err := p.Decrypt(sh, cipherText)
	if err != nil {
		t.Fatalf("Could not perform decryption: %v", err)
	}
	if len(decryptedText) != len(data) {
		t.Logf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
		t.Fatalf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
	}
	if string(decryptedText) != string(data) {
		t.Fatalf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
	}

}

func TestKeyDerivationStringData(t *testing.T) {
	p := setenv(t)
	sh := getSession(p, t)
	defer finishSession(p, sh)
	needMech(t, p, sh, CKM_DES3_ECB_ENCRYPT_DATA)

	key, err := p.GenerateKey(sh, []*Mechanism{NewMechanism(CKM_DES2_KEY_GEN, nil)}, []*Attribute{
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DERIVE, true),
	})
	if err != nil {
		t.Fatal("GenerateKey:", err)
	}

	ksn := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32}

	dKey := deriveECBKey(p, sh, key, ksn)
	encryptMech := []*Mechanism{NewMechanism(CKM_DES3_ECB, nil)}
	if err := p.EncryptInit(sh, encryptMech, dKey); err != nil {
		t.Fatal("EncryptInit:", err)
	}
	cipherText, err := p.Encrypt(sh, data)
	if err != nil {
		t.Fatal("Encrypt:", err)
	}

	err = p.DecryptInit(sh, encryptMech, dKey)
	if err != nil {
		t.Fatalf("Could not initiate Decrypt operation: %v", err)
	}
	decryptedText, err := p.Decrypt(sh, cipherText)
	if err != nil {
		t.Fatalf("Could not perform decryption: %v", err)
	}
	if len(decryptedText) != len(data) {
		t.Logf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
		t.Fatalf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
	}
	if string(decryptedText) != string(data) {
		t.Fatalf("decrypted string %v, original data string %v does not match", string(decryptedText), string(data))
	}
}
