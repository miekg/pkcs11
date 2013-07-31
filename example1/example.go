package main

import (
	"fmt"
	"github.com/miekg/pkcs11"
)

func main() {
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm.so")
	if p == nil {
		fmt.Printf("new error\n")
		return
	}
	if e := p.Initialize(); e != nil {
		fmt.Printf("init error %s\n", e.Error())
		return
	}

	defer p.Destroy()
	defer p.Finalize()
	slots, e := p.GetSlotList(true)
	fmt.Printf("slots %v\n", slots)
	if e != nil {
		fmt.Printf("slots %s\n", e.Error())
		return
	}
	// Only works on initialized tokens

	session, e := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if e != nil {
		fmt.Printf("session %s\n", e.Error())
		return
	}
	fmt.Printf("%v %v\n", slots, session)

	publicKeyTemplate := []pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(1024)),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
	}
	privateKeyTemplate := []pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}
	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
	pub, priv, e := p.GenerateKeyPair(session, mech, publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		fmt.Printf("%s\n", e.Error())
	}
	println(pub)
	println(priv)

	/*
		e = p.C_SignInit(session, &pkcs11.CKM_RSA_PKCS{} , priv)
		if e != nil {
			fmt.Printf("signinit: %s\n", e.Error())
		}

		// Sign something with priv
		data := []byte{1, 2, 3, 4}

		sig, err := p.C_Sign(session, data)
		if err != nil {
			fmt.Printf("sig: %s\n", err.Error())
		}
		fmt.Printf("%v\n", sig)
	*/
}
