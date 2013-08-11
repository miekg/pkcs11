package main

import (
	"flag"
	"github.com/miekg/pkcs11"
	"log"
)

func main() {
	flag.Parse()
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")
	p := pkcs11.New("/usr/lib/softhsm/libsofthsm.so")
	if len(flag.Args()) > 0 {
		p = pkcs11.New(flag.Arg(0))
	}
	if p == nil {
		log.Fatalf("new error\n")
	}
	if e := p.Initialize(); e != nil {
		log.Fatalf("init error %s\n", e.Error())
	}

	defer p.Destroy()
	defer p.Finalize()
	slots, e := p.GetSlotList(true)
	log.Printf("slots %v\n", slots)
	if e != nil {
		log.Fatalf("slots %s\n", e.Error())
		return
	}
	session, e := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if e != nil {
		log.Fatalf("session %s\n", e.Error())
	}
	defer p.CloseSession(session)
	log.Printf("%v %v\n", slots, session)

	if e := p.Login(session, pkcs11.CKU_USER, "1234"); e != nil {
		log.Fatal("user pin %s\n", e.Error())
	}
	defer p.Logout(session)
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 1024),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyFirstKey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyFirstKey"),
	}
	pub, priv, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		log.Fatalf("%s\n", e.Error())
	}
	log.Printf("pub id %d, priv id %d", pub, priv)
	e = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA1_RSA_PKCS, nil)}, priv)
	if e != nil {
		log.Fatalf("SignInit: %s\n", e.Error())
	}

	// Sign something with priv
	data := []byte{1, 2, 3, 4}

	sig, err := p.Sign(session, data)
	if err != nil {
		log.Fatalf("sig: %s\n", err.Error())
	}
	log.Printf("%v\n", sig)
}
