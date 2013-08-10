package main

import (
	"flag"
	"github.com/miekg/pkcs11"
	"log"
)

func main() {
	flag.Parse()
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
	e = p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	if e != nil {
		log.Fatalf("DigestInit: %s\n", e.Error())
	}

	// Sign something with priv
	data := []byte{1, 2, 3, 4}

	hash, err := p.Digest(session, data)
	if err != nil {
		log.Fatalf("sig: %s\n", err.Error())
	}
	log.Printf("%v\n", hash)
}
