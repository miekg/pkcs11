package main

import (
	"github.com/miekg/pkcs11"
)

func main() {
	p := pkcs11.New("/usr/lib/libsofthsm.so")
	if p == nil {
		return
	}
	defer p.Destroy()
	slots, _ := p.Slots()
	for _, s := range slots {
		println(s.Description)
		if s.Token != nil {
			println(s.Token.Manufacturer)
		}
	}
}
