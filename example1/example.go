package main

import (
	"fmt"
	"github.com/miekg/pkcs11"
)

func yesno(b bool) string {
	if b { return "yes" }
	return "no"
}

func main() {
	p := pkcs11.New("/usr/lib/libsofthsm.so")
	if p == nil {
		return
	}
	if e := p.C_Initialize(); e != nil {
		fmt.Printf("init error %s\n", e.Error())
		return
	}

	defer p.Destroy()
	defer p.C_Finalize()
	if info, err := p.C_GetInfo(); err == nil {
		fmt.Printf("%s\n", info.ManufacturerID)
	} else {
		fmt.Printf("error %s\n", err.Error())
	}
}
