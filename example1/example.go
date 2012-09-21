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
	defer p.Destroy()
	slots, _ := p.Slots()
	for i, s := range slots {
		fmt.Printf("Slot %d\n", i)
		if s.Token == nil {
			fmt.Printf("\tToken present: no")
			continue
		}
		fmt.Printf("\tToken present: yes\n")
		fmt.Printf("\tToken initialized: %s\n", yesno(s.Token.Initialized))
		fmt.Printf("\tUser PIN initialized: %s\n", yesno(s.Token.UserPinSet))
		// Initializing
		s.Token.Init("1234", "miekstuff")
		fmt.Printf("Token label: %s\n", s.Token.Label)
	}
}
