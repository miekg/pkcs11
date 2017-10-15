// Package p11 wraps `miekg/pkcs11` to make it easier to use and more idiomatic
// to Go, as compared with the more straightforward C wrapper that
// `miekg/pkcs11` presents. All types are safe to use concurrently.
//
// To use, first you open a module (a dynamically loaded library) by providing
// its path on your filesystem. This module is typically provided by
// the maker of your HSM, smartcard, or other cryptographic hardware, or
// sometimes by your operating system. Common module filenames are
// opensc-pkcs11.so, libykcs11.so, and libsofthsm2.so (you'll have to find the
// exact location).
//
// Once you've opened a Module, you can list the slots available with that
// module. Each slot may or may not contain a token. For instance, if you have a
// smartcard reader, that's a slot; if there's a smartcard in it, that's the
// token. Using this package, you can iterate through slots and check their
// information, and the information about tokens in them.
//
// Once you've found the slot with the token you want to use, you can open a
// Session with that token using OpenSession. Almost all operations require
// a session. Sessions use a sync.Mutex to ensure only one operation is active on
// them at a given time, as required by PKCS#11. If you want to get full
// performance out of your multi-core HSM, you will need to create multiple
// sessions.
//
// Once you've got a session, you can login to it. This is not necessary if you
// only want to access non-sensitive data, like certificates and public keys.
// However, to use any secret keys on a token, you'll need to login.
//
// Many operations, like FindObjects, return Objects. These represent pieces of
// data that exist on the token, referring to them by a numeric handle. With
// objects representing private keys, you can perform operations like signing
// and decrypting; with public keys and certificates you can extract their
// values.
//
// To summarize, a typical workflow (omitting error handling) might look like:
//
//   module, _ := p11.OpenModule("/path/to/module.so")
//   slots, _ := module.Slots()
//   session, _ := slots[0].OpenSession()
//   pk, _ := session.FindObject(...)
//   privateKey := p11.PrivateKey(pk)
//   signature, _ := privateKey.Sign(..., []byte{"hello"})
package p11

import "github.com/miekg/pkcs11"

// OpenModule loads a PKCS#11 module (a .so file or dynamically loaded library),
// and returns a Module.
func OpenModule(path string) (Module, error) {
	m := pkcs11.New(path)
	err := m.Initialize()
	if err != nil {
		return Module{}, err
	}
	return Module{m}, nil
}

// Module represents a PKCS#11 module, and can be used to create Sessions.
type Module struct {
	ctx *pkcs11.Ctx
}

// Info returns general information about the module.
func (m Module) Info() (pkcs11.Info, error) {
	return m.ctx.GetInfo()
}

// Slots returns all available Slots with a token present.
func (m Module) Slots() ([]Slot, error) {
	ids, err := m.ctx.GetSlotList(true)
	if err != nil {
		return nil, err
	}
	result := make([]Slot, len(ids))
	for i, id := range ids {
		result[i] = Slot{
			ctx: m.ctx,
			id:  id,
		}
	}
	return result, nil
}
