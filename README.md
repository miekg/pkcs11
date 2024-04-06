# PKCS#11

This is a Go implementation of the PKCS#11 API. It wraps the library closely, but uses Go idioms where
they make sense. It has been tested with SoftHSM.

The version used is "PKCS #11 Cryptographic Token Interface Base Specification Version 3.0", see
<http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html>. Note that the header
files listed there are *broken*, the fixed ones live in a [github repo](https://github.com/oasis-tcs/pkcs11/tree/pkcs11-3.00/published/3-00).
From that repo commit d8d3a0b7c47d7cc129063004f1fce6553bc70839 was pulled into this repository.

## SoftHSM

 *  Make it use a custom configuration file `export SOFTHSM_CONF=$PWD/softhsm.conf`

 *  Then use `softhsm` to init it

    ~~~
    softhsm2-util --init-token --slot 0 --label test --pin 1234
    ~~~

 *  Then use `libsofthsm2.so` as the pkcs11 module:

    ~~~ go
    p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
    ~~~

### Mac OS X

 *  If installing `softhsm` via `homebrew`, set the environment variable
    `SOFTHSM_LIB` to the location of the homebrew installation:

  ~~~
  export SOFTHSM_LIB=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
  ~~~


## Examples

A skeleton program would look somewhat like this (yes, pkcs#11 is verbose):

~~~ go
p := pkcs11.New("/usr/lib/softhsm/libsofthsm2.so")
err := p.Initialize()
if err != nil {
    panic(err)
}

defer p.Destroy()
defer p.Finalize()

slots, err := p.GetSlotList(true)
if err != nil {
    panic(err)
}

session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
if err != nil {
    panic(err)
}
defer p.CloseSession(session)

err = p.Login(session, pkcs11.CKU_USER, "1234")
if err != nil {
    panic(err)
}
defer p.Logout(session)

p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
hash, err := p.Digest(session, []byte("this is a string"))
if err != nil {
    panic(err)
}

for _, d := range hash {
        fmt.Printf("%x", d)
}
fmt.Println()
~~~

Further examples are included in the tests.

To expose PKCS#11 keys using the [crypto.Signer interface](https://golang.org/pkg/crypto/#Signer),
please see [github.com/thalesignite/crypto11](https://github.com/thalesignite/crypto11).
