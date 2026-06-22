# PKCS#11

This is a Go implementation of the PKCS#11 API. It wraps the library closely, but uses Go idiom where
it makes sense. It has been tested with [SoftHSMv3 by PQCToday](https://github.com/pqctoday/pqctoday-hsm).

The specification followed is [PKCS #11 Cryptographic Token Interface Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).
The C headers are fetched from the [OASIS pkcs11 repository](https://github.com/oasis-tcs/pkcs11/tree/pkcs11-3.20/published/3-02)
at tag `pkcs11-3.20` (commit [`858bfc8b93ded02a40886e2321240b5978e1aa42`](https://github.com/oasis-tcs/pkcs11/tree/858bfc8b93ded02a40886e2321240b5978e1aa42/published/3-02)) via `make headers`.

## Overview & Architecture

The folowing diagrams help understand the architecture of this library.

* [architecture diagrams](./docs/architecture-diagrams.md)
* [component diagrams](./docs/component-diagrams.md)
* [flow diagrams](./docs/flow-diagrams.md)
* [sequence diagrams](./docs/sequence-diagrams.md)

## PKCS#11 v3.2 support

Project `miekg/pkcs11` supports [PKCS#11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html), including:

- `C_EncapsulateKey` / `C_DecapsulateKey` — KEM operations (§5.18.8 & §5.18.9)
- ML-KEM key generation, encapsulation and decapsulation (`CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`)
- New constants: `CKK_ML_KEM`, `CKP_ML_KEM_512/768/1024`, `CKA_ENCAPSULATE`, `CKA_DECAPSULATE`, `CKA_PARAMETER_SET`, `CKF_ENCAPSULATE`, `CKF_DECAPSULATE`

## SoftHSMv3 - A Software HSM that implements PKCS#11 v3.2

Integration tests require HSM compliant with PKCS#11 v3.2.
[SoftHSMv3 by PQCToday](https://github.com/pqctoday/pqctoday-hsm) is a software
HSM compliant with PKCS#11 v3.2.

> Note: As of april 2026, https://github.com/softhsm/SoftHSMv2 is not compatible with PKCS#11 v3.2.

No manual token setup is needed — `TestMain` creates an ephemeral token via the PKCS#11 API
(`C_InitToken` / `C_InitPIN`) in a temporary directory and cleans it up after the run.

Pass the path to the SoftHSMv3 shared library via `PKCS11_MODULE`:

~~~ bash
make integration PKCS11_MODULE=/path/to/libsofthsm3.so
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
please see [github.com/ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11).
