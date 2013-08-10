# PKCS#11

This is a Go implementation of the PKCS#11 API. It wraps the library closely, but uses Go idiom
were it makes sense.

It is *assumed*, that:

* Go's uint size == PKCS11's CK_ULONG size
* CK_ULONG never overflows an Go uint

## SoftHSM

* Make it use a custom configuration file

        export SOFTHSM_CONF=$PWD/softhsm.conf

* Then use `softhsm` to init it

        softhsm --init-token --slot 0 --label test --pin 1234

## Examples

The following examples are available:

* sign/ directory contains a program, that generates a keypair and then signs
    some data;
* hash/ directory contains a program that hashes a string with SHA1.
