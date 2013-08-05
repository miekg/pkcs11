# PKCS#11

This is a Go implementation of the PKCS#11 API. It wraps the library closely, but uses Go idiom
were it makes sense.

It is *assumed*, that:

* Go's int size == PKCS11's CK_ULONG size
* CK_ULONG never overflows an Go int

# SoftHSM

* Make it use a custom configuration file

        export SOFTHSM_CONF=$PWD/softhsm.conf

* Then use `softhsm` to init it

    softhsm --init-token --slot 0 --label test




