# PKCS#11

This is a Go implementation of the PKCS#11 API. It wraps the library closely. 

# SoftHSM

* Make it use a custom configuration file

        export SOFTHSM_CONF=$PWD/softhsm.conf

* Then use `softhsm` to init it

    softhsm --init-token --slot 0 --label test




