

Libp11 is a library to simplify using smart cards via PKCS#11
modules.  It was spun of the OpenSC project but can be used with any
pkcs#11 module.

This Go package is a wrapper for this library, in essence its a 
wrapper of a wrapper.

# Installation

To play with an HSM (Hardware security module) you can buy one, or
you can install softhsm.

Under Ubuntu:

sudo apt-get install softhsm libp11-2 libp11-dev
