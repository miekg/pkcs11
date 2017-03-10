// +build nopkcs11

// Copyright 2017 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pkcs11 is a wrapper around the PKCS#11 cryptographic library.
package pkcs11

import (
	"errors"
)

// Ctx contains the current pkcs11 context.
type Ctx struct {
}

// IsSupported returns true iff PKCS11 is supported (i.e. if built without the 'nopkcs11' tag)
func IsSupported() bool {
	return false
}

// New creates a new context and initializes the module/library for use.
func New(module string) *Ctx {
	if module == "" {
		return nil
	}
	return new(Ctx)
}

// Destroy unloads the module/library and frees any remaining memory.
func (c *Ctx) Destroy() {
	// noop
}

/* Initialize initializes the Cryptoki library. */
func (c *Ctx) Initialize() error {
	return buildError()
}

/* Finalize indicates that an application is done with the Cryptoki library. */
func (c *Ctx) Finalize() error {
	return buildError()
}

/* GetInfo returns general information about Cryptoki. */
func (c *Ctx) GetInfo() (Info, error) {
	return Info{}, buildError()
}

/* GetSlotList obtains a list of slots in the system. */
func (c *Ctx) GetSlotList(tokenPresent bool) ([]uint, error) {
	return nil, buildError()
}

/* GetSlotInfo obtains information about a particular slot in the system. */
func (c *Ctx) GetSlotInfo(slotID uint) (SlotInfo, error) {
	return SlotInfo{}, buildError()
}

// GetTokenInfo obtains information about a particular token
// in the system.
func (c *Ctx) GetTokenInfo(slotID uint) (TokenInfo, error) {
	return TokenInfo{}, buildError()
}

/* GetMechanismList obtains a list of mechanism types supported by a token. */
func (c *Ctx) GetMechanismList(slotID uint) ([]*Mechanism, error) {
	return nil, buildError()
}

// GetMechanismInfo obtains information about a particular
// mechanism possibly supported by a token.
func (c *Ctx) GetMechanismInfo(slotID uint, m []*Mechanism) (MechanismInfo, error) {
	return MechanismInfo{}, buildError()
}

// InitToken initializes a token. The label must be 32 characters
// long, it is blank padded if it is not. If it is longer it is capped
// to 32 characters.
func (c *Ctx) InitToken(slotID uint, pin string, label string) error {
	return buildError()
}

/* InitPIN initializes the normal user's PIN. */
func (c *Ctx) InitPIN(sh SessionHandle, pin string) error {
	return buildError()
}

/* SetPIN modifies the PIN of the user who is logged in. */
func (c *Ctx) SetPIN(sh SessionHandle, oldpin string, newpin string) error {
	return buildError()
}

/* OpenSession opens a session between an application and a token. */
func (c *Ctx) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	return 0, buildError()
}

/* CloseSession closes a session between an application and a token. */
func (c *Ctx) CloseSession(sh SessionHandle) error {
	return buildError()
}

/* CloseAllSessions closes all sessions with a token. */
func (c *Ctx) CloseAllSessions(slotID uint) error {
	return buildError()
}

/* GetSessionInfo obtains information about the session. */
func (c *Ctx) GetSessionInfo(sh SessionHandle) (SessionInfo, error) {
	return SessionInfo{}, buildError()
}

/* GetOperationState obtains the state of the cryptographic operation in a session. */
func (c *Ctx) GetOperationState(sh SessionHandle) ([]byte, error) {
	return nil, buildError()
}

/* SetOperationState restores the state of the cryptographic operation in a session. */
func (c *Ctx) SetOperationState(sh SessionHandle, state []byte, encryptKey, authKey ObjectHandle) error {
	return buildError()
}

/* Login logs a user into a token. */
func (c *Ctx) Login(sh SessionHandle, userType uint, pin string) error {
	return buildError()
}

/* Logout logs a user out from a token. */
func (c *Ctx) Logout(sh SessionHandle) error {
	return buildError()
}

/* CreateObject creates a new object. */
func (c *Ctx) CreateObject(sh SessionHandle, temp []*Attribute) (ObjectHandle, error) {
	return 0, buildError()
}

/* CopyObject copies an object, creating a new object for the copy. */
func (c *Ctx) CopyObject(sh SessionHandle, o ObjectHandle, temp []*Attribute) (ObjectHandle, error) {
	return 0, buildError()
}

/* DestroyObject destroys an object. */
func (c *Ctx) DestroyObject(sh SessionHandle, oh ObjectHandle) error {
	return buildError()
}

/* GetObjectSize gets the size of an object in bytes. */
func (c *Ctx) GetObjectSize(sh SessionHandle, oh ObjectHandle) (uint, error) {
	return 0, buildError()
}

/* GetAttributeValue obtains the value of one or more object attributes. */
func (c *Ctx) GetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) ([]*Attribute, error) {
	return nil, buildError()
}

/* SetAttributeValue modifies the value of one or more object attributes */
func (c *Ctx) SetAttributeValue(sh SessionHandle, o ObjectHandle, a []*Attribute) error {
	return buildError()
}

// FindObjectsInit initializes a search for token and session
// objects that match a template.
func (c *Ctx) FindObjectsInit(sh SessionHandle, temp []*Attribute) error {
	return buildError()
}

// FindObjects continues a search for token and session
// objects that match a template, obtaining additional object
// handles. The returned boolean indicates if the list would
// have been larger than max.
func (c *Ctx) FindObjects(sh SessionHandle, max int) ([]ObjectHandle, bool, error) {
	return nil, false, buildError()
}

/* FindObjectsFinal finishes a search for token and session objects. */
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	return buildError()
}

/* EncryptInit initializes an encryption operation. */
func (c *Ctx) EncryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	return buildError()
}

/* Encrypt encrypts single-part data. */
func (c *Ctx) Encrypt(sh SessionHandle, message []byte) ([]byte, error) {
	return nil, buildError()
}

/* EncryptUpdate continues a multiple-part encryption operation. */
func (c *Ctx) EncryptUpdate(sh SessionHandle, plain []byte) ([]byte, error) {
	return nil, buildError()
}

// EncryptFinal finishes a multiple-part encryption operation.
func (c *Ctx) EncryptFinal(sh SessionHandle) ([]byte, error) {
	return nil, buildError()
}

/* DecryptInit initializes a decryption operation. */
func (c *Ctx) DecryptInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	return buildError()
}

/* Decrypt decrypts encrypted data in a single part. */
func (c *Ctx) Decrypt(sh SessionHandle, cypher []byte) ([]byte, error) {
	return nil, buildError()
}

/* DecryptUpdate continues a multiple-part decryption operation. */
func (c *Ctx) DecryptUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return nil, buildError()
}

/* DecryptFinal finishes a multiple-part decryption operation. */
func (c *Ctx) DecryptFinal(sh SessionHandle) ([]byte, error) {
	return nil, buildError()
}

/* DigestInit initializes a message-digesting operation. */
func (c *Ctx) DigestInit(sh SessionHandle, m []*Mechanism) error {
	return buildError()
}

/* Digest digests message in a single part. */
func (c *Ctx) Digest(sh SessionHandle, message []byte) ([]byte, error) {
	return nil, buildError()
}

/* DigestUpdate continues a multiple-part message-digesting operation. */
func (c *Ctx) DigestUpdate(sh SessionHandle, message []byte) error {
	return buildError()
}

// DigestKey continues a multi-part message-digesting
// operation, by digesting the value of a secret key as part of
// the data already digested.
func (c *Ctx) DigestKey(sh SessionHandle, key ObjectHandle) error {
	return buildError()
}

/* DigestFinal finishes a multiple-part message-digesting operation. */
func (c *Ctx) DigestFinal(sh SessionHandle) ([]byte, error) {
	return nil, buildError()
}

// SignInit initializes a signature (private key encryption)
// operation, where the signature is (will be) an appendix to
// the data, and plaintext cannot be recovered from the
// signature.
func (c *Ctx) SignInit(sh SessionHandle, m []*Mechanism, o ObjectHandle) error {
	return buildError()
}

// Sign signs (encrypts with private key) data in a single part, where the signature
// is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
func (c *Ctx) Sign(sh SessionHandle, message []byte) ([]byte, error) {
	return nil, buildError()
}

// SignUpdate continues a multiple-part signature operation,
// where the signature is (will be) an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (c *Ctx) SignUpdate(sh SessionHandle, message []byte) error {
	return buildError()
}

/* SignFinal finishes a multiple-part signature operation returning the signature. */
func (c *Ctx) SignFinal(sh SessionHandle) ([]byte, error) {
	return nil, buildError()
}

// SignRecoverInit initializes a signature operation, where
// the data can be recovered from the signature.
func (c *Ctx) SignRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	return buildError()
}

// SignRecover signs data in a single operation, where the
// data can be recovered from the signature.
func (c *Ctx) SignRecover(sh SessionHandle, data []byte) ([]byte, error) {
	return nil, buildError()
}

// VerifyInit initializes a verification operation, where the
// signature is an appendix to the data, and plaintext cannot
// be recovered from the signature (e.g. DSA).
func (c *Ctx) VerifyInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	return buildError()
}

// Verify verifies a signature in a single-part operation,
// where the signature is an appendix to the data, and plaintext
// cannot be recovered from the signature.
func (c *Ctx) Verify(sh SessionHandle, data []byte, signature []byte) error {
	return buildError()
}

// VerifyUpdate continues a multiple-part verification
// operation, where the signature is an appendix to the data,
// and plaintext cannot be recovered from the signature.
func (c *Ctx) VerifyUpdate(sh SessionHandle, part []byte) error {
	return buildError()
}

// VerifyFinal finishes a multiple-part verification
// operation, checking the signature.
func (c *Ctx) VerifyFinal(sh SessionHandle, signature []byte) error {
	return buildError()
}

// VerifyRecoverInit initializes a signature verification
// operation, where the data is recovered from the signature.
func (c *Ctx) VerifyRecoverInit(sh SessionHandle, m []*Mechanism, key ObjectHandle) error {
	return buildError()
}

// VerifyRecover verifies a signature in a single-part
// operation, where the data is recovered from the signature.
func (c *Ctx) VerifyRecover(sh SessionHandle, signature []byte) ([]byte, error) {
	return nil, buildError()
}

// DigestEncryptUpdate continues a multiple-part digesting
// and encryption operation.
func (c *Ctx) DigestEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	return nil, buildError()
}

/* DecryptDigestUpdate continues a multiple-part decryption and digesting operation. */
func (c *Ctx) DecryptDigestUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return nil, buildError()
}

/* SignEncryptUpdate continues a multiple-part signing and encryption operation. */
func (c *Ctx) SignEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	return nil, buildError()
}

/* DecryptVerifyUpdate continues a multiple-part decryption and verify operation. */
func (c *Ctx) DecryptVerifyUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	return nil, buildError()
}

/* GenerateKey generates a secret key, creating a new key object. */
func (c *Ctx) GenerateKey(sh SessionHandle, m []*Mechanism, temp []*Attribute) (ObjectHandle, error) {
	return 0, buildError()
}

/* GenerateKeyPair generates a public-key/private-key pair creating new key objects. */
func (c *Ctx) GenerateKeyPair(sh SessionHandle, m []*Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	return 0, 0, buildError()
}

/* WrapKey wraps (i.e., encrypts) a key. */
func (c *Ctx) WrapKey(sh SessionHandle, m []*Mechanism, wrappingkey, key ObjectHandle) ([]byte, error) {
	return nil, buildError()
}

/* UnwrapKey unwraps (decrypts) a wrapped key, creating a new key object. */
func (c *Ctx) UnwrapKey(sh SessionHandle, m []*Mechanism, unwrappingkey ObjectHandle, wrappedkey []byte, a []*Attribute) (ObjectHandle, error) {
	return 0, buildError()
}

// DeriveKey derives a key from a base key, creating a new key object.
func (c *Ctx) DeriveKey(sh SessionHandle, m []*Mechanism, basekey ObjectHandle, a []*Attribute) (ObjectHandle, error) {
	return 0, buildError()
}

// SeedRandom mixes additional seed material into the token's
// random number generator.
func (c *Ctx) SeedRandom(sh SessionHandle, seed []byte) error {
	return buildError()
}

/* GenerateRandom generates random data. */
func (c *Ctx) GenerateRandom(sh SessionHandle, length int) ([]byte, error) {
	return nil, buildError()
}

// WaitForSlotEvent returns a channel which returns a slot event
// (token insertion, removal, etc.) when it occurs.
func (c *Ctx) WaitForSlotEvent(flags uint) chan SlotEvent {
	return nil
}

func buildError() error {
	return errors.New(BLD_ERR_MSG)
}
