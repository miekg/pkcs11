// Copyright 2026 Miek Gieben and the Golang pkcs11 Contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX-License-Identifier: BSD-3-Clause

package p11

import "github.com/miekg/pkcs11"

// PublicKey is an Object representing a public key. Since any object can be cast to a
// PublicKey, it is the user's responsibility to ensure that the object is
// actually a public key. For instance, if you use a FindObjects template that
// includes CKA_CLASS: CKO_PUBLIC_KEY, you can be confident the resulting object
// is a public key.
// For ML-KEM, public key is the encapsulation key.
type PublicKey Object

// PrivateKey is an Object representing a private key. Since any object can be cast to a
// PrivateKey, it is the user's responsibility to ensure that the object is
// actually a private key.
// For ML-KEM, private key is the decapsulation key.
type PrivateKey Object

// KEMKeyPair holds the two objects produced by ML-KEM key generation:
//   - encapsulation key is public
//   - decapsulation key is private
type KEMKeyPair struct {
	EncapsPubKey  PublicKey
	DecapsPrivKey PrivateKey
}

// Decrypt decrypts the input with a given mechanism.
func (privK PrivateKey) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := privK.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.DecryptInit(s.handle, []*pkcs11.Mechanism{&mechanism}, privK.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Sign signs the input with a given mechanism.
func (privK PrivateKey) Sign(mechanism pkcs11.Mechanism, message []byte) ([]byte, error) {
	s := privK.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.SignInit(s.handle, []*pkcs11.Mechanism{&mechanism}, privK.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Sign(s.handle, message)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (privK PrivateKey) deriveInner(mechanism pkcs11.Mechanism, attributes []*pkcs11.Attribute) (*Object, error) {
	s := privK.session
	s.Lock()
	defer s.Unlock()
	objectHandle, err := s.ctx.DeriveKey(s.handle, []*pkcs11.Mechanism{&mechanism}, privK.objectHandle, attributes)
	if err != nil {
		return nil, err
	}

	obj := Object{
		session:      s,
		objectHandle: objectHandle,
	}
	return &obj, nil
}

// Derive derives a shared secret with a given mechanism.
func (privK PrivateKey) Derive(mechanism pkcs11.Mechanism, attributes []*pkcs11.Attribute) ([]byte, error) {
	sharedObj, err := privK.deriveInner(mechanism, attributes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := sharedObj.Value()
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// Verify verifies a signature over a message with a given mechanism.
func (pubK PublicKey) Verify(mechanism pkcs11.Mechanism, message, signature []byte) error {
	s := pubK.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.VerifyInit(s.handle, []*pkcs11.Mechanism{&mechanism}, pubK.objectHandle)
	if err != nil {
		return err
	}
	err = s.ctx.Verify(s.handle, message, signature)
	if err != nil {
		return err
	}
	return nil
}

// Encrypt encrypts a plaintext with a given mechanism.
func (pubK PublicKey) Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	s := pubK.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.EncryptInit(s.handle, []*pkcs11.Mechanism{&mechanism}, pubK.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Encapsulate performs ML-KEM key encapsulation (PKCS #11 v3.2 §5.18.8).
//
// The token generates a random shared secret, encrypts it under the public key,
// and returns:
//   - ciphertext: the KEM ciphertext to be sent to the recipient.
//   - sharedSecret: a handle to the derived shared-secret key object on the token,
//     whose type and attributes are controlled by derivedKeyTemplate.
//
// Example derivedKeyTemplate for a 32-byte AES-256 shared secret:
//
//	[]*pkcs11.Attribute{
//	    pkcs11.NewAttribute(pkcs11.CKA_CLASS,     pkcs11.CKO_SECRET_KEY),
//	    pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE,  pkcs11.CKK_AES),
//	    pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
//	    pkcs11.NewAttribute(pkcs11.CKA_TOKEN,     false),
//	}
func (pubK PublicKey) Encapsulate(mechanism pkcs11.Mechanism, derivedKeyTemplate []*pkcs11.Attribute) (ciphertext []byte, sharedSecret SecretKey, err error) {
	s := pubK.session
	s.Lock()
	defer s.Unlock()
	ct, handle, err := s.ctx.EncapsulateKey(s.handle,
		[]*pkcs11.Mechanism{&mechanism},
		pubK.objectHandle,
		derivedKeyTemplate)
	if err != nil {
		return nil, SecretKey{}, err
	}
	return ct, SecretKey(Object{session: s, objectHandle: handle}), nil
}

// Decapsulate performs ML-KEM key decapsulation (PKCS #11 v3.2 §5.18.9).
//
// The token uses the private key to recover the shared secret from ciphertext
// and returns a handle to the derived shared-secret key object on the token.
// derivedKeyTemplate controls the type and attributes of that object; it should
// match what was passed to Encapsulate on the sender side.
func (privK PrivateKey) Decapsulate(mechanism pkcs11.Mechanism, ciphertext []byte, derivedKeyTemplate []*pkcs11.Attribute) (SecretKey, error) {
	s := privK.session
	s.Lock()
	defer s.Unlock()
	handle, err := s.ctx.DecapsulateKey(s.handle,
		[]*pkcs11.Mechanism{&mechanism},
		privK.objectHandle,
		derivedKeyTemplate,
		ciphertext)
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey(Object{session: s, objectHandle: handle}), nil
}

// VerifyStateless verifies a signature using the PKCS #11 v3.2 stateless API
// (§5.15): the signature is bound at init time rather than at the final step,
// which allows the token to stream the message without buffering it.
//
// Use this instead of Verify when the token requires the v3.2 flow, for
// example with ML-DSA keys on a v3.2-capable token.
func (pubK PublicKey) VerifyStateless(mechanism pkcs11.Mechanism, message, signature []byte) error {
	s := pubK.session
	s.Lock()
	defer s.Unlock()
	if err := s.ctx.VerifySignatureInit(s.handle,
		[]*pkcs11.Mechanism{&mechanism},
		pubK.objectHandle,
		signature); err != nil {
		return err
	}
	return s.ctx.VerifySignature(s.handle, message)
}
