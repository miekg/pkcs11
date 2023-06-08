package p11

import "github.com/lcmmhcc/pkcs11"

// SecretKey is an Object representing a secret (symmetric) key. Since any object can be cast to a
// SecretKey, it is the user's responsibility to ensure that the object is
// actually a secret key. For instance, if you use a FindObjects template that
// includes CKA_CLASS: CKO_SECRET_KEY, you can be confident the resulting object
// is a secret key.
type SecretKey Object

// Encrypt encrypts a plaintext with a given mechanism.
func (secret SecretKey) Encrypt(mechanism pkcs11.Mechanism, plaintext []byte) ([]byte, error) {
	s := secret.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.EncryptInit(s.handle, []*pkcs11.Mechanism{&mechanism}, secret.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Encrypt(s.handle, plaintext)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Decrypt decrypts the input with a given mechanism.
func (secret SecretKey) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := secret.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.DecryptInit(s.handle, []*pkcs11.Mechanism{&mechanism}, secret.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Decrypt(s.handle, ciphertext)
	if err != nil {
		return nil, err
	}
	return out, nil
}
