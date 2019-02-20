package p11

import "github.com/miekg/pkcs11"

// PrivateKey is an Object representing a private key. Since any object can be cast to a
// PrivateKey, it is the user's responsibility to ensure that the object is
// actually a private key.
// For instance, if you use a FindObjects template that
// includes CKA_CLASS: CKO_PRIVATE_KEY, you can be confident the resulting object
// is a public key.
type PrivateKey Object

// Decrypt decrypts the input with a given mechanism.
func (priv PrivateKey) Decrypt(mechanism pkcs11.Mechanism, ciphertext []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.DecryptInit(s.handle, []*pkcs11.Mechanism{&mechanism}, priv.objectHandle)
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
func (priv PrivateKey) Sign(mechanism pkcs11.Mechanism, message []byte) ([]byte, error) {
	s := priv.session
	s.Lock()
	defer s.Unlock()
	err := s.ctx.SignInit(s.handle, []*pkcs11.Mechanism{&mechanism}, priv.objectHandle)
	if err != nil {
		return nil, err
	}
	out, err := s.ctx.Sign(s.handle, message)
	if err != nil {
		return nil, err
	}
	return out, nil
}
