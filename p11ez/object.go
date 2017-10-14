package p11ez

import (
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// Object represents a PKCS#11 object. It is attached to a given session. Once
// that session is closed, operations on the Object will fail. Operations may
// also depend on the logged-in state of the session.
type Object struct {
	session      *Session
	objectHandle pkcs11.ObjectHandle
}

// GetID gets the internal identifier of an object, as a hex string. If the
// object has no identifier, returns the empty string.
func (o Object) GetID() (string, error) {
	idBytes, err := o.GetAttributeValue(pkcs11.CKA_ID)
	if err != nil {
		// Some objects don't have ID; that's fine, just return the empty string.
		if err, ok := err.(pkcs11.Error); ok && err == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID {
			return "", nil
		}
		return "", err
	}
	return fmt.Sprintf("%x", idBytes), nil
}

// GetLabel returns the label of an object.
func (o Object) GetLabel() (string, error) {
	labelBytes, err := o.GetAttributeValue(pkcs11.CKA_LABEL)
	if err != nil {
		// Some objects don't have a label; that's fine, just return the empty string.
		if err, ok := err.(pkcs11.Error); ok && err == pkcs11.CKR_ATTRIBUTE_TYPE_INVALID {
			return "", nil
		}
		return "", err
	}
	return string(labelBytes), nil
}

// GetValue returns an object's CKA_VALUE attribute, as bytes.
func (o Object) GetValue() ([]byte, error) {
	return o.GetAttributeValue(pkcs11.CKA_VALUE)
}

// GetAttributeValue gets exactly one attribute from a PKCS#11 object, returning
// an error if the attribute is not found, or if multiple attributes are
// returned. On success, it will return the value of that attribute as a slice
// of bytes.
func (o Object) GetAttributeValue(attributeType uint) ([]byte, error) {
	o.session.Lock()
	defer o.session.Unlock()

	attrs, err := o.session.ctx.GetAttributeValue(o.session.handle, o.objectHandle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, nil)})
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 {
		return nil, errors.New("attribute not found")
	}
	if len(attrs) > 1 {
		return nil, errors.New("too many attributes found")
	}
	return attrs[0].Value, nil
}

// SetAttributeValue sets exactly one attribute on a PKCS#11 object.
func (o Object) SetAttributeValue(attributeType uint, value []byte) error {
	o.session.Lock()
	defer o.session.Unlock()

	err := o.session.ctx.SetAttributeValue(o.session.handle, o.objectHandle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, value)})
	if err != nil {
		return err
	}
	return nil
}

// Copy makes a copy of this object, with the attributes in template applied on
// top of it, if possible.
func (o Object) Copy(template []*pkcs11.Attribute) (Object, error) {
	s := o.session
	s.Lock()
	defer s.Unlock()
	newHandle, err := s.ctx.CopyObject(s.handle, o.objectHandle, template)
	if err != nil {
		return Object{}, err
	}
	return Object{
		session:      s,
		objectHandle: newHandle,
	}, nil
}

// Destroy destroys this object.
func (o Object) Destroy() error {
	s := o.session
	s.Lock()
	defer s.Unlock()
	return s.ctx.DestroyObject(s.handle, o.objectHandle)
}
