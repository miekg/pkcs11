package p11ez

import "github.com/miekg/pkcs11"

// Slot represents a slot that may hold a token.
type Slot struct {
	ctx *pkcs11.Ctx
	id  uint
}

// GetInfo returns information about the Slot.
func (s Slot) GetInfo() (pkcs11.SlotInfo, error) {
	return s.ctx.GetSlotInfo(s.id)
}

// GetTokenInfo returns information about the token in a Slot, if applicable.
func (s Slot) GetTokenInfo() (pkcs11.TokenInfo, error) {
	return s.ctx.GetTokenInfo(s.id)
}

// InitToken initializes a token with the given tokenLabel, setting an initial
// securityOfficerPIN.
func (s Slot) InitToken(securityOfficerPIN string, tokenLabel string) error {
	return s.ctx.InitToken(s.id, securityOfficerPIN, tokenLabel)
}

// ID returns the slot's ID.
func (s Slot) ID() uint {
	return s.id
}

// sessionType is a typed version of the session flags.
type sessionType uint

const (
	// ReadWrite is the flag to pass to OpenSession to get a read/write session.
	ReadWrite sessionType = pkcs11.CKF_RW_SESSION
	// ReadOnly is the flag to pass to OpenSession to get a read-only session.
	ReadOnly sessionType = 0
)

// OpenSession opens a session with the token in this slot, using the session
// type provided (ReadWrite or ReadOnly).
func (s Slot) OpenSession(sessType sessionType) (*Session, error) {
	// CKF_SERIAL_SESSION is always mandatory for legacy reasons, per PKCS#11.
	handle, err := s.ctx.OpenSession(s.id, uint(sessType)|pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, err
	}
	return &Session{
		ctx:    s.ctx,
		handle: handle,
	}, nil
}

// CloseAllSessions closes all sessions on this slot.
func (s Slot) CloseAllSessions() error {
	return s.ctx.CloseAllSessions(s.id)
}

// GetMechanismList returns a list of Mechanisms available on the token in this
// slot.
func (s Slot) GetMechanismList() ([]Mechanism, error) {
	list, err := s.ctx.GetMechanismList(s.id)
	if err != nil {
		return nil, err
	}
	result := make([]Mechanism, len(list))
	for i, mech := range list {
		result[i] = Mechanism{
			Mechanism: mech,
			slot:      s,
		}
	}
	return result, nil
}

// Mechanism represents a mechanism (for instance a cipher, signature algorithm,
// or hash function).
type Mechanism struct {
	*pkcs11.Mechanism
	slot Slot
}

// GetInfo returns information about this mechanism.
func (m *Mechanism) GetInfo() (pkcs11.MechanismInfo, error) {
	return m.slot.ctx.GetMechanismInfo(m.slot.id, []*pkcs11.Mechanism{m.Mechanism})
}
