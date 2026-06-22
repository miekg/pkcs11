# Component Diagrams

## Purpose
This file captures component and type-relationship views for the root package and `p11` package.

## Evidence Base
- `pkcs11.go`
- `types.go`
- `params.go`
- `p11/module.go`
- `p11/slot.go`
- `p11/session.go`
- `p11/object.go`
- `p11/crypto.go`
- `p11/secret_key.go`

## Root Package Components
Observed: the root package centers on `Ctx`, which coordinates lifecycle, slot/session operations, object operations, crypto operations, and v3.2 extensions.

```mermaid
flowchart TD
    Ctx[Ctx in pkcs11.go]
    Types[Info SlotInfo TokenInfo SessionInfo]
    Attrs[Attribute Mechanism]
    Params[GCMParams OAEPParams ECDH1DeriveParams]
    Errors[Error and strerror mapping]
    V32[v3.2 methods: EncapsulateKey DecapsulateKey VerifySignature* WrapKeyAuthenticated Async*]

    Ctx --> Types
    Ctx --> Attrs
    Ctx --> Params
    Ctx --> Errors
    Ctx --> V32
    Attrs --> Params
```

## `p11` Object Model
Observed from `p11/module.go`, `p11/slot.go`, `p11/session.go`, `p11/object.go`, `p11/crypto.go`, and `p11/secret_key.go`.

```mermaid
classDiagram
    class Module {
      -ctx *pkcs11.Ctx
      +Info()
      +Slots()
      +Destroy()
    }

    class Slot {
      -ctx *pkcs11.Ctx
      -id uint
      +Info()
      +TokenInfo()
      +OpenSession()
      +OpenWriteSession()
      +Mechanisms()
      +InitToken()
    }

    class Session {
      <<interface>>
      +Login()
      +Logout()
      +Close()
      +FindObject()
      +FindObjects()
      +CreateObject()
      +GenerateKeyPair()
      +GenerateRandom()
      +InitPIN()
      +SetPIN()
    }

    class sessionImpl {
      -ctx *pkcs11.Ctx
      -handle pkcs11.SessionHandle
      -Mutex
    }

    class Object {
      -session *sessionImpl
      -objectHandle pkcs11.ObjectHandle
      +Label()
      +Value()
      +Attribute()
      +Set()
      +Copy()
      +Destroy()
    }

    class PublicKey
    class PrivateKey
    class SecretKey
    class KeyPair {
      +Public PublicKey
      +Private PrivateKey
    }

    Module --> Slot
    Slot --> Session
    Session <|.. sessionImpl
    sessionImpl --> Object
    Object <|-- PublicKey
    Object <|-- PrivateKey
    Object <|-- SecretKey
    KeyPair --> PublicKey
    KeyPair --> PrivateKey
```

## Session Concurrency Component View
Observed: `sessionImpl` serializes per-session operations with a mutex, while `parallel_test.go` demonstrates multi-session concurrency via a signer pool.

```mermaid
flowchart LR
    A[Goroutines] --> B[Signer cache / pool]
    B --> C[signer 1 -> session 1]
    B --> D[signer 2 -> session 2]
    B --> E[signer N -> session N]
    C --> F[shared pkcs11.Ctx]
    D --> F
    E --> F
    F --> G[PKCS#11 module with OS locking]
```
