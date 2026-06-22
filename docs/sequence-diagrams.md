# Sequence Diagrams

## Purpose
This file captures operational sequences that are exercised by code and tests.

## Evidence Base
- `pkcs11.go`
- `p11/module.go`
- `main_test.go`
- `pkcs11_test.go`
- `pkcs11_v32_test.go`
- `parallel_test.go`

## Module Load and Initialization
Observed from `pkcs11.go` and `p11/module.go`.

```mermaid
sequenceDiagram
    participant Caller
    participant P11 as p11.OpenModule / pkcs11.New
    participant Loader as cgo loader
    participant Module as PKCS#11 Module

    Caller->>P11: OpenModule(path) or New(path)
    P11->>Loader: LoadLibrary / dlopen
    Loader->>Module: open shared library
    P11->>Module: resolve C_GetFunctionList
    P11->>Module: resolve C_GetInterface optional
    Caller->>P11: Initialize()
    P11->>Module: C_Initialize(CKF_OS_LOCKING_OK)
```

## Standard Session Lifecycle
Observed from `README.md`, `pkcs11_test.go`, and `pkcs11_v32_test.go`.

```mermaid
sequenceDiagram
    participant App
    participant Ctx as pkcs11.Ctx
    participant Mod as PKCS#11 Module

    App->>Ctx: Initialize()
    Ctx->>Mod: C_Initialize
    App->>Ctx: GetSlotList(true)
    Ctx->>Mod: C_GetSlotList
    App->>Ctx: OpenSession(slot, flags)
    Ctx->>Mod: C_OpenSession
    App->>Ctx: Login(sh, CKU_USER, pin)
    Ctx->>Mod: C_Login
    App->>Ctx: SignInit / DigestInit / FindObjectsInit / ...
    Ctx->>Mod: C_* operation
    Mod-->>Ctx: result bytes / handles / status
    App->>Ctx: Logout(sh)
    App->>Ctx: CloseSession(sh)
    App->>Ctx: Finalize()
```

## Token Bootstrap Sequence
Observed from `main_test.go`.

```mermaid
sequenceDiagram
    participant TestMain
    participant Ctx as pkcs11.Ctx
    participant Mod as PKCS#11 Module

    TestMain->>Ctx: New(modulePath)
    TestMain->>Ctx: Initialize()
    Ctx->>Mod: C_Initialize
    TestMain->>Ctx: GetSlotList(false)
    Ctx->>Mod: C_GetSlotList(tokenPresent=false)
    TestMain->>Ctx: InitToken(slot, soPin, label)
    Ctx->>Mod: C_InitToken
    TestMain->>Ctx: GetSlotList(true)
    TestMain->>Ctx: OpenSession(slot, serial|rw)
    TestMain->>Ctx: Login(sh, CKU_SO, soPin)
    Ctx->>Mod: C_Login
    TestMain->>Ctx: InitPIN(sh, userPin)
    Ctx->>Mod: C_InitPIN
    TestMain->>Ctx: Logout(sh)
    TestMain->>Ctx: CloseSession(sh)
    TestMain->>Ctx: Finalize()
    TestMain->>Ctx: Destroy()
```

## ML-KEM Round-Trip Sequence
Observed from `pkcs11_v32_test.go`.

```mermaid
sequenceDiagram
    participant Test
    participant Ctx as pkcs11.Ctx
    participant Mod as PKCS#11 Module

    Test->>Ctx: GenerateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN, pubTmpl, prvTmpl)
    Ctx->>Mod: C_GenerateKeyPair
    Test->>Ctx: EncapsulateKey(CKM_ML_KEM, pub, ssTmpl)
    Ctx->>Mod: C_EncapsulateKey
    Mod-->>Ctx: ciphertext, shared secret handle
    Test->>Ctx: DecapsulateKey(CKM_ML_KEM, prv, ssTmpl, ciphertext)
    Ctx->>Mod: C_DecapsulateKey
    Mod-->>Ctx: shared secret handle
    Test->>Ctx: GetAttributeValue(CKA_VALUE) on both secret handles
    Test->>Test: compare shared-secret bytes
```

## Parallel Signing Sequence
Observed from `parallel_test.go`.

```mermaid
sequenceDiagram
    participant Goroutine
    participant Cache as signer cache
    participant Signer as signer/session
    participant Ctx as pkcs11.Ctx
    participant Mod as PKCS#11 Module

    Goroutine->>Cache: get signer
    Cache-->>Goroutine: available signer
    Goroutine->>Signer: sign(input)
    Signer->>Ctx: SignInit(session, CKM_RSA_PKCS, privateKey)
    Ctx->>Mod: C_SignInit
    Signer->>Ctx: Sign(session, input)
    Ctx->>Mod: C_Sign
    Mod-->>Ctx: signature bytes
    Signer-->>Goroutine: signature
    Goroutine->>Cache: return signer
```
