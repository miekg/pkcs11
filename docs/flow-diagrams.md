# Flow Diagrams

## Purpose
This file captures decision-oriented and lifecycle-oriented flows derived from the codebase.

## Evidence Base
- `README.md`
- `types.go`
- `params.go`
- `main_test.go`
- `pkcs11_test.go`
- `pkcs11_v32_test.go`
- `parallel_test.go`

## Caller Operation Flow
Observed from `README.md` and `pkcs11_test.go`.

```mermaid
flowchart TD
    A[Start] --> B[Load module]
    B --> C[Initialize library]
    C --> D[Get token-present slots]
    D --> E[Open session]
    E --> F{Need private or secret key operation?}
    F -- Yes --> G[Login]
    F -- No --> H[Proceed without login]
    G --> I[Perform object or crypto operation]
    H --> I
    I --> J{More operations?}
    J -- Yes --> I
    J -- No --> K[Logout if logged in]
    K --> L[Close session]
    L --> M[Finalize and destroy]
```

## v3.2 Mechanism-Gated Test Flow
Observed from `pkcs11_v32_test.go`.

```mermaid
flowchart TD
    A[Start v3.2 test] --> B[Load module and open authenticated session]
    B --> C[Query supported mechanisms]
    C --> D{Required mechanism present?}
    D -- No --> E[Skip test]
    D -- Yes --> F[Run v3.2 or PQC operation]
    F --> G[Validate result]
    G --> H[Teardown session and context]
```

## Attribute and Parameter Marshaling Flow
Observed from `types.go` and `params.go`.

```mermaid
flowchart LR
    A[Go caller values] --> B[NewAttribute / NewMechanism / param constructors]
    B --> C[Build native structs and temporary arena]
    C --> D[Invoke pkcs11.Ctx method]
    D --> E[PKCS#11 call through cgo]
    E --> F[Return status handles or bytes]
    F --> G[Convert C data back to Go values]
    G --> H[Free temporary native allocations]
```

## Parallel Signing Resource Flow
Observed from `parallel_test.go`.

```mermaid
flowchart TD
    A[Initialize shared context] --> B[Create many signers]
    B --> C[Each signer opens its own session]
    C --> D[Store signers in cache]
    D --> E[Goroutine requests signer]
    E --> F{Signer available?}
    F -- No --> G[Wait on condition variable]
    F -- Yes --> H[Use signer for SignInit + Sign]
    G --> F
    H --> I[Return signer to cache]
    I --> J[More sign requests or close sessions]
```
