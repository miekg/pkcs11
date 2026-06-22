# Architecture Diagrams

## Purpose
This file captures static architecture views that are directly supported by repository code.

## Evidence Base
- `pkcs11.go`
- `types.go`
- `params.go`
- `p11/module.go`
- `p11/session.go`
- `p11/object.go`
- `p11/slot.go`
- `README.md`
- `Makefile`

## Repository Architecture
Observed: the repository is split into a low-level PKCS#11 binding, a type/marshaling layer, a higher-level `p11` convenience package, generated/header inputs, and integration-oriented tests.

```mermaid
flowchart TD
    A[Go callers / tests] --> B[Root package pkcs11]
    A --> C[p11 convenience package]
    C --> B
    B --> D[types.go and params.go marshaling layer]
    B --> E[cgo C bridge in pkcs11.go]
    E --> F[PKCS#11 shared library]
    G[OASIS headers: pkcs11.h pkcs11f.h pkcs11t.h] --> B
    G --> H[zconst.go generation]
    I[Test harness: main_test.go pkcs11_test.go pkcs11_v32_test.go parallel_test.go] --> B
    I --> C
```

## Runtime Layer Architecture
Observed in `pkcs11.go`: `Ctx` wraps a native `struct ctx`; the native layer stores the module handle, the classic function table `sym`, and the optional v3.2 table `fl32`.

```mermaid
flowchart LR
    A[Application code] --> B[p11 facade optional]
    A --> C[pkcs11.Ctx methods]
    B --> C
    C --> D[Go-to-C marshaling]
    D --> E[Native struct ctx]
    E --> F[C_GetFunctionList -> sym]
    E --> G[C_GetInterface -> fl32 optional]
    F --> H[PKCS#11 v2.4-compatible calls]
    G --> I[PKCS#11 v3.2-only calls]
    H --> J[Vendor module]
    I --> J
```

## Ownership Boundaries
- The repository owns the Go wrapper, cgo bridge, type conversions, and helper abstractions.
- The repository does not own the internals of the loaded vendor PKCS#11 module.
- Generated/header assets are build inputs and API definitions, not separate runtime services.
