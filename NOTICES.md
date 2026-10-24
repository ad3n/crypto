# Third-Party Notices

This project uses the following third-party Go modules.

| Package | License | License URL |
|---------|---------|-------------|
| `github.com/eclipse-keypont/pkcs11-go` | MIT | [Link](https://github.com/eclipse-keypont/pkcs11-go/blob/v1.2.0-rc4/LICENSE) |

## Vendored source (in-tree)

The following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.

| Path | Origin | License | License file |
|------|--------|---------|--------------|
| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |

## Local dependency patches

The checkout vendors dependencies listed in `vendor/modules.txt`, including their license files. `pkcs11-go v1.2.0-rc4` has two local changes, recorded in `patches/pkcs11-go-rc4.patch`:

- On macOS, secret erasure uses the existing volatile-write fallback because the Apple SDK does not provide `explicit_bzero`.
- CK_ULONG encoding uses native-endian Go writes with one owned allocation, preserving the binding's overflow rejection.

Rebuild vendor sources with `go mod vendor`, then apply `git apply patches/pkcs11-go-rc4.patch`. The patch is required for this macOS checkout. Go consumers do not inherit a dependency's vendor directory; downstream module-mode users need a binding release/fork containing these fixes. This local merge does not publish such a release.
