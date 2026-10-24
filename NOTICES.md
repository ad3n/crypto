# Third-Party Notices

This project uses the following third-party Go modules.

| Package | License | License URL |
|---------|---------|-------------|
| `github.com/ad3n/pkcs11-go` | MIT | [Link](https://github.com/ad3n/pkcs11-go/blob/v1.2.0-rc4.ad3n.1/LICENSE) |

## Vendored source (in-tree)

The following code is copied directly into this repository and is not a Go module dependency, so it is not covered by the table above.

| Path | Origin | License | License file |
|------|--------|---------|--------------|
| `internal/pool` | `github.com/thales-e-security/pool` (extracted from `vitess.io/vitess`) | Apache-2.0 | [internal/pool/LICENSE](internal/pool/LICENSE) |

## Patched binding dependency

The module directly requires `github.com/ad3n/pkcs11-go v1.2.0-rc4.ad3n.1`, forked from upstream rc4. It preserves one-allocation ULONG encoding and uses the volatile zeroization fallback on macOS. Attribution remains in the fork's LICENSE and NOTICE.md. No vendor directory or replace directive is required. See the fork's [patch report](https://github.com/ad3n/pkcs11-go/blob/v1.2.0-rc4.ad3n.1/FORK_PATCHES.md).
