# Apple-based NIOSSH migration

- Switched to TopScrech/swift-nio-ssh main, based directly on Apple's implementation with native RSA support
- Updated Swift Crypto to 5.x
- Retained OpenSSH RSA key parsing through `Insecure.RSA.PrivateKey(sshRsa:)`, now backed by Swift Crypto
- Replaced `NIOSSHPrivateKey(custom:)` with `NIOSSHPrivateKey(rsaKey:)`
- Defaulted RSA user authentication to SHA-512; exposed `signatureAlgorithm:` for SHA-256 or legacy SHA-1
- Retained AES128-CTR with SHA-256, SHA-512 and SHA-1 MAC variants through Apple's transport protection API
- Replaced fork-specific username access with per-connection authentication state
- Removed custom Diffie-Hellman group14 implementations and the `keyExchangeAlgorithms` / `publicKeyAlgorihtms` registration properties; key exchange now uses Apple's supported ECDH algorithms

RSA keys must be at least 2048 bits, matching the native implementation's import policy
Servers requiring only the removed finite-field DH exchanges remain unsupported
