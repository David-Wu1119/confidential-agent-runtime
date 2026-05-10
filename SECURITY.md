# Security

Confidential Agent Runtime v0.1 is a local prototype.

## Protected In v0.1

- Secrets can be sealed with AES-256-GCM using a passphrase.
- Commands run with an explicit environment allowlist.
- Denied environment names block matching sealed secret injection.
- Injected secret values are redacted from captured stdout/stderr before evidence hashing.
- Run evidence stores hashes and metadata instead of raw secrets.

## Not Protected In v0.1

- Hardware-backed trusted execution.
- OS-level sandboxing.
- Network egress blocking.
- Protection from a malicious child process that can exfiltrate secrets by design.
- Side-channel resistance.

Use this as a local reference prototype, not as a production confidential-computing boundary.
