# Threat Model

v0.1 assumes:

- The local machine and parent Node.js process are trusted.
- The passphrase is provided out-of-band through an environment variable.
- The child command may be buggy or overly verbose.

v0.1 protects against:

- Accidental secret storage in plaintext files.
- Ambient environment leakage from the parent shell.
- Accidental evidence files containing injected secret values.

v0.1 does not protect against:

- Malware on the host.
- A malicious command intentionally sending secrets over the network.
- Kernel, shell, or debugger-level observation.
- Cloud TEE compromise or misconfiguration because no TEE exists yet.
