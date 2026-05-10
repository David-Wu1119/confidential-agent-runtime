# Confidential Agent Runtime

Confidential Agent Runtime is a local prototype for private agent execution.

It supports:

- sealing local secrets with AES-256-GCM
- running commands with an allowlisted environment
- injecting sealed secrets only when explicitly requested
- redacting injected secret values from captured output
- writing run evidence with command metadata and output hashes

## Install

```bash
corepack pnpm install
corepack pnpm build
node dist/cli.js --help
```

## CLI

```bash
node dist/cli.js init
CONFAGENT_PASSPHRASE='use-a-long-passphrase' node dist/cli.js seal --name DEMO_TOKEN --value secret --out demo.sealed.json
CONFAGENT_PASSPHRASE='use-a-long-passphrase' node dist/cli.js run --policy .confagent/policy.json --secret DEMO_TOKEN=demo.sealed.json --passphrase-env CONFAGENT_PASSPHRASE -- node -e "console.log(process.env.DEMO_TOKEN)"
```

## Claim Boundary

This v0.1 release is not a trusted execution environment, not a sandbox, and not remote attestation. It is a local control-plane prototype for sealed secrets, environment minimization, and run evidence.

## Verification

```bash
corepack pnpm install
corepack pnpm format:check
corepack pnpm check
npm pack --dry-run
```
