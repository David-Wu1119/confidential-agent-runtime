export type SealedSecret = {
  version: "0.1";
  name: string;
  kdf: "scrypt";
  cipher: "aes-256-gcm";
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
  created_at: string;
};

export type RuntimePolicy = {
  version: "0.1";
  name: string;
  allow_env: string[];
  deny_env: string[];
  network: "inherit" | "deny_not_enforced";
  redact_stdout_patterns: string[];
};

export type RunEvidence = {
  version: "0.1";
  run_id: string;
  command: string[];
  policy_name: string;
  started_at: string;
  finished_at: string;
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  injected_secret_names: string[];
  allowed_env_names: string[];
  stdout_sha256: string;
  stderr_sha256: string;
};
